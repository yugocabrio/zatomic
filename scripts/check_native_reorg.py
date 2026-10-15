#!/usr/bin/env python3
"""Temporarily invalidate only this fixture's native funding/confirmation blocks.

Uses the owned isolated Zebra, with a durable restoration marker before each
mutation. It restores the exact original chain before further settlement. No
public node, no simulation of native transaction validation, no branch deletion.
"""
import argparse
import contextlib
import json
import os
from pathlib import Path
import time
import owner_swap as flow
import prefunding_swap
from check_evm_reorg import digest
from evm_journal import checkpoint
from peer_workspace import sync
from regtest_node import status, rpc, GENESIS, BRANCH
from regtest_wallet import save
from run_client_swap import client


def wait(predicate):
    deadline=time.monotonic()+30
    while not predicate():
        if time.monotonic()>deadline:raise RuntimeError('native reorg observation timed out; inspect restoration marker')
        time.sleep(.1)


def restore(directory):
    marker=directory/'native-reorg-inflight.json'
    if not marker.exists():return
    value=flow.read(marker)
    if value['genesis']!=GENESIS or value['branch']!=BRANCH:
        raise RuntimeError('native restoration marker domain mismatch')
    status()  # Reject another chain before any reconsideration.
    rpc('reconsiderblock',[value['invalidated_block']],timeout=60)
    wait(lambda:status()['tip']==value['original_tip'])
    marker.unlink();sync(directory)


@contextlib.contextmanager
def invalidated(directory,block):
    before=status()
    save(directory/'native-reorg-inflight.json',{'genesis':GENESIS,'branch':BRANCH,
        'invalidated_block':block,'original_tip':before['tip'],'original_height':before['blocks']})
    try:
        rpc('invalidateblock',[block],timeout=60)
        wait(lambda:status()['tip']!=before['tip'])
        yield
    finally:
        restore(directory)


def funding_confirmations(txid):
    try:value=rpc('getrawtransaction',[txid,1])
    except RuntimeError:return 0
    return value.get('confirmations',0) if value.get('in_active_chain') else 0


def check(directory):
    with flow.chain_lock():
        restore(directory)
        if (directory/'08-complete.json').exists():raise RuntimeError('requires a fixture paused at eth-locked')
        with flow.node(directory,restore=True):
            agreement=flow.validate_recovery(directory)
            order=flow.read(directory/'04-eth-locked.json')['order']
            funding=rpc('getrawtransaction',[agreement['native']['funding_txid'],1])
            before=status()
            if funding['confirmations']!=2:
                raise RuntimeError('run immediately after this fixture funding reaches two confirmations')
            alice,bob=directory/'owners/alice',directory/'owners/bob'
            if (alice/'eth-intent-claim.json').exists():raise RuntimeError('requires no prior secret exposure')
            bob_intent=digest(bob/'eth-intent-lock.json')
            cases=[]
            for name,block,expected in [('one_confirmation',before['tip'],1),
                    ('funding_orphaned',funding['blockhash'],0)]:
                with invalidated(directory,block):
                    wait(lambda:funding_confirmations(funding['txid'])==expected)
                    client('claim',alice,{'order':order},reject=True)
                    client('lock',bob,flow.read(directory/'owner-lock-request.json'),reject=True)
                    if (alice/'eth-intent-claim.json').exists() or digest(bob/'eth-intent-lock.json')!=bob_intent:
                        raise RuntimeError('native confirmation loss created or changed an owner intent')
                    cases.append({'case':name,'native_confirmations':expected,
                        'new_reveal_rejected':True,'lock_reconciliation_rejected':True,
                        'owner_intents_unchanged':True})
                if funding_confirmations(funding['txid'])!=2 or status()['tip']!=before['tip']:
                    raise RuntimeError('original native chain was not restored')
            claim=flow.owner_call(directory,'claim','alice',{'order':order})
            checkpoint(directory)
            completed=flow.finish(directory,agreement,order,recovered=True)
    repeated=prefunding_swap.recover(directory)
    if repeated['new_native_transactions']!=0 or repeated['new_evm_transactions']!=0:
        raise RuntimeError('native restoration recovery duplicated payment')
    result={'scope':'actual isolated Zebra invalidate/reconsider; original branch restored',
        'funding_txid':funding['txid'],'checks':cases,'restoration_marker_cleared':True,
        'original_branch_restored_before_reveal':True,'claim_after_restoration':claim['txid'],
        'completed':completed,'repeat':repeated,'public_reorg_policy':False}
    save(directory/'native-reorg-checks.json',result)
    return result


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('directory',type=Path)
    p.add_argument('--restore-only',action='store_true')
    a=p.parse_args();os.umask(0o077);directory=a.directory.resolve()
    if a.restore_only:
        with flow.chain_lock():restore(directory)
        print(json.dumps({'restoration_marker_cleared':not (directory/'native-reorg-inflight.json').exists()}))
    else:print(json.dumps(check(directory),indent=2))
