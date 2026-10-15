#!/usr/bin/env python3
"""Actual controlled forks after relayed settlement and owner withdrawal.

Requires a current success/refund fixture paused at eth-locked. The original
claim/refund intent is retained across all forks. Only the harness uses Anvil snapshot/revert; the
owner client never restores a chain. Native funding is not rolled back.
"""
import argparse
import json
import os
from pathlib import Path
import owner_swap as flow
import prefunding_swap
import run_native_evm_gate as evm
from evm_wallet import rlp, keccak
from check_evm_reorg import digest, revert
from evm_journal import checkpoint
from regtest_node import status
from regtest_wallet import save
from run_client_swap import client


def check(directory, expect_collision=False):
    if (directory/'08-complete.json').exists():
        raise RuntimeError('requires a fixture paused before settlement')
    initial_checkpoint = digest(directory/'evm-checkpoint.json')
    with flow.chain_lock(), flow.node(directory,restore=True):
        agreement=flow.validate_recovery(directory)
        order=flow.read(directory/'04-eth-locked.json')['order']
        mode=flow.read(directory/'setup.json')['mode']
        action,role=('claim','alice') if mode=='success' else ('refund','bob')
        owner=directory/'owners'/role
        address=agreement['recipient' if role=='alice' else 'maker']
        if mode=='refund':
            now=int(evm.rpc('eth_getBlockByNumber',['latest',False])['timestamp'],16)
            if now<agreement['eth_expiry']:
                evm.rpc('evm_setNextBlockTimestamp',[agreement['eth_expiry']])
                evm.rpc('evm_mine')
        state=lambda:flow.order_state(agreement,agreement['native'],order)
        if state()!=1:raise RuntimeError('requires a locked unclaimed checkpoint')
        tip=status()['tip']
        snapshot=evm.rpc('evm_snapshot')
        claim=client(action,owner,{'order':order})
        tx=evm.rpc('eth_getTransactionByHash',[claim['txid']])
        public_data=tx['input']
        # Reconstruct only already-public signed calldata from the mined RPC
        # transaction; never read a private owner intent for the pending test.
        public_raw=rlp([int(tx[k],16) for k in ('nonce','gasPrice','gas')]+
            [bytes.fromhex(tx['to'][2:]),int(tx['value'],16),bytes.fromhex(tx['input'][2:])]+
            [int(tx[k],16) for k in ('v','r','s')])
        if '0x'+keccak(public_raw).hex()!=claim['txid']:
            raise RuntimeError('public raw transaction reconstruction changed hash')
        claim_hash=digest(owner/f'eth-intent-{action}.json')
        revert(snapshot)
        before_relay=evm.rpc('evm_snapshot')
        relayer=evm.rpc('eth_accounts')[0]
        relay=lambda:evm.send({'from':relayer,'to':agreement['contract'],
            'data':public_data,'gas':hex(1_000_000)})
        relay()
        pending_snapshot=evm.rpc('evm_snapshot')
        evm.rpc('evm_setAutomine',[False])
        if evm.rpc('eth_sendRawTransaction',['0x'+public_raw.hex()])!=claim['txid']:
            raise RuntimeError('public settlement transaction not accepted into pending pool')
        before_files={str(p.relative_to(owner)):digest(p) for p in owner.glob('eth-*withdraw*.json')}
        before_files.update({str(p.relative_to(owner)):digest(p) for p in (owner/'eth-withdraw-attempts').glob('*.json')})
        client('withdraw',owner,{'order':order},reject=True)
        after_files={str(p.relative_to(owner)):digest(p) for p in owner.glob('eth-*withdraw*.json')}
        after_files.update({str(p.relative_to(owner)):digest(p) for p in (owner/'eth-withdraw-attempts').glob('*.json')})
        if before_files!=after_files:raise RuntimeError('unrelated pending nonce caused a withdrawal signature')
        # Anvil snapshot/revert does not clear a live mempool. Remove only the
        # exact public test transaction we injected before restoring this fork.
        if evm.rpc('anvil_dropTransaction',[claim['txid']]) != claim['txid']:
            raise RuntimeError('owned injected pending transaction was not removed')
        revert(pending_snapshot);evm.rpc('evm_setAutomine',[True])
        first=client('withdraw',owner,{'order':order})
        first_tx=evm.rpc('eth_getTransactionByHash',[first['txid']])
        first_receipt=evm.rpc('eth_getTransactionReceipt',[first['txid']])
        first_time=int(evm.rpc('eth_getBlockByNumber',[first_receipt['blockNumber'],False])['timestamp'],16)
        original_withdraw=digest(owner/'eth-intent-withdraw.json')
        if first_tx['nonce']!=tx['nonce']:
            raise RuntimeError('settlement/withdraw nonce collision was not constructed')
        revert(before_relay)
        if state()!=1 or evm.rpc('eth_getTransactionReceipt',[first['txid']]) is not None:
            raise RuntimeError('withdrawal was not orphaned by rollback')
        before_owner_claim=evm.rpc('evm_snapshot')
        replay=client(action,owner,{'order':order})
        if replay['txid']!=claim['txid'] or not replay['new_transaction']:
            raise RuntimeError('original settlement did not consume the old withdrawal nonce')
        if expect_collision:
            client('withdraw',owner,{'order':order},reject=True)
            if digest(directory/'evm-checkpoint.json')!=initial_checkpoint:
                raise RuntimeError('diagnostic changed recovery checkpoint')
            result={'scope':'actual owned fork after withdrawal, expected pre-fix refusal',
                'old_withdraw_nonce_consumed_by_settlement':True,'withdrawal_rejected':True,
                'original_intents_retained':digest(owner/'eth-intent-withdraw.json')==original_withdraw
                    and digest(owner/f'eth-intent-{action}.json')==claim_hash,
                'native_tip_unchanged':status()['tip']==tip,'initial_checkpoint_retained':True}
            save(directory/'withdraw-reorg-before-fix.json',result)
            return result

        # New nonce attempt is durable before send. Stop with the actual call
        # pending, restart twice without mining, then reconcile its mined receipt.
        evm.rpc('evm_setAutomine',[False])
        client('withdraw',owner,{'order':order},stop=True)
        pending=evm.rpc('eth_getBlockByNumber',['pending',True])['transactions']
        candidates=[t for t in pending if t['from'].lower()==address.lower()]
        if len(candidates)!=1:raise RuntimeError('one real pending owner withdrawal required')
        replacement=candidates[0]
        if int(replacement['nonce'],16)!=int(first_tx['nonce'],16)+1:
            raise RuntimeError('new withdrawal did not use the available nonce')
        client('withdraw',owner,{'order':order},stop=True)
        again=evm.rpc('eth_getBlockByNumber',['pending',True])['transactions']
        if [t['hash'] for t in again]!=[t['hash'] for t in pending]:
            raise RuntimeError('pending restart created or changed a transaction')
        evm.rpc('evm_mine');evm.rpc('evm_setAutomine',[True])
        higher=client('withdraw',owner,{'order':order})
        if higher['txid']!=replacement['hash'] or higher['new_transaction']:
            raise RuntimeError('restart did not reconcile mined replacement withdrawal')
        attempts={p.name:digest(p) for p in (owner/'eth-withdraw-attempts').glob('*.json')}
        if len(attempts)!=1:raise RuntimeError('expected one additional signed attempt')

        # Another fork puts the owner nonce back to its prior value. Reuse the previously
        # signed lower-nonce bytes instead of discarding/overwriting either intent.
        revert(before_owner_claim)
        evm.rpc('evm_setNextBlockTimestamp',[first_time+30])
        relay()
        lower=client('withdraw',owner,{'order':order})
        lower_receipt=evm.rpc('eth_getTransactionReceipt',[lower['txid']])
        if lower['txid']!=first['txid'] or not lower['new_transaction']:
            raise RuntimeError('lower-nonce fork did not reuse the original withdrawal')
        if lower_receipt['blockHash']==first_receipt['blockHash']:
            raise RuntimeError('lower-nonce withdrawal was not mined on a new branch')
        if attempts!={p.name:digest(p) for p in (owner/'eth-withdraw-attempts').glob('*.json')}:
            raise RuntimeError('nonce rollback rewrote withdrawal attempts')
        if digest(owner/'eth-intent-withdraw.json')!=original_withdraw or digest(owner/f'eth-intent-{action}.json')!=claim_hash:
            raise RuntimeError('original intent changed across fork recovery')
        if status()['tip']!=tip:raise RuntimeError('fork tests changed native funding')
        checkpoint(directory)
        completed=flow.finish(directory,agreement,order,recovered=True)
    repeated=prefunding_swap.recover(directory)
    if repeated['new_native_transactions']!=0 or repeated['new_evm_transactions']!=0:
        raise RuntimeError('completed fork recovery sent duplicate payments')
    result={'scope':'controlled EVM forks after withdrawal; native chain never reverted',
        'mode':mode,'original_withdraw_txid':first['txid'],'new_nonce_withdraw_txid':higher['txid'],
        'original_nonce':int(first_tx['nonce'],16),'new_nonce':int(replacement['nonce'],16),
        'pending_restart_identical':True,'original_intents_retained':True,
        'unrelated_pending_call_rejected_without_new_signature':True,
        'lower_nonce_reuses_original_bytes':True,'extra_attempts_unchanged':True,
        'completed':completed,'repeat':repeated,'public_reorg_policy':False}
    save(directory/'withdraw-reorg-checks.json',result)
    return result


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('directory',type=Path)
    p.add_argument('--expect-nonce-collision',action='store_true')
    a=p.parse_args();os.umask(0o077)
    print(json.dumps(check(a.directory.resolve(),a.expect_nonce_collision),indent=2))
