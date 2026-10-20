#!/usr/bin/env python3
"""Exercise owner receipt rollback and a different canonical claim relayer.

Anvil snapshot/revert creates controlled local fork histories; it is not public
consensus/finality verification. Native funding is real and is never rolled back.
The initial checkpoint is retained until fork checks finish. A failed check can
be recovered through the regular prefunding driver without losing claim intent.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import owner_swap as flow
import prefunding_swap
import run_native_evm_gate as evm
import escrow_abi
from evm_journal import checkpoint, local_order, order_slot
from regtest_node import status, rpc as zrpc
from regtest_wallet import save
from run_client_swap import client


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def revert(snapshot):
    if not evm.rpc('evm_revert',[snapshot]):
        raise RuntimeError('owned Anvil snapshot revert failed')


def check(directory, expect_collision=False):
    if (directory/'08-complete.json').exists():
        raise RuntimeError('requires a current-driver success fixture paused at eth-locked')
    initial_checkpoint = digest(directory/'evm-checkpoint.json')
    with flow.chain_lock(), flow.node(directory,restore=True):
        agreement = flow.validate_recovery(directory)
        order = flow.read(directory/'04-eth-locked.json')['order']
        alice, bob = directory/'owners/alice', directory/'owners/bob'
        state = lambda:flow.order_state(agreement,agreement['native'],order)
        if state()!=1: raise RuntimeError('checkpoint must precede claim')
        native_tip = status()['tip']
        first_snapshot = evm.rpc('evm_snapshot')
        claim = client('claim',alice,{'order':order})
        owner_hash = claim['txid']
        first_receipt = evm.rpc('eth_getTransactionReceipt',[owner_hash])
        first_time = int(evm.rpc('eth_getBlockByNumber',[first_receipt['blockNumber'],False])['timestamp'],16)
        # This data is already public in the real mined transaction.
        public_data = evm.rpc('eth_getTransactionByHash',[owner_hash])['input']
        client('claim',alice,{'order':order})  # Persist the original settlement observation.
        intent_path = alice/'eth-intent-claim.json'
        original_intent = digest(intent_path)
        revert(first_snapshot)
        if state()!=1 or evm.rpc('eth_getTransactionReceipt',[owner_hash]) is not None:
            raise RuntimeError('claim was not removed by controlled fork rollback')
        if digest(intent_path)!=original_intent:
            raise RuntimeError('rollback erased or changed secret-exposure intent')
        native_pool = zrpc('getrawmempool')
        client('native-claim', bob, {'order': order}, reject=True)

        late_snapshot = evm.rpc('evm_snapshot')
        evm.rpc('evm_setNextBlockTimestamp',[agreement['eth_expiry']])
        evm.rpc('evm_mine')
        client('claim',alice,{'order':order},reject=True)
        client('native-claim', bob, {'order': order}, reject=True)
        client('native-refund', alice, {'order': order}, reject=True)
        if state()!=1 or (bob/'eth-intent-refund.json').exists():
            raise RuntimeError('expired exposed claim incorrectly became refund')
        refund_relayer = evm.rpc('eth_accounts')[0]
        v = escrow_abi.version(agreement)
        refund = evm.send({'from': refund_relayer, 'to': agreement['contract'],
            'data': escrow_abi.calldata(v, 'refund', order, local_order(agreement, agreement['native']) if v == 2 else None),
            'gas': hex(200_000)})
        if state() != 3:
            raise RuntimeError('competing ETH refund was not canonical')
        client('native-claim', bob, {'order': order}, reject=True)
        client('native-refund', alice, {'order': order}, reject=True)
        if (zrpc('getrawmempool') != native_pool or status()['tip'] != native_tip
                or digest(intent_path) != original_intent
                or list((alice / 'recovery').glob('refund-*.hex'))):
            raise RuntimeError('native owner crossed a possible-exposure refusal')
        revert(late_snapshot)

        replay_snapshot = evm.rpc('evm_snapshot')
        evm.rpc('evm_setNextBlockTimestamp',[first_time+5])
        replay = client('claim',alice,{'order':order})
        second_receipt = evm.rpc('eth_getTransactionReceipt',[owner_hash])
        if replay['txid']!=owner_hash or not replay['new_transaction'] or second_receipt['blockHash']==first_receipt['blockHash']:
            raise RuntimeError('owner did not replay exact bytes into a different block')
        client('claim',alice,{'order':order})
        for receipt in (first_receipt,second_receipt):
            if not (alice/'eth-receipts'/f'{owner_hash}-{receipt["blockHash"]}.json').exists():
                raise RuntimeError('historical receipt observation was lost')
        revert(replay_snapshot)

        relayer = evm.rpc('eth_accounts')[0]
        evm.rpc('evm_setNextBlockTimestamp',[first_time+10])
        relayed = evm.send({'from':relayer,'to':agreement['contract'],
            'data':public_data,'gas':hex(1_000_000)})
        if relayed['transactionHash']==owner_hash or state()!=2:
            raise RuntimeError('different relayer did not settle the replacement history')
        if expect_collision:
            client('claim',alice,{'order':order},reject=True)
            if digest(directory/'evm-checkpoint.json')!=initial_checkpoint:
                raise RuntimeError('diagnostic changed the initial recovery checkpoint')
            result={'scope':'actual owned EVM rollback, expected pre-fix failure',
                'changed_canonical_relayer_rejected_due_to_fixed_journal':True,
                'signed_exposure_intent_preserved':digest(intent_path)==original_intent,
                'initial_checkpoint_retained':True,'native_tip_unchanged':status()['tip']==native_tip}
            save(directory/'reorg-before-fix.json',result)
            return result
        settled = client('claim',alice,{'order':order})
        if settled['txid']!=relayed['transactionHash'] or settled['new_transaction'] or not settled['settlement_via_other_relayer']:
            raise RuntimeError('owner used an orphaned settlement observation')
        for observed in (first_receipt,second_receipt,relayed):
            history = alice/'eth-settlements'/f'claim-{observed["transactionHash"]}-{observed["blockHash"]}.json'
            if not history.is_file():
                raise RuntimeError('canonical observation history was not retained')
        if digest(intent_path)!=original_intent or status()['tip']!=native_tip:
            raise RuntimeError('fork checks mutated owner intent or native funding')
        if escrow_abi.version(agreement) == 1:
            credit = lambda address:int(evm.rpc('eth_call',[{'to':agreement['contract'],
                'data':evm.calldata('credits(address)',address)},'latest']),16)
            fixed = credit(agreement['recipient'])==agreement['amount_wei'] and credit(relayer)==0
        else:
            # v2 credits the committed order, whose recipient is fixed.
            fixed = order_slot(agreement, agreement['native'], order) == (2, False)
        if not fixed:
            raise RuntimeError('relayer changed fixed ETH recipient')
        # Commit only the chosen replacement history, then settle the native
        # leg using its public claim event and the owner's accepted exit bundle.
        checkpoint(directory)
        result = flow.finish(directory,agreement,order,recovered=True)
    repeated = prefunding_swap.recover(directory)
    if repeated['new_native_transactions']!=0 or repeated['new_evm_transactions']!=0:
        raise RuntimeError('fork recovery repeat submitted a duplicate payment')
    outcome={'scope':'controlled Anvil fork histories; actual native funding and final exit',
        'claim_receipt_removed_then_exact_bytes_replayed':True,
        'original_claim_txid':owner_hash,'old_block_hash':first_receipt['blockHash'],
        'replay_block_hash':second_receipt['blockHash'],
        'canonical_relayer_txid':relayed['transactionHash'],
        'old_receipts_retained_as_history':True,'secret_exposure_intent_unchanged':True,
        'expired_exposed_claim_rejected_without_refund':True,'relayer_credit_zero':True,
        'native_owner_claim_refused_orphaned_expired_and_refunded_eth': True,
        'native_owner_refund_refused_own_exposure_on_expired_and_refunded_eth': True,
        'competing_refund_txid_on_reverted_branch': refund['transactionHash'],
        'settlement':result,'repeat':repeated,'public_reorg_policy':False}
    save(directory/'reorg-checks.json',outcome)
    return outcome


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('directory',type=Path)
    p.add_argument('--expect-settlement-collision',action='store_true')
    a=p.parse_args();os.umask(0o077)
    print(json.dumps(check(a.directory.resolve(),a.expect_settlement_collision),indent=2))
