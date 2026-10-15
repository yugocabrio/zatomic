#!/usr/bin/env python3
"""Restore published F after a real native fork and a canonical ETH claim.

The same run also removes the ETH claim and expires it on a controlled EVM
branch: Bob must refuse native restoration in both cases. No source key is read
by the recovery client. Test-only branch manipulation is confined to own nodes.
"""
import argparse
import contextlib
import json
import os
from pathlib import Path
import owner_swap as flow
import prefunding_swap
import run_native_evm_gate as evm
from check_evm_reorg import digest, revert
from check_native_reorg import wait
from evm_journal import checkpoint
from peer_workspace import sync
from regtest_node import rpc, status, GENESIS, BRANCH
from regtest_wallet import native, save
from run_client_swap import client

MARKER = 'native-funding-fork-inflight.json'


def restore(directory):
    path = directory / MARKER
    if not path.exists():
        return
    value = flow.read(path)
    if value['genesis'] != GENESIS or value['branch'] != BRANCH:
        raise RuntimeError('funding fork marker domain mismatch')
    status()
    rpc('reconsiderblock', [value['invalidated_block']], timeout=60)
    wait(lambda: flow.confirmed(value['funding_txid']))
    path.unlink()
    sync(directory)


@contextlib.contextmanager
def fork(directory, block, funding_txid):
    before = status()
    if not flow.confirmed(funding_txid):
        raise RuntimeError('fork requires currently confirmed funding')
    save(directory / MARKER, {'genesis': GENESIS, 'branch': BRANCH,
        'invalidated_block': block, 'funding_txid': funding_txid,
        'original_tip': before['tip'], 'original_height': before['blocks']})
    try:
        rpc('invalidateblock', [block], timeout=60)
        wait(lambda: status()['tip'] != before['tip'])
        if flow.confirmed(funding_txid):
            raise RuntimeError('funding remained confirmed after test invalidation')
        yield
    finally:
        restore(directory)


def no_funding_mutation(directory, order, claim_intent, expected_intent, name):
    before, pool = status()['tip'], rpc('getrawmempool')
    client('restore-funding', directory / 'owners/bob', {'order': order}, reject=True)
    if (status()['tip'] != before or rpc('getrawmempool') != pool
            or digest(claim_intent) != expected_intent
            or (directory / 'owners/bob/eth-intent-refund.json').exists()):
        raise RuntimeError('unsafe funding restoration changed funds or exposure intent')
    return {'case': name, 'restoration_rejected': True,
        'native_tip_and_mempool_unchanged': True, 'exposure_intent_retained': True,
        'no_refund_intent_created': True}


def check(directory, direct=False, orphan_source_tip=False):
    with flow.chain_lock():
        restore(directory)
        if (directory / '08-complete.json').exists():
            raise RuntimeError('requires a fresh success fixture paused at eth-locked')
        with contextlib.ExitStack() as forks:
            with flow.node(directory, restore=True):
                agreement = flow.validate_recovery(directory)
                funding_txid = agreement['native']['funding_txid']
                original_funding = rpc('getrawtransaction', [funding_txid, 1])
                if original_funding['confirmations'] != 2:
                    raise RuntimeError('run immediately after two funding confirmations')
                order = flow.read(directory / '04-eth-locked.json')['order']
                bob, alice = directory / 'owners/bob', directory / 'owners/alice'
                histories = list((bob / 'native-funding-observed').glob('*.json'))
                if len(histories) != 1:
                    raise RuntimeError('Bob did not retain the originally published funding')
                original_history = digest(histories[0])
                source_authorization = directory / 'coordinator-native-offline/funding.hex'
                source_digest = digest(source_authorization)
                miner = native('regtest-init', directory / 'fork-miner')
                before_claim = evm.rpc('evm_snapshot')
                claim = client('claim', alice, {'order': order})
                checkpoint(directory)
                intent = alice / 'eth-intent-claim.json'
                exposure_digest = digest(intent)
                public_call = evm.rpc('eth_getTransactionByHash', [claim['txid']])['input']
                client('restore-funding', alice, {'order': order}, reject=True)
                checks = [{'case': 'wrong_owner', 'restoration_rejected': True}]

                removed = original_funding['blockhash']
                if orphan_source_tip:
                    terms = agreement['native']
                    if (terms['source_height'] - terms['funding_anchor_height'] != 6
                            or terms['refund_height'] != terms['source_height'] + 20
                            or rpc('getblock', [original_funding['blockhash'], 1])['previousblockhash'] != terms['source_tip']):
                        raise RuntimeError('requires current-clock funding with a six-block older anchor')
                    removed = terms['source_tip']
                forks.enter_context(fork(directory, removed, funding_txid))
                if funding_txid in rpc('getrawmempool'):
                    raise RuntimeError('test expected funding absent from native mempool')
                # Remove the actual ETH claim too; retained exposure is still
                # real even when neither chain currently contains settlement.
                revert(before_claim)
                if flow.order_state(agreement, agreement['native'], order) != 1:
                    raise RuntimeError('ETH claim rollback did not happen')
                checks.append(no_funding_mutation(directory, order, intent, exposure_digest, 'eth_claim_orphaned'))
                before_expiry = evm.rpc('evm_snapshot')
                evm.rpc('evm_setNextBlockTimestamp', [agreement['eth_expiry']])
                evm.rpc('evm_mine')
                checks.append(no_funding_mutation(directory, order, intent, exposure_digest, 'exposed_claim_expired'))
                refund_relayer = evm.rpc('eth_accounts')[0]
                refunded = evm.send({'from': refund_relayer, 'to': agreement['contract'],
                    'data': evm.calldata('refund(bytes32)', order), 'gas': hex(200_000)})
                if flow.order_state(agreement, agreement['native'], order) != 3:
                    raise RuntimeError('competing ETH refund did not settle')
                refused = no_funding_mutation(directory, order, intent, exposure_digest, 'eth_refund_won')
                checks.append(dict(refused, actual_refund_txid=refunded['transactionHash']))
                revert(before_expiry)
                # Relay the already-public call into the timely replacement
                # branch. This is a test relayer, not a fabricated receipt.
                relayer = evm.rpc('eth_accounts')[0]
                relayed = evm.send({'from': relayer, 'to': agreement['contract'],
                    'data': public_call, 'gas': hex(1_000_000)})
                flow.public_event(agreement, 'Claimed(bytes32,uint256)', order)
                checkpoint(directory)
                # Add a different shielded leaf before restoring F so its note
                # position and later C witness come from the new native branch.
                rpc('generatetoaddress', [1, miner['address']], timeout=300)
                if not direct:
                    with flow.peer_offline(directory / 'owners', 'alice'):
                        stopped = client('restore-funding', bob, {'order': order}, stop=True)
                        if (stopped.get('intentional_stop') != 'owner-send-before-receipt'
                                or funding_txid not in rpc('getrawmempool')):
                            raise RuntimeError('actual funding-send interruption was not pending')
            completed = prefunding_swap.recover_locked(directory)
            resumed = completed['native_funding_recovery']
            if (not resumed or resumed['new_transaction'] != direct
                    or resumed['new_source_signature'] or resumed['txid'] != funding_txid
                    or completed['new_native_transactions'] != (2 if direct else 1)):
                raise RuntimeError('normal recovery did not reconcile exact native funding')
            current = rpc('getrawtransaction', [funding_txid, 1])
            if (current['blockhash'] == original_funding['blockhash']
                    or current['hex'] != original_funding['hex']
                    or digest(histories[0]) != original_history
                    or digest(source_authorization) != source_digest
                    or digest(intent) != exposure_digest):
                raise RuntimeError('funding restoration changed authorized bytes or owner history')
            chosen = status()['tip']
        if status()['tip'] != chosen:
            raise RuntimeError('replacement native branch was not retained')
    repeated = prefunding_swap.recover(directory)
    if repeated['new_native_transactions'] or repeated['new_evm_transactions']:
        raise RuntimeError('funding fork recovery repeated a payment')
    result = {'scope': 'actual native funding replacement and EVM claim rollback on owned nodes',
        'checks': checks, 'funding_txid': funding_txid,
        'original_funding_block': original_funding['blockhash'], 'replacement_funding_block': current['blockhash'],
        'original_claim_txid': claim['txid'], 'canonical_relayer_txid': relayed['transactionHash'],
        'driver_restored_absent_funding': direct,
        'preparation_tip_also_orphaned': orphan_source_tip,
        'pending_funding_observed_after_owner_exit': not direct, 'alice_offline_during_funding_broadcast': not direct,
        'funding_raw_bytes_unchanged': True, 'source_authorization_file_unchanged': True,
        'exposure_intent_unchanged': True, 'owner_restart': resumed,
        'completed': completed, 'repeat': repeated, 'old_blocks_reconsidered': not (directory / MARKER).exists(),
        'source_anchor_remained_available': True, 'public_reorg_policy': False}
    save(directory / 'native-funding-reorg-checks.json', result)
    return result


def check_depth(directory):
    """Exercise the normal driver when F stays canonical but loses depth."""
    with flow.chain_lock():
        restore(directory)
        agreement = flow.read(directory / 'agreement.json')
        completed = flow.read(directory / '08-complete.json')
        funding_txid = agreement['native']['funding_txid']
        original = rpc('getrawtransaction', [funding_txid, 1])
        paid = rpc('getrawtransaction', [completed['native_txid'], 1])
        if completed['mode'] != 'success' or original['confirmations'] != 4 or paid['confirmations'] != 2:
            raise RuntimeError('depth gate requires the latest just-completed four-block success')
        height = rpc('getblock', [original['blockhash'], 1])['height']
        confirming_block = rpc('getblockhash', [height + 1])
        before = status()
        with fork(directory, confirming_block, funding_txid):
            if rpc('getrawtransaction', [funding_txid, 1])['confirmations'] != 1:
                raise RuntimeError('funding did not drop to one confirmation')
            result = prefunding_swap.recover_locked(directory)
            restored = result['native_funding_recovery']
            if (not restored or restored['new_transaction'] or result['new_evm_transactions']
                    or result['native_txid'] != completed['native_txid']
                    or result['new_native_transactions'] != 1):
                raise RuntimeError('one-confirmation funding recovery changed a payment')
            extra = before['blocks'] + 1 - status()['blocks']
            if extra > 0:
                rpc('generate', [extra], timeout=300)
            chosen = status()['tip']
        if status()['tip'] != chosen:
            raise RuntimeError('depth recovery replacement branch was not selected')
    repeated = prefunding_swap.recover(directory)
    if repeated['new_native_transactions'] or repeated['new_evm_transactions']:
        raise RuntimeError('depth recovery repeated a payment')
    outcome = {'scope': 'actual F confirmation loss after a completed exchange',
        'funding_txid': funding_txid, 'funding_not_resent_or_resigned': True,
        'orphaned_exit_reproved_with_same_txid': True, 'completed': result, 'repeat': repeated}
    save(directory / 'native-funding-depth-checks.json', outcome)
    return outcome


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('directory', type=Path)
    mode = p.add_mutually_exclusive_group()
    mode.add_argument('--restore-only', action='store_true')
    mode.add_argument('--depth-only', action='store_true')
    mode.add_argument('--direct-recovery', action='store_true')
    p.add_argument('--orphan-source-tip', action='store_true')
    a = p.parse_args()
    os.umask(0o077)
    directory = a.directory.resolve()
    if a.restore_only:
        with flow.chain_lock():
            restore(directory)
        print(json.dumps({'restoration_marker_cleared': not (directory / MARKER).exists()}))
    else:
        result = check_depth(directory) if a.depth_only else check(directory, direct=a.direct_recovery,
            orphan_source_tip=a.orphan_source_tip)
        print(json.dumps(result, indent=2))
