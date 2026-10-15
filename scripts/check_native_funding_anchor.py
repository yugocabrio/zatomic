#!/usr/bin/env python3
"""Prove the limit: published F cannot be re-proved from a shared-note bundle.

Invalidates the dedicated shielded block selected as this F's source anchor.
The owner must reject without signing or mutating either chain; the old branch
is then restored and the actual exchange completes normally.
"""
import argparse
import json
import os
from pathlib import Path
import owner_swap as flow
import prefunding_swap
from check_evm_reorg import digest
from check_native_funding_reorg import fork, restore
from regtest_node import rpc, status
from regtest_wallet import save
from run_client_swap import client


def check(directory, seed):
    with flow.chain_lock():
        restore(directory)
        if (directory / '08-complete.json').exists():
            raise RuntimeError('requires fresh fixture paused after ETH claim')
        original_tip = status()['tip']
        seed = flow.read(seed / 'seed.json')
        agreement = flow.read(directory / 'agreement.json')
        funding_txid = agreement['native']['funding_txid']
        original = rpc('getrawtransaction', [funding_txid, 1])
        expected_seed = agreement['native'].get('funding_anchor_tip')
        if expected_seed is None:
            expected_seed = rpc('getblock', [original['blockhash'], 1])['previousblockhash']
        if original['confirmations'] != 2 or expected_seed != seed['block']:
            raise RuntimeError('requires the dedicated seed block at the agreed source anchor')
        source = directory / 'coordinator-native-offline/funding.hex'
        source_digest = digest(source)
        intent = directory / 'owners/alice/eth-intent-claim.json'
        exposure_digest = digest(intent)
        checkpoint_digest = digest(directory / 'evm-checkpoint.json')
        with flow.node(directory, restore=True):
            flow.validate_recovery(directory)
            order = flow.read(directory / '04-eth-locked.json')['order']
            claimed = flow.public_event(agreement, 'Claimed(bytes32,uint256)', order)['transactionHash']
            with fork(directory, seed['block'], funding_txid):
                before, pool = status()['tip'], rpc('getrawmempool')
                try:
                    rpc('sendrawtransaction', [original['hex']], timeout=180)
                except RuntimeError as exc:
                    rejection = str(exc)
                    if 'unknown Ironwood anchor' not in rejection:
                        raise RuntimeError('source funding failed for an unexpected reason') from exc
                else:
                    raise RuntimeError('source anchor was still accepted after rollback')
                client('restore-funding', directory / 'owners/bob', {'order': order}, reject=True)
                if (status()['tip'] != before or rpc('getrawmempool') != pool
                        or digest(source) != source_digest or digest(intent) != exposure_digest
                        or digest(directory / 'evm-checkpoint.json') != checkpoint_digest
                        or flow.public_event(agreement, 'Claimed(bytes32,uint256)', order)['transactionHash'] != claimed
                        or (directory / 'owners/bob/eth-intent-refund.json').exists()):
                    raise RuntimeError('unavailable-source recovery changed funds or exposure state')
        if status()['tip'] != original_tip:
            raise RuntimeError('source-anchor gate did not restore its original branch')
        completed = prefunding_swap.recover_locked(directory)
    repeated = prefunding_swap.recover(directory)
    if repeated['new_native_transactions'] or repeated['new_evm_transactions']:
        raise RuntimeError('source-anchor restoration repeated a payment')
    result = {'scope': 'actual source-anchor invalidation, explicit refusal and original-branch restoration',
        'funding_txid': funding_txid, 'unavailable_anchor_rejection': rejection,
        'owner_did_not_claim_source_reproof': True, 'no_source_signature_requested': True,
        'native_tip_and_mempool_unchanged_on_rejection': True,
        'eth_claim_and_exposure_intent_unchanged': True, 'no_refund_intent_created': True,
        'original_branch_restored_before_completion': True, 'completed': completed, 'repeat': repeated,
        'funding_source_reproof_implemented': False, 'public_reorg_policy': False}
    save(directory / 'native-funding-anchor-checks.json', result)
    return result


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('directory', type=Path)
    p.add_argument('seed', type=Path)
    a = p.parse_args()
    os.umask(0o077)
    print(json.dumps(check(a.directory.resolve(), a.seed.resolve()), indent=2))
