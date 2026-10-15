#!/usr/bin/env python3
"""Real native exit forks, with funding kept in the common ancestor.

Only the owned isolated Zebra is mutated. Each fork has a durable marker and
reconsiders its old blocks before returning. Unlike the pre-reveal gate, a
longer replacement branch is intentionally retained, never silently rolled back.
"""
import argparse
import contextlib
import json
import os
from pathlib import Path
import owner_swap as flow
import prefunding_swap
from check_native_reorg import wait
from peer_workspace import sync
from regtest_node import rpc, status, GENESIS, BRANCH
from regtest_wallet import capture, native, save

MARKER = 'native-exit-fork-inflight.json'


def restore(directory):
    path = directory / MARKER
    if not path.exists():
        return
    value = flow.read(path)
    if value['genesis'] != GENESIS or value['branch'] != BRANCH:
        raise RuntimeError('exit fork marker domain mismatch')
    status()
    rpc('reconsiderblock', [value['invalidated_block']], timeout=60)
    wait(lambda: status()['blocks'] >= value['original_height'])
    if not flow.confirmed(value['funding_txid']):
        raise RuntimeError('common-ancestor funding is not confirmed; marker retained')
    path.unlink()
    sync(directory)


@contextlib.contextmanager
def replacement(directory, block, funding_txid):
    before = status()
    funding = rpc('getrawtransaction', [funding_txid, 1])
    funding_height = rpc('getblock', [funding['blockhash'], 1])['height']
    root = rpc('getblock', [block, 1])
    if root['height'] <= funding_height + 1 or root.get('confirmations', 0) < 1:
        raise RuntimeError('exit fork must preserve two-confirmation funding')
    save(directory / MARKER, {'genesis': GENESIS, 'branch': BRANCH,
        'invalidated_block': block, 'original_tip': before['tip'],
        'original_height': before['blocks'], 'funding_txid': funding_txid})
    chosen = None
    try:
        rpc('invalidateblock', [block], timeout=60)
        wait(lambda: status()['tip'] != before['tip'])
        yield
        # Avoid equal-work ambiguity when re-enabling the old branch. This is
        # controlled test mining, not a client rule for public-chain finality.
        extra = before['blocks'] + 1 - status()['blocks']
        if extra > 0:
            rpc('generate', [extra], timeout=300)
        chosen = status()['tip']
    finally:
        restore(directory)
    if status()['tip'] != chosen:
        raise RuntimeError('the longer replacement branch did not remain selected')


def count_proofs(workspace, mode):
    return len(list(workspace.glob(f'{mode}-*.hex')))


def exact_result(result, txid, submissions):
    if (result['native_txid'] != txid or result['new_native_transactions'] != submissions
            or result['new_evm_transactions'] != 0):
        raise RuntimeError('recovery changed payment identity or unexpected submissions')


def check(directory):
    with flow.chain_lock():
        restore(directory)
        if (directory / '08-complete.json').exists():
            raise RuntimeError('requires fresh paused fixture; recover an interrupted checker normally')
        mode = flow.read(directory / 'setup.json')['mode']
        exit_mode, receiver = ('claim', 'bob') if mode == 'success' else ('refund', 'alice')
        workspace = directory / 'owners' / receiver / 'recovery'
        agreement = flow.read(directory / 'agreement.json')
        funding_txid = agreement['native']['funding_txid']
        funding = rpc('getrawtransaction', [funding_txid, 1])
        if not funding.get('in_active_chain') or funding.get('confirmations') != 2:
            raise RuntimeError('run immediately after this fixture reaches two funding confirmations')
        if mode == 'success' and not (directory / 'owners/alice/eth-intent-claim.json').exists():
            raise RuntimeError('success gate requires prior actual ETH secret exposure')
        # A shielded coinbase changes the tree after F, making an anchor that
        # can be genuinely orphaned without removing F from the common ancestor.
        miner = native('regtest-init', directory / 'fork-miner')
        if mode == 'refund':
            extra = agreement['native']['refund_height'] + 1 - status()['blocks']
            if extra > 0:
                rpc('generate', [extra], timeout=300)
        anchor_block = rpc('generatetoaddress', [1, miner['address']], timeout=300)[0]
        old_capture = capture(workspace)
        old_scan = flow.read(Path(old_capture['file']))
        order = flow.read(directory / '04-eth-locked.json')['order']
        with flow.node(directory, restore=True):
            flow.validate_recovery(directory)
            completed = flow.finish(directory, agreement, order, recovered=True)
        txid = completed['native_txid']
        files = list(workspace.glob(f'{exit_mode}-*.hex'))
        if len(files) != 1:
            raise RuntimeError('fresh exit must have exactly one persisted proof')
        original_file = files[0]
        original = native('regtest-inspect', original_file)
        if original['ironwood_anchor'] != old_scan['anchor']:
            raise RuntimeError('original exit did not use the intended fork anchor')
        original_bytes = original_file.read_bytes()
        checks = []

        # Already mined effects must not be re-broadcast when depth drops to 1.
        with replacement(directory, status()['tip'], funding_txid):
            one = rpc('getrawtransaction', [txid, 1])
            if one['confirmations'] != 1:
                raise RuntimeError('exit did not lose one confirmation')
            result = prefunding_swap.recover_locked(directory)
            exact_result(result, txid, 0)
            if count_proofs(workspace, exit_mode) != 1:
                raise RuntimeError('one-confirmation recovery unnecessarily re-proved')
        checks.append({'case': 'one_confirmation', 'same_payment': True,
            'new_proofs': 0, 'native_submissions': 0, 'evm_submissions': 0})

        # An actual pending re-broadcast after another exit rollback must also
        # resume by confirming the existing bytes, without another proof/send.
        block = rpc('getrawtransaction', [txid, 1])['blockhash']
        with replacement(directory, block, funding_txid):
            accepted = rpc('sendrawtransaction', [original_file.read_text().strip()], timeout=180)
            if accepted != txid or txid not in rpc('getrawmempool'):
                raise RuntimeError('exact replacement exit was not actually pending')
            result = prefunding_swap.recover_locked(directory)
            exact_result(result, txid, 0)
            if count_proofs(workspace, exit_mode) != 1:
                raise RuntimeError('pending recovery unnecessarily re-proved')
        checks.append({'case': 'pending_after_reorg', 'exact_bytes_pending': True,
            'recovery_native_submissions': 0, 'new_proofs': 0, 'evm_submissions': 0})

        # Remove the anchor itself, create a DIFFERENT shielded tree at the
        # SAME height, and require native rejection of the old authorization.
        with replacement(directory, anchor_block, funding_txid):
            if txid in rpc('getrawmempool'):
                raise RuntimeError('expected old exit absent from mempool')
            rpc('generatetoaddress', [1, miner['address']], timeout=300)
            replacement_capture = capture(workspace)
            new_scan = flow.read(Path(replacement_capture['file']))
            if (new_scan['height'] != old_scan['height'] or new_scan['tip'] == old_scan['tip']
                    or new_scan['anchor'] == old_scan['anchor']):
                raise RuntimeError('test did not replace the actual anchor at equal height')
            try:
                rpc('sendrawtransaction', [original_file.read_text().strip()], timeout=180)
            except RuntimeError as exc:
                rejection = str(exc)
                if 'anchor' not in rejection.lower():
                    raise RuntimeError('old authorization failed for a reason other than anchor') from exc
            else:
                raise RuntimeError('orphaned anchor authorization unexpectedly accepted')
            result = prefunding_swap.recover_locked(directory)
            exact_result(result, txid, 1)
            newer = [p for p in workspace.glob(f'{exit_mode}-*.hex') if p != original_file]
            if len(newer) != 1 or original_file.read_bytes() != original_bytes:
                raise RuntimeError('re-proof did not preserve the original authorization history')
            reproved_file = newer[0]
            reproved = native('regtest-inspect', reproved_file)
            if (reproved['ironwood_anchor'] != new_scan['anchor']
                    or reproved['txid'] != original['txid']
                    or reproved['authorization_bytes_sha256'] == original['authorization_bytes_sha256']):
                raise RuntimeError('replacement proof did not change anchor with fixed effects')
            if flow.read(Path(old_capture['file'])) != old_scan:
                raise RuntimeError('old branch scan was overwritten')
        checks.append({'case': 'orphaned_anchor', 'same_height_captures_retained': True,
            'old_anchor': old_scan['anchor'], 'replacement_anchor': new_scan['anchor'],
            'old_tip': old_scan['tip'], 'replacement_tip': new_scan['tip'],
            'old_authorization_rejected': rejection, 'same_payment_txid': txid,
            'changed_authorization_bytes': True, 'native_submissions': 1,
            'evm_submissions': 0, 'old_proof_retained': True})

    repeated = prefunding_swap.recover(directory)
    exact_result(repeated, txid, 0)
    result = {'scope': 'actual owned Zebra exit forks; longer replacement branches retained',
        'mode': mode, 'funding_txid': funding_txid, 'native_txid': txid,
        'checks': checks, 'completed': completed, 'repeat': repeated,
        'funding_kept_in_common_ancestor': True,
        'all_invalidated_blocks_reconsidered': not (directory / MARKER).exists(),
        'post_eth_secret_exposure': mode == 'success', 'public_reorg_policy': False}
    save(directory / 'native-exit-reorg-checks.json', result)
    return result


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('directory', type=Path)
    p.add_argument('--restore-only', action='store_true')
    a = p.parse_args()
    os.umask(0o077)
    directory = a.directory.resolve()
    if a.restore_only:
        with flow.chain_lock():
            restore(directory)
        print(json.dumps({'restoration_marker_cleared': not (directory / MARKER).exists()}))
    else:
        print(json.dumps(check(directory), indent=2))
