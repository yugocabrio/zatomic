#!/usr/bin/env python3
"""Reject replaced owner recovery data through the actual CLI, without keys.

Only watch-only exit data and public agreement/identity are copied into ignored
private fixtures. The completed original owner's state is never edited.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import detached_owner
import owner_swap as flow
import peer_workspace
import run_native_evm_gate as evm
from regtest_node import rpc, status
from regtest_wallet import save
from run_client_swap import client


def clone(source, target):
    names = ['identity.json', 'eth-agreement.json', 'eth-acceptance.json',
        'native/recovery-bundle.json', 'native/recovery-receipt.json',
        'recovery/recovery-ready.json', 'recovery/terms.json', 'recovery/pending-note.json',
        'recovery/joint-fvk.bin', 'recovery/bob/joint-fvk.bin',
        'recovery/bob/claim.pczt', 'recovery/bob/presignature.json']
    names += [str(p.relative_to(source)) for p in (source / 'recovery').glob('claim-*.hex')]
    for name in names:
        path = target / name
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        shutil.copyfile(source / name, path)


def changed(path, key, value):
    data = flow.read(path)
    data[key] = value
    # Deliberately corrupt only this test's copy; production save() correctly
    # refuses changing an immutable private snapshot.
    path.write_text(json.dumps(data))


def relocation(fixture, directory):
    results = []
    # Reconstruct every durable forward-rename gap without any actual key.
    for step in range(4):
        root = directory / f'relocation-{step}'
        owner = root / 'owners/bob'
        for name in ('agreement.json', 'owner-flow.json'):
            root.mkdir(mode=0o700, parents=True, exist_ok=True)
            shutil.copyfile(fixture / name, root / name)
        for name in ('identity.json', 'eth-agreement.json', 'eth-acceptance.json', 'recovery/recovery-ready.json'):
            target = owner / name
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            shutil.copyfile(fixture / 'owners/bob' / name, target)
        (owner / 'ethereum').mkdir(mode=0o700)
        (owner / 'ethereum/synthetic-placeholder').write_text('not a key')
        control = detached_owner.paths(root)
        control.mkdir(mode=0o700)
        binding = peer_workspace.identity(root, owner, 'bob')
        save(control / 'inflight.json', {'version': 1, 'fixture': str(root), 'role': 'bob', 'binding': binding})
        if step >= 1:
            owner.rename(control / 'owner')
        if step >= 2:
            root.rename(control / 'coordinator')
        if step >= 3:
            (control / 'owner/ethereum').rename(control / 'eth-key-offline')
        detached_owner.restore(root)
        detached_owner.restore(root)
        if (peer_workspace.identity(root, owner, 'bob') != binding
                or (owner / 'ethereum/synthetic-placeholder').read_text() != 'not a key'
                or list(control.iterdir())):
            raise RuntimeError('detached-owner rename gap did not reconcile')
        results.append(step)
    return results


def check(fixture, directory):
    directory.mkdir(mode=0o700)
    with flow.chain_lock(), flow.node(fixture, restore=True):
        original = fixture / 'owners/bob'
        order = flow.read(fixture / '04-eth-locked.json')['order']
        before = (status()['tip'], rpc('getrawmempool'), evm.rpc('eth_blockNumber'))
        cases = ['valid', 'wrong_role', 'wrong_funding', 'wrong_digest', 'spend_key_flag',
            'changed_terms', 'changed_pending_note', 'changed_joint_fvk', 'changed_recipient_fvk',
            'changed_pczt', 'changed_presignature', 'symlink_file', 'symlink_role_directory',
            'symlink_recovery_directory', 'public_file_permissions', 'oversized_pczt']
        rejected = []
        for case in cases:
            owner = directory / case
            clone(original, owner)
            root = owner / 'recovery'
            if case == 'wrong_role':
                changed(root / 'recovery-ready.json', 'participant', 1)
            elif case == 'wrong_funding':
                changed(root / 'recovery-ready.json', 'funding_txid', '00' * 32)
            elif case == 'wrong_digest':
                changed(root / 'recovery-ready.json', 'bundle_digest', '00' * 32)
            elif case == 'spend_key_flag':
                changed(root / 'recovery-ready.json', 'spending_keys_exported', True)
            elif case == 'changed_terms':
                changed(root / 'terms.json', 'payout_zatoshi', 1)
            elif case == 'changed_pending_note':
                changed(root / 'pending-note.json', 'substituted', True)
            elif case in ('changed_joint_fvk', 'changed_recipient_fvk', 'changed_pczt', 'oversized_pczt'):
                path = root / {'changed_joint_fvk': 'joint-fvk.bin', 'changed_recipient_fvk': 'bob/joint-fvk.bin',
                    'changed_pczt': 'bob/claim.pczt', 'oversized_pczt': 'bob/claim.pczt'}[case]
                path.write_bytes(b'\0' * (200_001 if case == 'oversized_pczt' else 32))
            elif case == 'changed_presignature':
                changed(root / 'bob/presignature.json', 'substituted', True)
            elif case.startswith('symlink_'):
                path = root / 'bob/claim.pczt' if case == 'symlink_file' else root / 'bob' if case == 'symlink_role_directory' else root
                offline = path.with_name(path.name + '-offline')
                path.rename(offline)
                path.symlink_to(offline)
            elif case == 'public_file_permissions':
                (root / 'bob/claim.pczt').chmod(0o644)
            result = client('native-claim', owner, {'order': order}, reject=case != 'valid')
            if case == 'valid':
                if result['state'] != 'confirmed' or result['new_transaction']:
                    raise RuntimeError('valid watch-only copy did not reconcile')
            else:
                rejected.append(case)
        after = (status()['tip'], rpc('getrawmempool'), evm.rpc('eth_blockNumber'))
        if before != after:
            raise RuntimeError('binding checks mutated a chain')
    result = {'scope': 'actual owner CLI and continuing owned chain; private watch-only copies',
        'valid_copy_reconciled_without_send': True, 'rejected': rejected,
        'chain_tips_and_native_mempool_unchanged': True, 'spending_keys_copied': False,
        'detached_owner_forward_rename_gaps_restored_twice': relocation(fixture, directory)}
    save(directory / 'checks.json', result)
    return result


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('fixture', type=Path)
    p.add_argument('directory', type=Path)
    a = p.parse_args()
    os.umask(0o077)
    print(json.dumps(check(a.fixture.resolve(), a.directory.resolve()), indent=2))
