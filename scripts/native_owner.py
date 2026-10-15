"""Bind an owner's watch-only exit workspace to its own accepted native bundle.

No peer directory, coordinator checkpoint, source wallet or spending key is
read. Current chain status is observed separately by the owning CLI.
"""
import json
from signer_transport import private_file


def workspace(directory, role, terms, bundle, receipt):
    root = directory / 'recovery'
    if role not in ('alice', 'bob') or any(p.is_symlink() or not p.is_dir()
            for p in (root, root / role)):
        raise RuntimeError('owner native workspace requires real role directories')
    ready = json.loads(private_file(root / 'recovery-ready.json'))
    expected_mode = 'claim' if role == 'bob' else 'refund'
    if (ready['funding_txid'] != terms['funding_txid'] or ready['mode'] != expected_mode
            or ready['participant'] != (2 if role == 'bob' else 1)
            or ready['bundle_digest'] != receipt['bundle_digest']
            or ready['spending_keys_exported'] is not False):
        raise RuntimeError('owner native workspace identity changed')
    for name, expected in [('terms.json', terms), ('pending-note.json', bundle['policy']['pending'])]:
        if json.loads(private_file(root / name, 200_000)) != expected:
            raise RuntimeError('owner native workspace terms changed')
    encoded = {'joint-fvk.bin': bundle['policy']['joint_fvk'],
        f'{role}/joint-fvk.bin': bundle['policy'][f'{role}_fvk'],
        f'{role}/{expected_mode}.pczt': bundle[expected_mode]}
    for name, value in encoded.items():
        if private_file(root / name, 200_000) != bytes.fromhex(value):
            raise RuntimeError('owner native workspace differs from accepted bundle')
    if role == 'bob' and json.loads(private_file(root / 'bob/presignature.json')) != bundle['presignature']:
        raise RuntimeError('owner native pre-signature changed')
    return root
