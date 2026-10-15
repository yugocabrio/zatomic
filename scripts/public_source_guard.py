#!/usr/bin/env python3
"""Immutable local public-source owner pins and permanent funding cancellation.

One wallet currently supports one outstanding preparation. This guard neither
releases a reservation nor signs F. Local file deletion/rollback or spending
outside this wallet is outside its guarantee. No public send RPC is provided.
"""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
from public_evm_observation import digest
from regtest_wallet import native
from source_inputs import publish
from testnet_wallet import GENESIS, read
from testnet_owner import identity

AUTHORITY = 'public-source-authority.json'
CANCELLED = 'public-source-cancelled.json'
# Source signers fsync this release marker before creating ANY F signature.
RELEASE = 'public-source-release.json'


def immutable(path, value):
    if path.exists() or path.is_symlink():
        if read(path) != value: raise RuntimeError('immutable source authority/decision changed')
    else: publish(path, value)


def owners(value):
    if set(value) != {'alice', 'bob'}: raise RuntimeError('exact source owner pair required')
    for role in ('alice', 'bob'): identity(value[role], role)
    if value['alice']['address'] == value['bob']['address']:
        raise RuntimeError('distinct source-approved owners required')
    return value


def wallet_binding(wallet):
    # Derive from the actual local spending key, never a caller-provided FVK or
    # the watch-wallet preference in wallet::fvk. Metadata stays private here.
    r = native('testnet-wallet-receivers', wallet)
    if r['genesis'] != GENESIS or not re.fullmatch('[0-9a-f]{64}', r['fvk_fingerprint']):
        raise RuntimeError('public source wallet identity mismatch')
    return {'genesis': GENESIS, 'fvk_fingerprint': r['fvk_fingerprint'], 'aux_script': r['aux_script']}


def initialize_locked(wallet, pins, expected_digest):
    """The expected fingerprint must come from the source operator's trusted input.

    Do not derive it automatically from an incoming coordinator packet. This is
    local pin provisioning, not independent-host authentication demonstrated.
    """
    pair = owners(read(pins))
    if not re.fullmatch('[0-9a-f]{64}', expected_digest) or digest(pair) != expected_digest:
        raise RuntimeError('source owner pair differs from independently pinned fingerprint')
    value = {'format': 'latch-public-source-authority-v1', 'wallet': wallet_binding(wallet),
        'owners': pair, 'owners_digest': expected_digest}
    # Cancellation or possible release cannot be bypassed by re-initialization.
    active_locked(wallet)
    immutable(wallet/AUTHORITY, value)
    return {'authority_digest': digest(value), 'owners_digest': expected_digest,
        'source_keys_used_only_for_public_identity': True, 'funding_authorized': False, 'broadcast': False}


def active_locked(wallet):
    if (wallet/CANCELLED).exists() or (wallet/CANCELLED).is_symlink():
        raise RuntimeError('public source permanently cancelled; preserve all recovery data')
    # A release marker means authorization may already exist, even if a raw
    # transaction is absent. Initial funding preflight must not start over.
    for name in (RELEASE, 'public-source-funding/intent.json', 'public-source-outgoing.json', 'funding.hex'):
        if (wallet/name).exists() or (wallet/name).is_symlink():
            raise RuntimeError('possible public source release; reconcile outgoing state instead')


def check_locked(wallet, agreement):
    """Caller holds sync.lock; bind source pins before any provider disclosure."""
    active_locked(wallet)
    return dict(identity_locked(wallet, agreement), source_cancelled=False,
        source_release_recorded=False, funding_authorized=False)


def identity_locked(wallet, agreement):
    """Revalidate immutable pins even after a durable release intent exists."""
    value = read(wallet/AUTHORITY)
    if (set(value) != {'format', 'wallet', 'owners', 'owners_digest'}
            or value['format'] != 'latch-public-source-authority-v1'
            or value['owners_digest'] != digest(owners(value['owners']))
            or value['wallet'] != wallet_binding(wallet)
            or value['owners'] != agreement['owners']
            or agreement['native_genesis'] != GENESIS):
        raise RuntimeError('agreement differs from source wallet or approved owner pins')
    return {'authority_digest': digest(value), 'owners_digest': value['owners_digest'],
        'source_fvk_fingerprint': value['wallet']['fvk_fingerprint'],
        'source_aux_script': value['wallet']['aux_script'],
        'source_wallet_and_owner_pins_bound': True}


def cancel_locked(wallet):
    # A malformed or partial intent still forbids cancellation: absence of raw
    # bytes is NOT evidence that no authorization escaped before a crash.
    for name in (RELEASE, 'public-source-funding/intent.json', 'public-source-outgoing.json', 'funding.hex'):
        if (wallet/name).exists() or (wallet/name).is_symlink():
            raise RuntimeError('possible public source release; cancellation requires reconciliation')
    authority = read(wallet/AUTHORITY)
    if (authority['format'] != 'latch-public-source-authority-v1'
            or authority['wallet'] != wallet_binding(wallet)
            or authority['owners_digest'] != digest(owners(authority['owners']))):
        raise RuntimeError('source authority changed before cancellation')
    value = {'format': 'latch-public-source-cancellation-v1', 'authority_digest': digest(authority),
        'future_funding_disabled': True, 'reservation_released': False, 'broadcast': False}
    immutable(wallet/CANCELLED, value)
    return value


def main():
    from public_source import locked
    os.umask(0o077)
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('operation', choices=('init', 'cancel'))
    p.add_argument('wallet', type=Path)
    p.add_argument('--owners', type=Path, help='private Alice/Bob identity pair JSON')
    p.add_argument('--expected-owners-sha256', help='independently trusted canonical pair fingerprint')
    a = p.parse_args()
    with locked(a.wallet):
        if a.operation == 'init':
            if a.owners is None or a.expected_owners_sha256 is None:
                raise RuntimeError('owner pair and independently pinned fingerprint required')
            return initialize_locked(a.wallet, a.owners, a.expected_owners_sha256)
        if a.owners is not None or a.expected_owners_sha256 is not None:
            raise RuntimeError('cancellation uses the existing immutable authority')
        return cancel_locked(a.wallet)


if __name__ == '__main__':
    try: print(json.dumps(main(), indent=2))
    except (RuntimeError, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        raise SystemExit('Source authority operation refused; state retained, no signing or sending.') from None
