#!/usr/bin/env python3
"""Exercise caller pins and source cancellation with real consent verification.

Copies only accepted public/private protocol packets, not owner signing keys.
New testnet-profile source keys stay in unfunded ignored test directories. No
RPC, proof generation, funding authorization or transaction signing occurs.
"""
import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import public_authority as caller
import public_preflight
import public_source
import public_source_guard as guard
from public_evm_observation import digest
from regtest_wallet import ROOT, native, save
from testnet_wallet import read

OWNER_FILES = ('identity.json', 'trusted-peer.json', 'accepted-trade.json',
    'authenticated-destinations.json', 'reviewed-graph-packet.json',
    'public-native-recovery.json', 'public-native-recovery-receipt.json',
    'public-consent-proposal.json', 'public-conditional-consent.json')


def refuses(fn, text):
    try: fn()
    except (RuntimeError, ValueError) as error:
        if text not in str(error): raise RuntimeError('unexpected authority refusal') from error
    else: raise RuntimeError('authority check incorrectly passed')


def check(root, fixture):
    root.mkdir(mode=0o700)
    for role in ('alice', 'bob'):
        (root/role).mkdir(mode=0o700)
        for name in OWNER_FILES:
            shutil.copyfile(fixture/role/name, root/role/name); os.chmod(root/role/name, 0o600)
    for name in ('native-recovery.json', 'conditional-proposal.json', 'conditional-consents.json'):
        shutil.copyfile(fixture/'coordinator'/name, root/name); os.chmod(root/name, 0o600)
    paths = [root/'native-recovery.json', root/'conditional-proposal.json', root/'conditional-consents.json']
    files, verified = caller.verified_files(*paths) # Real native signatures/proofs, no mocked verifier.
    agreement = files['proposal']['agreement']
    for role, phase in (('alice', 'first_reveal'), ('bob', 'eth_lock')):
        peer = 'bob' if role == 'alice' else 'alice'
        denied = (fixture, root/peer)
        policy = '(version 1)(allow default)'+''.join(
            '(deny file-read* file-write* (subpath '+json.dumps(str(p))+'))' for p in denied)
        probe = subprocess.run(['/usr/bin/sandbox-exec', '-p', policy, sys.executable, '-c',
            'from pathlib import Path;import sys\ntry: Path(sys.argv[1]).read_bytes()\nexcept PermissionError: sys.exit(0)\nelse: sys.exit(9)',
            str(fixture/role/'identity.json')], capture_output=True)
        if probe.returncode: raise RuntimeError('original owner root not denied')
        result = subprocess.run(['/usr/bin/sandbox-exec', '-p', policy, sys.executable,
            str(ROOT/'scripts/public_authority.py'), str(root/role), *map(str, paths), phase],
            capture_output=True, text=True, timeout=60)
        if result.returncode:
            save(root/'error.json', {'stderr': result.stderr})
            raise RuntimeError('keyless owner binding failed')
        r = json.loads(result.stdout)
        assert r['role'] == role and r['local_identity_and_peer_pins_bound'] and r['synthetic_inputs']
        with caller.owner_locked(root/role):
            assert caller.bind_owner(root/role, files, verified, phase)['exact_local_acceptance_bound']
            refuses(lambda: caller.bind_owner(root/role, files, verified, 'eth_lock' if role == 'alice' else 'funding'),
                'identity schema/role/chain mismatch')
            # Retained authorization from another role must never match just
            # because both signatures in the incoming agreement are valid.
            path = root/role/'public-conditional-consent.json'; saved = path.read_bytes()
            path.write_text(json.dumps(files['consents'][peer]))
            refuses(lambda: caller.bind_owner(root/role, files, verified, phase), 'did not save this exact')
            path.write_bytes(saved)
            pin = root/role/'trusted-peer.json'; saved = pin.read_bytes()
            wrong = copy.deepcopy(agreement['owners'][role]); wrong['role'] = peer
            pin.write_text(json.dumps({'identity': wrong}))
            refuses(lambda: caller.bind_owner(root/role, files, verified, phase), 'differ from caller identity')
            pin.write_bytes(saved)
            child = subprocess.run([sys.executable, '-c',
                'import sys;from pathlib import Path;from public_authority import owner_locked\ntry:\n with owner_locked(Path(sys.argv[1])): pass\nexcept BlockingIOError: sys.exit(0)\nelse: sys.exit(9)',
                str(root/role)], env=dict(os.environ, PYTHONPATH=str(ROOT/'scripts')), capture_output=True)
            if child.returncode: raise RuntimeError('owner operator lock not exclusive')
    with caller.owner_locked(root/'alice'):
        assert caller.bind_owner(root/'alice', files, verified, 'funding')['role'] == 'alice'
    pins = root/'source-pins.json'; save(pins, agreement['owners'])
    trusted = digest(agreement['owners'])
    wallet = root/'source'; native('testnet-wallet-init', wallet)
    with public_source.locked(wallet):
        refuses(lambda: guard.initialize_locked(wallet, pins, '00'*32), 'independently pinned fingerprint')
        if (wallet/guard.AUTHORITY).exists(): raise RuntimeError('wrong pin persisted')
        initialized = guard.initialize_locked(wallet, pins, trusted)
        assert guard.initialize_locked(wallet, pins, trusted) == initialized
        assert guard.check_locked(wallet, agreement)['source_wallet_and_owner_pins_bound']
        alternate = copy.deepcopy(agreement['owners'])
        alternate['alice'], alternate['bob'] = alternate['bob'], alternate['alice']
        alternate['alice']['role'], alternate['bob']['role'] = 'alice', 'bob'
        bad = root/'changed-pins.json'; save(bad, alternate)
        refuses(lambda: guard.initialize_locked(wallet, bad, digest(alternate)), 'immutable source authority')
        changed = copy.deepcopy(agreement); changed['owners'] = alternate
        refuses(lambda: guard.check_locked(wallet, changed), 'approved owner pins')
        # This marker tests preservation, not a fabricated claim of funded inputs.
        marker = {'test_only': True, 'no_funded_inputs': True, 'must_not_delete': True}
        save(wallet/'source-reservation.json', marker)
        cancelled = guard.cancel_locked(wallet)
        assert guard.cancel_locked(wallet) == cancelled
        assert read(wallet/'source-reservation.json') == marker
        refuses(lambda: guard.check_locked(wallet, agreement), 'permanently cancelled')
        refuses(lambda: guard.initialize_locked(wallet, pins, trusted), 'permanently cancelled')
        # The production funding-preflight path refuses before any reservation,
        # bundle or network read, even when restarted with missing input paths.
        refuses(lambda: public_source.prepare(wallet, root/'absent', agreement, verified, root/'never-created'),
            'permanently cancelled')
    if (root/'never-created').exists(): raise RuntimeError('cancelled source advanced preparation')
    process = subprocess.run([sys.executable, str(ROOT/'scripts/public_source_guard.py'), 'cancel', str(wallet)],
        capture_output=True, text=True, timeout=20)
    if process.returncode or json.loads(process.stdout) != cancelled: raise RuntimeError('cancellation restart differs')
    other = root/'other-source'; native('testnet-wallet-init', other)
    shutil.copyfile(wallet/guard.AUTHORITY, other/guard.AUTHORITY); os.chmod(other/guard.AUTHORITY, 0o600)
    with public_source.locked(other):
        refuses(lambda: guard.check_locked(other, agreement), 'source wallet or approved owner pins')
    possible = root/'possible-release'; native('testnet-wallet-init', possible)
    with public_source.locked(possible):
        guard.initialize_locked(possible, pins, trusted)
        save(possible/guard.RELEASE, {}) # Explicit partial-marker fixture; no signature/raw tx exists.
        refuses(lambda: guard.cancel_locked(possible), 'cancellation requires reconciliation')
        refuses(lambda: guard.check_locked(possible, agreement), 'reconcile outgoing state instead')
        if (possible/guard.CANCELLED).exists(): raise RuntimeError('possible release was marked cancelled')
    refuses(lambda: public_preflight.preflight(*paths, 'funding', root/'no-rpc', 'https://invalid.invalid',
        source_wallet=wallet, owner=root/'alice'), 'synthetic inputs cannot enter public execution observations')
    if (root/'no-rpc').exists(): raise RuntimeError('synthetic public preflight advanced')
    return {'scope': 'real native offline consent verification and local filesystem guards; all source wallets unfunded',
        'both_callers_bound_with_original_roots_and_peer_denied': True, 'caller_keys_copied': False,
        'wrong_role_peer_pin_and_saved_consent_refused': True, 'owner_lock_excludes_second_process': True,
        'actual_source_key_identity_and_auxiliary_bound': True, 'wrong_pair_fingerprint_and_pin_change_refused': True,
        'authority_copied_to_different_source_keys_refused': True,
        'permanent_cancellation_survives_restart_and_blocks_production_preflight': True,
        'reservation_preserved_after_cancel': True, 'partial_release_marker_forbids_cancellation': True,
        'source_signing_and_outgoing_journal_implemented': False,
        'funded_public_preflight': False, 'new_proofs': 0, 'rpc_calls': 0, 'broadcast': False}


if __name__ == '__main__':
    os.umask(0o077)
    print(json.dumps(check(*(Path(p).resolve() for p in sys.argv[1:3])), indent=2))
