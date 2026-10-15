"""Bind actual native consent verification to a caller's saved local decisions.

This module never reads identity/spending keys or an adaptor opening. It does
not turn signed consent or a local authority record into a release token.
"""
from contextlib import contextmanager
import argparse
import fcntl
import json
import os
from pathlib import Path
import stat
import subprocess
from public_agreement import validate_policy
from public_evm_observation import digest
from regtest_wallet import native
from testnet_wallet import read
from testnet_owner import identity
import timestamp_policy


@contextmanager
def owner_locked(owner):
    meta = owner.lstat()
    if not stat.S_ISDIR(meta.st_mode) or meta.st_mode & 0o077:
        raise RuntimeError('private caller owner directory required')
    fd = os.open(owner/'operator.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield fd
    finally:
        os.close(fd)


def verified_files(bundle, proposal, consents):
    """Actual full native proof/receipt/conditional-signature validation.

    Offline synthetic verification is useful; the live caller MUST reject that
    provenance before constructing an RPC client or granting execution.
    """
    validate_policy()
    files = {'bundle': read(bundle), 'proposal': read(proposal), 'consents': read(consents)}
    checked = native('testnet-check-consents', bundle, proposal, consents)
    agreement = files['proposal']['agreement']
    if (checked['agreement_digest'] != digest(agreement)
            or checked['bundle_digest'] != digest(files['bundle'])
            or agreement['bundle_digest'] != checked['bundle_digest']
            or checked['both_owner_signatures_verified'] is not True
            or any(read(path) != files[name] for name, path in
                (('bundle', bundle), ('proposal', proposal), ('consents', consents)))):
        raise RuntimeError('conditional agreement files changed during validation')
    timestamp_policy.require_agreement_binding(agreement['execution_plan'], agreement)
    return files, checked


def bind_owner(owner, files, checked, phase):
    """Caller holds operator.lock. These files have just passed verified_files.

    Equality is required with this caller's retained state, not any valid pair's
    signatures. The final sender must repeat it under the same lock.
    """
    expected = {'funding': 'alice', 'eth_lock': 'bob', 'first_reveal': 'alice',
        'native_claim': 'bob', 'native_refund': 'alice'}[phase]
    own = identity(read(owner/'identity.json'), expected)
    peer = 'bob' if expected == 'alice' else 'alice'
    trusted = identity(read(owner/'trusted-peer.json')['identity'], peer)
    agreement = files['proposal']['agreement']
    if agreement['owners'] != {expected: own, peer: trusted}:
        raise RuntimeError('agreement owners differ from caller identity and trusted peer')
    if (read(owner/'public-native-recovery.json') != files['bundle']
            or read(owner/'reviewed-graph-packet.json') != files['bundle']['review']
            or read(owner/'authenticated-destinations.json') != files['bundle']['review']['destinations']
            or read(owner/'accepted-trade.json') != files['bundle']['review']['destinations']['trade']
            or read(owner/'public-native-recovery-receipt.json') != files['proposal']['receipts'][expected]
            or read(owner/'public-consent-proposal.json') != files['proposal']
            or read(owner/'public-conditional-consent.json') != files['consents'][expected]
            or checked['agreement_digest'] != digest(agreement)):
        raise RuntimeError('caller did not save this exact graph, recovery and conditional consent')
    return {'format': 'latch-public-caller-binding-v1', 'role': expected,
        'agreement_digest': checked['agreement_digest'], 'bundle_digest': checked['bundle_digest'],
        'local_identity_and_peer_pins_bound': True, 'exact_local_acceptance_bound': True,
        'signing_keys_read': False, 'funding_authorized': False, 'broadcast': False}


def main():
    os.umask(0o077)
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('owner', 'bundle', 'proposal', 'consents'): p.add_argument(name, type=Path)
    p.add_argument('phase', choices=('funding', 'eth_lock', 'first_reveal'))
    a = p.parse_args()
    with owner_locked(a.owner):
        files, checked = verified_files(a.bundle, a.proposal, a.consents)
        result = bind_owner(a.owner, files, checked, a.phase)
        return dict(result, synthetic_inputs=checked['synthetic_inputs'], live_chain_checked=False)


if __name__ == '__main__':
    try: print(json.dumps(main(), indent=2))
    except (RuntimeError, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        raise SystemExit('Caller binding refused; no signing, disclosure or transaction release.') from None
