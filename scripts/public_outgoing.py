#!/usr/bin/env python3
"""Durably stage private native recovery bytes; no public send RPC exists here.

A staged transaction is NOT permission to broadcast or proof of non-exposure.
Every replay verifies the real bytes against the locally accepted native bundle
and both conditional consents. Old proof versions and interrupted intents remain.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import public_authority as authority
from public_evm_observation import digest
from regtest_wallet import native
from source_inputs import publish, origin_bytes
from testnet_wallet import GENESIS, read

JOURNAL = 'public-native-outgoing'
LIMIT = 32


def private_directory(path):
    if not path.exists() and not path.is_symlink():
        path.mkdir(mode=0o700)
        parent = os.open(path.parent, os.O_RDONLY)
        try: os.fsync(parent)
        finally: os.close(parent)
    meta = path.lstat()
    if not stat.S_ISDIR(meta.st_mode) or meta.st_mode & 0o077:
        raise RuntimeError('private native outgoing directory required')


def immutable(path, value):
    if path.exists() or path.is_symlink():
        if read(path) != value: raise RuntimeError('outgoing immutable context changed')
    else: publish(path, value)


def raw_bytes(path):
    # Same strict private bounded canonical hex reader as the source origin.
    return bytes.fromhex(origin_bytes(path))


def publish_raw(path, raw):
    if path.exists() or path.is_symlink():
        if raw_bytes(path) != raw: raise RuntimeError('outgoing raw bytes changed')
        return
    fd, temporary = tempfile.mkstemp(prefix='.native-pending-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            stream.write(raw.hex()); stream.flush(); os.fsync(stream.fileno())
        os.link(temporary, path)
        parent = os.open(path.parent, os.O_RDONLY)
        try: os.fsync(parent)
        finally: os.close(parent)
    finally: os.unlink(temporary)


def context(owner, bundle, proposal, consents):
    files, verified = authority.verified_files(bundle, proposal, consents)
    role = read(owner/'identity.json')['role']
    mode = {'alice': 'refund', 'bob': 'claim'}[role]
    caller = authority.bind_owner(owner, files, verified, 'native_'+mode)
    receipt = files['proposal']['receipts'][role]
    binding = {'format': 'latch-public-native-outgoing-v1', 'role': role, 'mode': mode,
        'genesis': GENESIS, 'agreement_digest': verified['agreement_digest'],
        'bundle_digest': verified['bundle_digest'], 'owner_receipt_digest': digest(receipt),
        'synthetic_inputs': verified['synthetic_inputs'], 'send_authorized': False}
    return files, receipt, caller, binding


def check_exit(portable, transaction, binding):
    raw = raw_bytes(transaction)
    checked = native('testnet-inspect-exit', portable, transaction)
    if (checked['bytes_sha256'] != hashlib.sha256(raw).hexdigest()
            or any(checked[name] != binding[name] for name in
                ('mode', 'role', 'genesis', 'bundle_digest', 'synthetic_inputs'))
            or checked['proof_and_signatures_verified'] is not True
            or checked['agreed_effects_preserved'] is not True
            or checked['send_authorized'] is not False):
        raise RuntimeError('outgoing bytes or accepted bundle changed during verification')
    return checked, raw


def versions(directory, binding):
    """Inspect every retained version, never trust a saved success boolean."""
    folder = directory/'versions'
    if not folder.exists() and not folder.is_symlink(): return []
    private_directory(folder)
    members = list(folder.iterdir())
    intents = sorted(p for p in members if re.fullmatch('[0-9a-f]{64}\\.json', p.name))
    if len(intents) > LIMIT: raise RuntimeError('native outgoing history bound exceeded; preserve all versions')
    allowed = {p.name for p in intents} | {p.stem+'.hex' for p in intents}
    if any(p.name not in allowed and not p.name.startswith(('.source-pending-', '.native-pending-')) for p in members):
        raise RuntimeError('unmatched outgoing artifact; preserve for manual reconciliation')
    result = []
    for path in intents:
        saved = read(path)
        if (set(saved) != {'format', 'binding_digest', 'checked'}
                or saved['format'] != 'latch-public-native-version-v1'
                or saved['binding_digest'] != digest(binding)
                or saved['checked']['bytes_sha256'] != path.stem):
            raise RuntimeError('native outgoing intent changed')
        raw_path = path.with_suffix('.hex')
        if raw_path.exists() or raw_path.is_symlink():
            checked, _ = check_exit(directory, raw_path, binding)
            if checked != saved['checked']: raise RuntimeError('saved outgoing result differs from actual raw transaction')
            status = 'private-bytes-reverified'
        else:
            status = 'interrupted-before-raw-persistence'
        result.append({'bytes_sha256': path.stem, 'status': status,
            'checked': checked if status == 'private-bytes-reverified' else None})
    return result


def verified_journal_locked(owner):
    directory = owner/JOURNAL
    if not directory.exists() and not directory.is_symlink():
        raise RuntimeError('no native outgoing journal')
    private_directory(directory)
    files, receipt, caller, binding = context(owner, directory/'native-recovery.json',
        directory/'proposal.json', directory/'consents.json')
    if read(directory/'binding.json') != binding or read(directory/'owner-receipt.json') != receipt:
        raise RuntimeError('outgoing context differs from local acceptance')
    retained = versions(directory, binding)
    return {'directory': directory, 'files': files, 'caller': caller, 'binding': binding, 'versions': retained}


def inspect_locked(owner):
    journal = verified_journal_locked(owner)
    binding = journal['binding']
    retained = [{k: v[k] for k in ('bytes_sha256', 'status')} for v in journal['versions']]
    return {'format': 'latch-public-native-outgoing-status-v1', 'role': binding['role'],
        'mode': binding['mode'], 'agreement_digest': binding['agreement_digest'],
        'synthetic_inputs': binding['synthetic_inputs'], 'versions': retained,
        'all_raw_versions_present': bool(retained) and all(v['status'] == 'private-bytes-reverified' for v in retained),
        'broadcast_performed': False, 'network_exposure_excluded': False,
        'send_authorized': False, 'live_chain_checked': False,
        'scope': 'private prepared bytes only; fresh cross-chain reconciliation and a send intent are still required'}


def stage(owner, portable, transaction, consents):
    with authority.owner_locked(owner):
        files, receipt, caller, binding = context(owner, owner/'public-native-recovery.json',
            owner/'public-consent-proposal.json', consents)
        if read(portable/'native-recovery.json') != files['bundle'] or read(portable/'owner-receipt.json') != receipt:
            raise RuntimeError('outgoing portable receipt/bundle differs from local owner')
        checked, raw = check_exit(portable, transaction, binding)
        directory = owner/JOURNAL
        private_directory(directory)
        # Complete immutable decision/context reaches stable storage before any
        # signed raw bytes are copied here. Retrying can finish this exact context.
        immutable(directory/'binding.json', binding)
        for name, value in (('native-recovery.json', files['bundle']), ('owner-receipt.json', receipt),
                ('proposal.json', files['proposal']), ('consents.json', files['consents'])):
            immutable(directory/name, value)
        previous = versions(directory, binding)
        fingerprint = checked['bytes_sha256']
        if len(previous) == LIMIT and fingerprint not in {v['bytes_sha256'] for v in previous}:
            raise RuntimeError('native outgoing history full; preserve all versions')
        if authority.bind_owner(owner, files, {'agreement_digest': binding['agreement_digest'],
                'bundle_digest': binding['bundle_digest']}, 'native_'+binding['mode']) != caller:
            raise RuntimeError('owner acceptance changed before outgoing persistence')
        folder = directory/'versions'; private_directory(folder)
        immutable(folder/(fingerprint+'.json'), {'format': 'latch-public-native-version-v1',
            'binding_digest': digest(binding), 'checked': checked})
        # A crash at this boundary leaves a durable version intent, no erasure
        # or false cancellation. Only the exact hash can complete that version.
        publish_raw(folder/(fingerprint+'.hex'), raw)
        return inspect_locked(owner)


def main():
    os.umask(0o077)
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest='operation', required=True)
    s = sub.add_parser('stage')
    for name in ('owner', 'portable', 'transaction', 'consents'): s.add_argument(name, type=Path)
    i = sub.add_parser('inspect'); i.add_argument('owner', type=Path)
    a = p.parse_args()
    if a.operation == 'stage': return stage(a.owner, a.portable, a.transaction, a.consents)
    with authority.owner_locked(a.owner): return inspect_locked(a.owner)


if __name__ == '__main__':
    try: print(json.dumps(main(), indent=2))
    except (RuntimeError, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        raise SystemExit('Native outgoing preparation refused; retain all private state, nothing sent.') from None
