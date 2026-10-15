"""Journal the local fixture's peer-directory move before making it unavailable.

This demonstrates recovery without reading the peer during native settlement.
It is not an OS sandbox or a remotely hosted owner. Caller holds the chain lease.
"""
import contextlib
import hashlib
import json
import os
from pathlib import Path
import secrets
from regtest_wallet import save


def read(path):
    if path.is_symlink() or not path.is_file():
        raise RuntimeError('peer journal requires regular local files')
    return json.loads(path.read_text())


def sync(directory):
    fd = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def identity(directory, owner, role):
    if owner.is_symlink() or not owner.is_dir():
        raise RuntimeError('peer workspace must be a real directory')
    agreement, flow = read(directory/'agreement.json'), read(directory/'owner-flow.json')
    digest = hashlib.sha256(json.dumps(agreement,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    ident = read(owner/'identity.json')
    ready = read(owner/'recovery/recovery-ready.json')
    if (flow['agreement_digest'] != digest or ident['role'] != role
        or ident['address'] != flow['addresses'][role]
        or read(owner/'eth-agreement.json') != agreement
        or read(owner/'eth-acceptance.json')['agreement_digest'] != digest
        or ready['funding_txid'] != agreement['native']['funding_txid']
        or ready['mode'] != ('refund' if role == 'alice' else 'claim')):
        raise RuntimeError('peer workspace identity or agreement changed')
    return {'identity':ident,'agreement_digest':digest,'recovery':ready}


def reconcile(directory):
    owners = directory/'owners'
    journal = directory/'peer-offline.json'
    if not journal.exists():
        if any((owners/(role+'-offline')).exists() for role in ('alice','bob')):
            raise RuntimeError('offline peer has no durable move journal')
        return None
    entry = read(journal)
    role = entry.get('role')
    if entry.get('version') != 1 or role not in ('alice','bob'):
        raise RuntimeError('peer move journal domain invalid')
    source, offline = owners/role, owners/(role+'-offline')
    if source.exists() == offline.exists():
        raise RuntimeError('ambiguous peer move: require exactly one workspace')
    current = offline if offline.exists() else source
    if identity(directory,current,role) != entry['binding']:
        raise RuntimeError('peer move binding changed')
    moved = current == offline
    if moved:
        offline.rename(source)
        sync(owners)
    journal.unlink()
    sync(directory)
    return {'role':role,'directory_restored':moved}


@contextlib.contextmanager
def unavailable(owners, role):
    directory = owners.parent
    if role not in ('alice','bob') or (directory/'peer-offline.json').exists():
        raise RuntimeError('peer move already active or invalid role')
    source, offline = owners/role, owners/(role+'-offline')
    if offline.exists():
        raise RuntimeError('offline peer already exists; reconcile first')
    entry = {'version':1,'role':role,'id':secrets.token_hex(16),
        'binding':identity(directory,source,role)}
    save(directory/'peer-offline.json',entry)
    source.rename(offline)
    sync(owners)
    try:
        yield
    finally:
        reconcile(directory)
