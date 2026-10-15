"""Test-only relocation: only one owner's directory stays at a usable path.

The peer, source wallet and coordinator files are moved out together; the owner's
ETH signing key is also outside the CLI's directory. This is not an OS sandbox.
A durable outside marker reconciles interruption at every rename boundary.
"""
import contextlib
import peer_workspace
from regtest_wallet import save


def paths(directory):
    return directory.with_name(directory.name + '-detached')


def restore(directory):
    control = paths(directory)
    marker = control / 'inflight.json'
    if not marker.exists():
        return
    entry = peer_workspace.read(marker)
    if entry['version'] != 1 or entry['fixture'] != str(directory) or entry['role'] not in ('alice', 'bob'):
        raise RuntimeError('detached owner marker mismatch')
    offline = control / 'coordinator'
    if directory.exists() == offline.exists():
        raise RuntimeError('ambiguous detached coordinator location')
    located = directory if directory.exists() else offline
    source, target = located / 'owners' / entry['role'], control / 'owner'
    if source.exists() == target.exists():
        raise RuntimeError('ambiguous detached owner location')
    owner = source if source.exists() else target
    if peer_workspace.identity(located, owner, entry['role']) != entry['binding']:
        raise RuntimeError('detached owner binding changed')
    key = owner / 'ethereum'
    offline_key = control / 'eth-key-offline'
    if key.exists() == offline_key.exists():
        raise RuntimeError('ambiguous detached ETH key location')
    if offline_key.exists():
        offline_key.rename(key)
        peer_workspace.sync(owner)
        peer_workspace.sync(control)
    if located == offline:
        offline.rename(directory)
        peer_workspace.sync(directory.parent)
        peer_workspace.sync(control)
    if target.exists():
        target.rename(directory / 'owners' / entry['role'])
        peer_workspace.sync(directory / 'owners')
        peer_workspace.sync(control)
    marker.unlink()
    peer_workspace.sync(control)


@contextlib.contextmanager
def isolated(directory, role):
    restore(directory)
    control = paths(directory)
    control.mkdir(mode=0o700, exist_ok=True)
    if any((control / name).exists() for name in ('owner', 'coordinator', 'eth-key-offline')):
        raise RuntimeError('unrecorded detached workspace present')
    source, target = directory / 'owners' / role, control / 'owner'
    save(control / 'inflight.json', {'version': 1, 'fixture': str(directory), 'role': role,
        'binding': peer_workspace.identity(directory, source, role)})
    try:
        source.rename(target)
        peer_workspace.sync(directory / 'owners')
        peer_workspace.sync(control)
        directory.rename(control / 'coordinator')
        peer_workspace.sync(directory.parent)
        peer_workspace.sync(control)
        (target / 'ethereum').rename(control / 'eth-key-offline')
        peer_workspace.sync(target)
        peer_workspace.sync(control)
        yield target
    finally:
        restore(directory)
