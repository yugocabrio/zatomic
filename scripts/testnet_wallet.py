#!/usr/bin/env python3
"""Read-only public-testnet Ironwood wallet. No transaction/deployment command.

The chosen birthday excludes all earlier notes. Checkpoints and viewing/spending
material are private. The TLS provider is trusted for canonical blocks/nullifiers.
On reorg, stop with the old checkpoints intact; do not silently reset a balance.
"""
import argparse
import fcntl
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import uuid

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'target/release/shielded-swap-native'
GENESIS = '05a60a92d99d85997cce3b87616c089f6124d7342af37106edc76126334a2c38'
ACTIVATION = 4_465_026


def read(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        meta = os.fstat(fd)
        if not stat.S_ISREG(meta.st_mode) or meta.st_mode & 0o077 or meta.st_size > 50_000_000:
            raise RuntimeError('bounded private regular file required')
        with os.fdopen(fd, 'r', closefd=False) as stream:
            return json.load(stream)
    finally:
        os.close(fd)


def invoke(*args):
    result = subprocess.run(list(map(str, args)), cwd=ROOT, text=True, capture_output=True)
    if result.returncode:
        raise RuntimeError(result.stderr.strip())
    return json.loads(result.stdout)


def head(directory, value):
    # Caller holds the wallet lock. Crash leaves the old or the new complete head;
    # all actual note/witness checkpoints are immutable and retained.
    target = directory / 'head.json'
    if target.exists() or target.is_symlink():
        read(target)
    fd, name = tempfile.mkstemp(prefix='.head-', dir=directory)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(value, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, target)
        parent = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def checkpoint(directory):
    info = read(directory / 'head.json')
    if info['genesis'] != GENESIS or type(info['birthday']) is not int or not ACTIVATION <= info['birthday'] <= 0xffffffff:
        raise RuntimeError('wallet head network/birthday mismatch')
    name = info['checkpoint']
    if name is None:
        return info, None
    if not re.fullmatch(r'compact-[0-9]+-[0-9]+-[0-9a-f]{64}\.json', name):
        raise RuntimeError('invalid checkpoint filename')
    value = read(directory / name)
    if value['genesis'] != GENESIS or value['birthday_height'] != info['birthday']:
        raise RuntimeError('checkpoint lineage mismatch')
    return info, value


def sync(directory, batches):
    results = []
    for _ in range(batches):
        info, previous = checkpoint(directory)
        height = previous['height'] if previous else info['birthday']
        capture = directory / ('capture-' + uuid.uuid4().hex + '.json')
        args = ['node', ROOT / 'scripts/capture_testnet.mjs', height, 256, capture]
        if previous:
            args.append(previous['tip'])
        observation = invoke(*args)
        args = [NATIVE, 'compact-scan', directory, capture]
        if previous:
            args.append(directory / info['checkpoint'])
        scanned = invoke(*args)
        info['checkpoint'] = Path(scanned['file']).name
        info['observation'] = read(capture)['observation']
        head(directory, info)
        results.append(scanned)
        if scanned['height'] == observation['provider_tip']:
            break
    return {'broadcast': False, 'provider_trusted': True, 'batches': results,
        'caught_up_to_observed_tip': results[-1]['height'] == observation['provider_tip']}


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=['init', 'sync', 'status'])
    parser.add_argument('directory', type=Path)
    parser.add_argument('--birthday', type=int, help='exclusive trusted starting height, before any incoming payment')
    parser.add_argument('--batches', type=int, default=4, help='up to 32 batches of 256 blocks per invocation')
    args = parser.parse_args()
    if args.directory.is_symlink():
        raise RuntimeError('wallet directory must not be a symlink')
    directory = args.directory.absolute()
    if args.operation == 'init':
        if args.birthday is None or not ACTIVATION <= args.birthday <= 0xffffffff:
            raise RuntimeError('an explicit post-NU7 birthday is required')
        directory.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        invoke(NATIVE, 'testnet-wallet-init', directory)
        head(directory, {'genesis': GENESIS, 'birthday': args.birthday, 'checkpoint': None})
        return {'initialized': True, 'birthday': args.birthday, 'broadcast': False, 'funded': False}
    if args.birthday is not None or not 1 <= args.batches <= 32:
        raise RuntimeError('birthday is immutable; batch count must be 1..32')
    meta = directory.stat()
    if not stat.S_ISDIR(meta.st_mode) or meta.st_mode & 0o077:
        raise RuntimeError('private wallet directory required')
    if read(directory / 'network.json')['genesis'] != GENESIS:
        raise RuntimeError('testnet wallet required')
    lock = os.open(directory / 'sync.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if args.operation == 'sync':
            return sync(directory, args.batches)
        info, previous = checkpoint(directory)
        return {'birthday': info['birthday'], 'height': previous['height'] if previous else None,
            'tip': previous['tip'] if previous else None,
            'unspent_notes': len(previous['notes']) if previous else 0,
            'observation': info.get('observation'), 'broadcast': False}
    finally:
        os.close(lock)


if __name__ == '__main__':
    try:
        print(json.dumps(main(), indent=2))
    except (RuntimeError, OSError, ValueError, KeyError) as error:
        raise SystemExit(str(error)) from None
