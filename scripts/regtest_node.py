#!/usr/bin/env python3
"""Own isolated Zebra NU7 regtest. Never attaches to public or other task nodes."""
import argparse
import hashlib
import json
import os
import platform
import re
from pathlib import Path
import subprocess
import tarfile
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
NODE_DIR = ROOT / '.local/zebra-nu7'
DEPS = ROOT / '.deps/zebra-7.0.0-rc.0'
NAMESPACE = os.environ.get('LATCH_REGTEST_NAMESPACE', '')
PORT_TEXT = os.environ.get('LATCH_REGTEST_PORT', '')
if NAMESPACE:
    if not re.fullmatch(r'[a-z][a-z0-9-]{0,31}', NAMESPACE):
        raise RuntimeError('invalid isolated node namespace')
    if not PORT_TEXT.isascii() or not PORT_TEXT.isdecimal() or not 1024 <= int(PORT_TEXT) <= 65535:
        raise RuntimeError('namespaced node requires an explicit unprivileged loopback port')
    if int(PORT_TEXT) == 30342:
        raise RuntimeError('namespaced node cannot use the default node port')
elif PORT_TEXT:
    raise RuntimeError('custom node port requires a namespace')
PORT = int(PORT_TEXT) if NAMESPACE else 30342
# A hosted demo runs zebrad as its own service user instead of a container, so
# the owner apps need no Docker access. The RPC checks below still apply.
EXTERNAL = os.environ.get('LATCH_NODE') == 'external'
if EXTERNAL and NAMESPACE:
    raise RuntimeError('an external node has no namespace')
NAME = 'shielded-swap-zebra-nu7' + (('-' + NAMESPACE) if NAMESPACE else '')
LABEL = 'shielded-swap.scope'
OWNER = 'isolated-regtest-v1'
RPC = f'http://127.0.0.1:{PORT}'
GENESIS = '029f11d80ef9765602235e1bc9727e3eb6ba20839319f761fee920d63401e327'
BRANCH = '77190ad9'
IMAGE = 'ubuntu@sha256:534baea6a22c03a63003dbc8dbe78fe34bc0d7e595d9a9dc9834884ff530eb55'
# Official v7.0.0-rc.0 builds, checked against the release's SHA256SUMS. The
# local node runs the arm64 build in Docker; a hosted node runs its host's build.
ARCHIVES = {
    'aarch64': ('zebrad-7.0.0-rc.0-aarch64-unknown-linux-gnu.tar.gz',
                '59adbb7d3e19c0fb7370eeca628787973ee347e421700a36e3b8dbde5c0b86c4'),
    'x86_64': ('zebrad-7.0.0-rc.0-x86_64-unknown-linux-gnu.tar.gz',
               '7486dcd91c18d9b8778c632a0cd8e5639d6313ae4d88bc8fd09b1bb7eb12c1f2'),
}
MACHINE = {'arm64': 'aarch64', 'amd64': 'x86_64'}.get(platform.machine().lower(), platform.machine().lower())
if EXTERNAL and MACHINE not in ARCHIVES:
    raise RuntimeError('no pinned zebrad build for this CPU; use an arm64 or x86_64 host')
ARCHIVE, DIGEST = ARCHIVES[MACHINE if EXTERNAL else 'aarch64']
URL = 'https://github.com/ZcashFoundation/zebra/releases/download/v7.0.0-rc.0/' + ARCHIVE
CONFIG = '''[network]
network = "Regtest"
listen_addr = "127.0.0.1:18233"

[network.testnet_parameters.activation_heights]
Overwinter = 1
Sapling = 1
Blossom = 1
Heartwood = 1
Canopy = 1
NU5 = 2
NU6 = 2
"NU6.1" = 2
"NU6.2" = 2
"NU6.3" = 2
NU7 = 2

[rpc]
listen_addr = "0.0.0.0:19332"
enable_cookie_auth = false

[state]
cache_dir = "/state"

[mining]
# Disposable test address from Zebra docs; no secret or real funds.
miner_address = "t27eWDgjFYJGVXmzrXeVjnb5J3uXDM9xH9v"
'''


class RpcError(RuntimeError):
    def __init__(self, method, error):
        self.method, self.code = method, error.get('code')
        super().__init__(f'{method}: {error}')


def rpc(method, params=None, timeout=30):
    request = urllib.request.Request(RPC, json.dumps({'jsonrpc': '2.0', 'id': 1,
        'method': method, 'params': params or []}).encode(),
        {'Content-Type': 'application/json'})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        value = json.load(response)
    if value.get('error'):
        raise RpcError(method, value['error'])
    return value['result']


def hosted_config(state):
    """The same node for a service-managed zebrad: RPC on loopback directly."""
    text = CONFIG.replace('listen_addr = "0.0.0.0:19332"', f'listen_addr = "127.0.0.1:{PORT}"')
    return text.replace('cache_dir = "/state"', f'cache_dir = {json.dumps(str(state))}')


def inspect():
    if EXTERNAL:
        raise RuntimeError('the external node is managed by its service, not by this checkout')
    validate_scope()
    p = subprocess.run(['docker', 'container', 'inspect', NAME], capture_output=True, text=True)
    if p.returncode:
        return None
    item = json.loads(p.stdout)[0]
    validate_container(item)
    return item


def validate_scope():
    marker = NODE_DIR / 'scope.json'
    expected = {'name': NAME, 'port': PORT}
    if marker.exists():
        if marker.is_symlink() or json.loads(marker.read_text()) != expected:
            raise RuntimeError('node scope ownership changed; preserve the original environment')
    elif NAMESPACE and NODE_DIR.exists():
        raise RuntimeError('custom node scope requires a fresh checkout state directory')


def validate_container(item):
    if item['Config'].get('Labels', {}).get(LABEL) != OWNER:
        raise RuntimeError('container ownership mismatch')
    if item.get('HostConfig', {}).get('PortBindings') != {
            '19332/tcp': [{'HostIp': '127.0.0.1', 'HostPort': str(PORT)}]}:
        raise RuntimeError('container loopback port ownership mismatch')
    # Labels/name identify this project, but not this checkout. Reusing an old
    # container from another checkout would mine/stop its retained wallet chain.
    expected = {'/zebra': (DEPS.resolve(), False),
        '/config/zebra.toml': ((NODE_DIR/'zebra.toml').resolve(), False),
        '/state': ((NODE_DIR/'state').resolve(), True)}
    mounts = item.get('Mounts', [])
    if len(mounts) != len(expected): raise RuntimeError('container mount ownership mismatch')
    seen = set()
    for mount in mounts:
        destination = mount.get('Destination')
        if (destination not in expected or destination in seen or mount.get('Type') != 'bind'
                or not isinstance(mount.get('Source'), str)
                or (Path(mount['Source']).resolve(), mount.get('RW')) != expected[destination]):
            raise RuntimeError('container belongs to another checkout or has changed mounts; preserve its state')
        seen.add(destination)


def status():
    if not EXTERNAL and inspect() is None: raise RuntimeError('owned checkout container required')
    info = rpc('getblockchaininfo')
    if rpc('getblockhash', [0]) != GENESIS or info['chain'] not in ('test', 'regtest'):
        raise RuntimeError('wrong network; refuse any transaction or mining')
    if info['upgrades'].get(BRANCH, {}).get('activationheight') != 2:
        raise RuntimeError('wrong NU7 activation')
    if info['blocks'] >= 2 and info['consensus']['chaintip'] != BRANCH:
        raise RuntimeError('wrong branch')
    return {'scope': 'isolated NU7 regtest', 'blocks': info['blocks'],
            'tip': info['bestblockhash'], 'genesis': GENESIS, 'branch': BRANCH,
            'rpc': RPC, 'container': None if EXTERNAL else NAME}


def prepare():
    DEPS.mkdir(parents=True, exist_ok=True)
    archive = DEPS / ARCHIVE
    if not archive.exists():
        # Atomic replacement only after the official pinned archive verifies.
        temporary = DEPS / (ARCHIVE + '.download')
        urllib.request.urlretrieve(URL, temporary)
        if hashlib.sha256(temporary.read_bytes()).hexdigest() != DIGEST:
            raise RuntimeError('download checksum mismatch')
        temporary.rename(archive)
    if hashlib.sha256(archive.read_bytes()).hexdigest() != DIGEST:
        raise RuntimeError('archive checksum mismatch')
    with tarfile.open(archive) as source:
        member = source.extractfile('zebrad')
        if member is None:
            raise RuntimeError('missing executable')
        data = member.read()
        for name in ('LICENSE-APACHE', 'LICENSE-MIT'):
            license_file = source.extractfile(name)
            if license_file is None:
                raise RuntimeError('official binary license missing')
            license_bytes = license_file.read()
            destination = DEPS / name
            if destination.exists():
                if destination.read_bytes() != license_bytes:
                    raise RuntimeError('retained license differs from pinned archive')
            else:
                with destination.open('xb') as retained:
                    retained.write(license_bytes)
    binary = DEPS / 'zebrad'
    if not binary.exists():
        with binary.open('xb') as f:
            f.write(data)
        binary.chmod(0o755)
    if hashlib.sha256(binary.read_bytes()).digest() != hashlib.sha256(data).digest():
        raise RuntimeError('binary differs from archive')


def start():
    os.umask(0o077)
    inspect() # Refuse a different checkout before creating/downloading anything.
    prepare()
    NODE_DIR.mkdir(parents=True, mode=0o700, exist_ok=True)
    if NODE_DIR.is_symlink() or NODE_DIR.stat().st_mode & 0o077:
        raise RuntimeError('private owned state directory required')
    marker = NODE_DIR / 'scope.json'
    if not marker.exists():
        with marker.open('x') as f:
            json.dump({'name': NAME, 'port': PORT}, f)
            f.flush()
            os.fsync(f.fileno())
    config = NODE_DIR / 'zebra.toml'
    if config.exists() and config.read_text() != CONFIG:
        raise RuntimeError('preserve existing configuration; unexpected difference')
    if not config.exists():
        with config.open('x') as f:
            f.write(CONFIG)
    state = NODE_DIR / 'state'
    state.mkdir(mode=0o700, exist_ok=True)
    if state.is_symlink():
        raise RuntimeError('state symlink refused')
    old = inspect()
    if old is None:
        subprocess.run(['docker', 'run', '--detach', '--name', NAME,
            '--label', f'{LABEL}={OWNER}', '--platform', 'linux/arm64',
            '--cpus', '2', '--memory', '2g', '--memory-swap', '2g', '--pids-limit', '256',
            '--publish', f'127.0.0.1:{PORT}:19332', '--env', 'RAYON_NUM_THREADS=2',
            '--env', 'TOKIO_WORKER_THREADS=2',
            '--mount', f'type=bind,source={DEPS},target=/zebra,readonly',
            '--mount', f'type=bind,source={config},target=/config/zebra.toml,readonly',
            '--mount', f'type=bind,source={state},target=/state', IMAGE,
            '/zebra/zebrad', '-c', '/config/zebra.toml', '--filters', 'warn', 'start'],
            check=True, stdout=subprocess.DEVNULL)
    elif not old['State']['Running']:
        subprocess.run(['docker', 'start', NAME], check=True, stdout=subprocess.DEVNULL)
    for _ in range(80):
        try:
            return status()
        except (OSError, RuntimeError):
            current = inspect()
            if current and not current['State']['Running']:
                raise RuntimeError('owned Zebra exited; inspect retained container log')
            time.sleep(.5)
    raise RuntimeError('Zebra startup timed out; preserved state')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['start', 'status', 'stop', 'mine', 'hosted-config'])
    parser.add_argument('blocks', type=int, nargs='?', default=1)
    args = parser.parse_args()
    if args.command == 'hosted-config':
        print(hosted_config(Path('/var/lib/latch-zebra/state')), end='')
        raise SystemExit(0)
    if args.command == 'start':
        value = start()
    elif args.command == 'stop':
        if inspect():
            subprocess.run(['docker', 'stop', NAME], check=True, stdout=subprocess.DEVNULL)
        value = {'stopped_owned_container': True, 'data_preserved': True}
    elif args.command == 'mine':
        status()
        if not 1 <= args.blocks <= 200:
            raise RuntimeError('block count outside local bound')
        rpc('generate', [args.blocks], timeout=300)
        value = status()
    else:
        value = status()
    print(json.dumps(value, indent=2))
