#!/usr/bin/env python3
"""Two-party local demo: a stand-in network, an untrusted relay and two owner apps.

Alice and Bob each get their own app, holding only their own private roots; an
OS sandbox denies each app the other's roots. This process plays the parts that
are not a participant: the public chains (one long-running Anvil with a
pre-deployed PointEscrow; isolated Zebra regtest blocks mined whenever a
transaction is pending), a relay that sees identity manifests in the clear and
every other message only as an envelope sealed to the recipient, and clearly
labelled local controls that stand in for time passing. It never holds or reads
a participant key and cannot open a sealed message.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import subprocess
import sys
import threading
import time
from http.server import ThreadingHTTPServer
import run_native_evm_gate as evm
import evm_wallet
from regtest_node import rpc as zrpc, status
from two_party_http import ROOT, Handler, atomic

PORTS = {'network': 8790, 'alice': 8791, 'bob': 8792}
TOPICS = ('manifest', 'sealed')
HEX = set('0123456789abcdef')
PRIVATE = {'alice': ('alice', 'alice-source', 'alice-app'), 'bob': ('bob', 'bob-app')}
CHILDREN = ROOT / '.local/two-party-children.json'


def reap_orphans():
    """A network stopped with SIGKILL cannot stop its Anvil or apps, which run
    in their own sessions. Called under the chain-driver lock, so any recorded
    survivor is an orphan of an earlier network, never a live one."""
    if not CHILDREN.exists():
        return
    recorded = set(json.loads(CHILDREN.read_text()))
    table = subprocess.run(['ps', '-A', '-o', 'pid=,pgid=,command='], capture_output=True, text=True).stdout
    for line in table.splitlines():
        pid, group, command = line.split(None, 2)
        # Anvil itself, or anything left in an app's own process group (the
        # app, its signer service or an operator command).
        if (int(pid) in recorded and 'anvil' in command and '/network/anvil-state.json' in command) or (
                int(group) in recorded and any(s in command for s in ('party_app.py', 'signer_transport.py', 'latch_operator.py'))):
            os.kill(int(pid), signal.SIGTERM)  # Anvil writes its --state file on exit.
            for _ in range(50):
                if subprocess.run(['ps', '-p', pid], capture_output=True).returncode:
                    break
                time.sleep(.1)
            else:
                os.kill(int(pid), signal.SIGKILL)
    CHILDREN.unlink()


def sealed(envelope, role):
    """Shape check only: the relay can neither open nor verify an envelope."""
    hexed = lambda key, low, high: isinstance(envelope.get(key), str) and low <= len(envelope[key]) <= high \
        and len(envelope[key]) % 2 == 0 and set(envelope[key]) <= HEX
    return (set(envelope) == {'v', 'from', 'to', 'epk', 'nonce', 'ct'} and envelope['v'] == 1
        and envelope['from'] == role and envelope['to'] == ('bob' if role == 'alice' else 'alice')
        and hexed('epk', 66, 66) and hexed('nonce', 24, 24) and hexed('ct', 34, 400_000))


class Network:
    def __init__(self, root):
        self.root = root
        self.lock = threading.RLock()
        self.app_tokens = {r: secrets.token_urlsafe(32) for r in PRIVATE}
        self.page_token = secrets.token_urlsafe(32)
        self.apps = {}
        self.events = []
        for name in ('network', 'relay'):
            (root / name).mkdir(mode=0o700, parents=True, exist_ok=True)

    def tokens(self):
        return {self.page_token, *self.app_tokens.values()}

    def note(self, text):
        self.events = (self.events + [{'at': int(time.time()), 'text': text}])[-40:]

    def record_children(self):
        pids = [self.anvil.pid] + [p.pid for p in self.apps.values() if p.poll() is None]
        atomic(CHILDREN, pids)

    # Public chains -------------------------------------------------------
    def start_chains(self):
        with socket.socket() as probe:
            if probe.connect_ex(('127.0.0.1', evm.PORT)) == 0:
                raise RuntimeError(f'port {evm.PORT} is already in use; stop the other local chain first')
        state = self.root / 'network/anvil-state.json'
        log = (self.root / 'network/anvil.log').open('a')
        self.anvil = subprocess.Popen(['anvil', '--host', '127.0.0.1', '--port', str(evm.PORT),
            '--chain-id', str(evm.CHAIN), '--silent', '--state', str(state), '--state-interval', '2'],
            stdout=log, stderr=log, cwd=ROOT, start_new_session=True)
        for _ in range(100):
            try:
                if int(evm.rpc('eth_chainId'), 16) == evm.CHAIN:
                    break
            except OSError:
                time.sleep(.1)
        else:
            raise RuntimeError('local Anvil did not start')
        escrow = self.root / 'network/escrow.json'
        artifact = json.loads((ROOT / '.local/forge-out/PointEscrow.sol/PointEscrow.json').read_text())
        if escrow.exists():
            deployed = json.loads(escrow.read_text())
            code = evm.rpc('eth_getCode', [deployed['address'], 'latest'])
            if code.removeprefix('0x') != artifact['deployedBytecode']['object'].removeprefix('0x'):
                raise RuntimeError('saved escrow missing from restored Anvil state')
        else:
            # One public contract for every trade, as on a real network.
            receipt = evm.send({'from': evm.rpc('eth_accounts')[0], 'data': artifact['bytecode']['object'],
                'gas': hex(5_000_000)})
            code = evm.rpc('eth_getCode', [receipt['contractAddress'], 'latest'])
            atomic(escrow, {'address': receipt['contractAddress'], 'block': int(receipt['blockNumber'], 16),
                'code_hash': evm_wallet.keccak(bytes.fromhex(code[2:])).hex()})
        self.escrow = json.loads(escrow.read_text())
        status()
        threading.Thread(target=self.mine, daemon=True).start()

    def mine(self):
        # A stand-in for block production: pending Zcash transactions get two
        # blocks, so every waiting party sees the confirmations it requires.
        while True:
            try:
                if zrpc('getrawmempool'):
                    zrpc('generate', [2], timeout=300)
                    self.note('Zcash: mined 2 blocks for pending transactions')
            except (OSError, RuntimeError):
                pass
            time.sleep(1)

    # Owner apps ------------------------------------------------------------
    def policy(self, role):
        denied = [self.root / name for name in ('network', 'relay')]
        denied += [self.root / name for other, names in PRIVATE.items() if other != role for name in names]
        return '(version 1)(allow default)' + ''.join(
            f'(deny file-read* file-write* (subpath {json.dumps(str(p))}))' for p in denied)

    def prove_isolation(self):
        # Under each app's exact policy, reading the other owner's identity
        # file must fail with a permission error, not merely be unused.
        for role, other in (('alice', 'bob'), ('bob', 'alice')):
            target = self.root / other / 'operator-public.json'
            probe = subprocess.run(['/usr/bin/sandbox-exec', '-p', self.policy(role), sys.executable, '-c',
                'import sys\ntry: open(sys.argv[1]).read()\nexcept PermissionError: sys.exit(0)\nelse: sys.exit(9)', str(target)],
                capture_output=True, timeout=20)
            if not target.exists() or probe.returncode:
                raise RuntimeError('sandbox isolation not proven')
        self.isolation = True
        self.note("Sandbox checked: neither app can read the other owner's files")

    def launch(self, role):
        policy = self.policy(role)
        log = (self.root / 'network' / f'{role}-app.log').open('a')
        process = subprocess.Popen(['/usr/bin/sandbox-exec', '-p', policy, sys.executable,
            str(ROOT / 'scripts/party_app.py'), '--role', role, '--root', str(self.root),
            '--port', str(PORTS[role]), '--network', f'http://127.0.0.1:{PORTS["network"]}'],
            cwd=ROOT, stdout=log, stderr=log, start_new_session=True,
            env=dict(os.environ, LATCH_RELAY_TOKEN=self.app_tokens[role], RAYON_NUM_THREADS='2'))
        self.apps[role] = process
        self.record_children()
        self.note(f'{role.capitalize()} app started (sandboxed)')

    def crash(self, role, reason='demo interruption'):
        process = self.apps.get(role)
        if process and process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)  # The app, its signer and any running command.
            process.wait()
            if reason:
                self.note(f'{role.capitalize()} app killed (SIGKILL): {reason}')

    # HTTP --------------------------------------------------------------------
    def relay(self):
        messages = []
        for path in sorted((self.root / 'relay').glob('*.json')):
            messages.append(json.loads(path.read_text()))
        return messages

    def get(self, path, raw):
        if path == '/api/network':
            with self.lock:
                tip = status()
                block = evm.rpc('eth_getBlockByNumber', ['latest', False])
                return {'token': self.page_token, 'zcash': {'height': tip['blocks'], 'mempool': len(zrpc('getrawmempool'))},
                    'ethereum': {'block': int(block['number'], 16), 'timestamp': int(block['timestamp'], 16)},
                    'escrow': self.escrow, 'isolation_proven': getattr(self, 'isolation', False), 'apps': {r: {'running': p.poll() is None, 'port': PORTS[r]} for r, p in self.apps.items()},
                    'relay': [{k: m.get(k) for k in ('seq', 'from', 'to', 'topic', 'at', 'bytes', 'sha256')} for m in self.relay()],
                    'events': self.events[::-1]}
        if path == '/api/relay':
            return {'messages': self.relay(), 'escrow': self.escrow}
        return None

    def post(self, path, body, token):
        role = next((r for r, t in self.app_tokens.items() if t == token), None)
        with self.lock:
            if path == '/api/relay' and role:
                topic, content = body.get('topic'), body.get('body')
                if topic not in TOPICS or not isinstance(content, dict) or (topic == 'sealed' and not sealed(content, role)):
                    raise ValueError('Unsupported relay message.')
                seq = len(list((self.root / 'relay').glob('*.json'))) + 1
                if seq > 500:
                    raise ValueError('Relay is full.')
                encoded = json.dumps(content, sort_keys=True, separators=(',', ':'))
                message = {'seq': seq, 'from': role, 'topic': topic, 'at': int(time.time()), 'bytes': len(encoded),
                    'sha256': hashlib.sha256(encoded.encode()).hexdigest(), 'body': content}
                if topic == 'sealed':
                    message['to'] = content['to']
                atomic(self.root / 'relay' / f'{seq:04d}-{role}-{topic}.json', message)
                self.note(f'Relay: {role} → {content["to"]}, sealed ({len(encoded):,} bytes)' if topic == 'sealed'
                    else f'Relay: {role} posted its identity')
                return {'seq': seq}
            if path == '/api/faucet' and role:
                address = body.get('address', '')
                if not (isinstance(address, str) and len(address) == 42 and address.startswith('0x')):
                    raise ValueError('Ethereum address required.')
                evm.rpc('anvil_setBalance', [address, hex(11 * 10**18)])
                self.note(f'Faucet: 11 local ETH to {role}')
                return {'funded': address}
            if token != self.page_token:
                raise ValueError('Network controls belong to the network page.')
            action = body.get('action')
            if action == 'advance-eth':
                evm.rpc('evm_increaseTime', [3660])
                evm.rpc('evm_mine')
                self.note('Control: Ethereum time advanced 61 minutes')
            elif action == 'advance-zec':
                zrpc('generate', [24], timeout=300)
                self.note('Control: Zcash advanced 24 blocks')
            elif action == 'prove-isolation':
                self.prove_isolation()
            elif action in ('crash', 'restart') and body.get('role') in PRIVATE:
                self.crash(body['role'], 'demo interruption' if action == 'crash' else None)
                if action == 'restart':
                    self.launch(body['role'])
            else:
                raise ValueError('Unknown control.')
            return {'ok': True}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('root', type=Path)
    a = p.parse_args()
    os.umask(0o077)
    root = a.root.resolve()
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    # Exclusive for the lifetime of this network: the single-window demo and
    # chain checks cannot start their own Anvil or mine underneath it.
    lock = (ROOT / '.local/chain-driver.lock').open('a')
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    reap_orphans()
    network = Network(root)
    network.start_chains()
    for role in PRIVATE:
        network.launch(role)
    # Apps create their roots on first start; prove the denial once both exist.
    def isolation():
        for _ in range(60):
            if all((root / r / 'operator-public.json').exists() for r in PRIVATE):
                return network.prove_isolation()
            time.sleep(1)
    threading.Thread(target=isolation, daemon=True).start()

    class Page(Handler):
        page = 'network.html'
    server = ThreadingHTTPServer(('127.0.0.1', PORTS['network']), Page)
    server.app = network

    def stop(signum, frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, stop)  # Clean up the apps and Anvil on any stop.
    print(json.dumps({'network': f'http://127.0.0.1:{PORTS["network"]}',
        'alice': f'http://127.0.0.1:{PORTS["alice"]}', 'bob': f'http://127.0.0.1:{PORTS["bob"]}'}), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        for role in list(network.apps):
            network.crash(role, None)
        os.killpg(network.anvil.pid, signal.SIGTERM)  # Anvil writes its --state file on exit.
        network.anvil.wait(timeout=20)
        CHILDREN.unlink(missing_ok=True)


if __name__ == '__main__':
    main()
