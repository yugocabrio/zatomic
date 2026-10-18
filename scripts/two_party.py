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
import urllib.error
from http.server import ThreadingHTTPServer
import run_native_evm_gate as evm
import evm_wallet
from regtest_node import rpc as zrpc, status
from regtest_wallet import native
from two_party_http import ROOT, Handler, atomic, call

PORTS = {'network': 8790, 'alice': 8791, 'bob': 8792}
TOPICS = ('manifest', 'sealed')
HEX = set('0123456789abcdef')
PRIVATE = {'alice': ('alice', 'alice-source', 'alice-app'), 'bob': ('bob', 'bob-app')}
EVIDENCE = {p.name: p for p in (ROOT / 'evidence').glob('*.json')}
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


def topic(signature):
    return '0x' + evm_wallet.keccak(signature.encode()).hex()


EVENTS = {topic('Locked(bytes32,address,address,uint256,uint64,uint256,uint256,bytes32)'): 'locked',
          topic('Claimed(bytes32,uint256)'): 'claimed', topic('Refunded(bytes32)'): 'refunded',
          topic('Withdrawn(address,address,uint256)'): 'withdrawn'}


class PublicView:
    """What an outside observer of the two chains and the relay can see.

    Decodes only public transaction effects (action count, transparent inputs
    and outputs) and escrow events. It never reads an owner's files."""

    def __init__(self, root):
        self.root, self.lock = root, threading.Lock()
        start = root/'network/public-start.json'
        if not start.exists():
            atomic(start, {'height': status()['blocks']})
        self.scanned = json.loads(start.read_text())['height']
        self.zcash, self.seen = [], {}

    def scan_zcash(self):
        tip = status()['blocks']
        for height in range(self.scanned + 1, tip + 1):
            block = zrpc('getblock', [zrpc('getblockhash', [height]), 2])
            for tx in block['tx'][1:]:  # Skip the coinbase.
                path = self.root/'network'/f'inspect-{tx["txid"]}.hex'
                path.write_text(tx['hex']); path.chmod(0o600)
                try:
                    info = native('inspect-transaction', path)
                finally:
                    path.unlink()
                self.zcash.append({'chain': 'zcash', 'at': int(time.time()), 'height': height, 'txid': info['txid'],
                    'actions': len(info['ironwood_actions']), 'transparent_inputs': len(info['transparent_inputs']),
                    'transparent_outputs': [o['value_zatoshi'] for o in info['transparent_outputs']]})
            self.scanned = height

    def ethereum(self, escrow):
        events = []
        for log in evm.rpc('eth_getLogs', [{'address': escrow, 'fromBlock': '0x0', 'toBlock': 'latest'}]):
            kind = EVENTS.get(log['topics'][0])
            if kind is None:
                continue
            key = (log['transactionHash'], log['logIndex'])
            at = self.seen.setdefault(key, int(time.time()))
            words = [int(log['data'][2 + 64*i:66 + 64*i], 16) for i in range((len(log['data']) - 2) // 64)]
            address = lambda t: '0x' + t[-40:]
            event = {'chain': 'ethereum', 'at': at, 'event': kind, 'tx': log['transactionHash'],
                'block': int(log['blockNumber'], 16)}
            if kind == 'locked':
                event.update(maker=address(log['topics'][2]), recipient=address(log['topics'][3]), amount_wei=str(words[0]))
            elif kind == 'claimed':
                event.update(witness=hex(words[0]))
            elif kind == 'withdrawn':
                event.update(owner=address(log['topics'][1]), amount_wei=str(words[0]))
            events.append(event)
        return events

    def snapshot(self, escrow, relay):
        with self.lock:
            self.scan_zcash()
            ethereum = self.ethereum(escrow)
        messages = [{'chain': 'relay', 'at': m['at'], 'seq': m['seq'], 'from': m['from'], 'to': m.get('to'),
            'kind': m['topic'], 'bytes': m.get('bytes')} for m in relay]
        return sorted(messages + self.zcash + ethereum, key=lambda e: (e['at'], e.get('seq', 0), e.get('block', 0), e.get('height', 0)))


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
        self.public = None  # Created once the chains are up.
        self.mining, self.autoplaying, self.generation = False, None, 0

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
        if not self.mining:
            self.mining = True
            threading.Thread(target=self.mine, daemon=True).start()

    def boot(self):
        """Chains, the public view and both apps, for the current workspace."""
        self.start_chains()
        self.public = PublicView(self.root)
        for role in PRIVATE:
            self.launch(role)
        threading.Thread(target=self.watch_isolation, args=(self.root,), daemon=True).start()

    def watch_isolation(self, root):
        # Apps create their roots on first start; prove the denial once both exist.
        for _ in range(60):
            if self.root != root:
                return
            if all((root / r / 'operator-public.json').exists() for r in PRIVATE):
                return self.prove_isolation()
            time.sleep(1)

    def shutdown(self):
        for role in list(self.apps):
            self.crash(role, None)
        if getattr(self, 'anvil', None) and self.anvil.poll() is None:
            os.killpg(self.anvil.pid, signal.SIGTERM)  # Anvil writes its --state file on exit.
            self.anvil.wait(timeout=20)

    def new_trade(self):
        """Each workspace holds one trade: start a fresh one with new keys, a
        fresh escrow and fresh apps. The previous workspace stays on disk."""
        self.shutdown()
        root = self.root.parent / time.strftime('two-party-%Y%m%d-%H%M%S')
        if root.exists():
            root = root.with_name(root.name + '-' + secrets.token_hex(2))
        self.root, self.apps, self.events, self.isolation = root, {}, [], False
        self.app_tokens = {r: secrets.token_urlsafe(32) for r in PRIVATE}
        for name in ('network', 'relay'):
            (root / name).mkdir(mode=0o700, parents=True, exist_ok=True)
        self.generation += 1
        self.note('New trade: fresh workspace, keys and escrow')
        self.boot()

    def advance_eth(self):
        evm.rpc('evm_increaseTime', [3660])
        evm.rpc('evm_mine')
        self.note('Control: Ethereum time advanced 61 minutes')

    def advance_zec(self):
        zrpc('generate', [24], timeout=300)
        self.note('Control: Zcash advanced 24 blocks')

    def autoplay(self, path):
        """Press each app's highlighted button in turn, at a watchable pace,
        through the apps' own page endpoints. 'refund' never reveals t: it lets
        the ETH order expire and the native refund mature instead."""
        if self.autoplaying:
            raise ValueError('Autoplay is already running.')
        self.autoplaying = path
        threading.Thread(target=self.play, args=(path, self.root), daemon=True).start()

    def play(self, path, root):
        urls = {r: f'http://127.0.0.1:{PORTS[r]}' for r in PRIVATE}
        advanced = {'eth': 0, 'zec': 0}
        try:
            for _ in range(900):
                if self.root != root:
                    return
                views = {}
                for r in PRIVATE:
                    try:
                        views[r] = call(urls[r], '/api/state')
                    except OSError:
                        views[r] = None
                if all(v and v.get('complete') for v in views.values()):
                    self.note('Autoplay: both owners finished')
                    return
                acted = False
                for r in PRIVATE:
                    v = views[r]
                    if not v or v.get('busy') or v.get('offline') or v.get('complete'):
                        continue
                    a = v.get('action') or {}
                    if path == 'refund' and r == 'alice' and a.get('id') == 'claim':
                        if not advanced['eth']:
                            advanced['eth'] += 1
                            self.advance_eth()
                        continue
                    if path == 'refund' and r == 'alice' and (a.get('wait') or '').startswith('ETH order expired'):
                        if advanced['zec'] < 3:
                            advanced['zec'] += 1
                            self.advance_zec()
                        continue
                    if not a.get('id'):
                        continue
                    body = {'action': a['id']}
                    if a['id'] == 'trust':
                        body['fingerprint'] = a['fingerprint']
                        if a.get('source_fingerprint'):
                            body['source_fingerprint'] = a['source_fingerprint']
                    if a['id'] == 'offer':
                        body.update(zec_amount='0.019', eth_amount='0.0371')
                    try:
                        call(urls[r], '/api/act', body, v['token'])
                    except urllib.error.HTTPError:
                        raise
                    except OSError:
                        continue  # The app was stopped mid-press; try again once it is back.
                    self.note(f'Autoplay: {r.capitalize()} pressed “{a["label"]}”')
                    acted = True
                    break  # One press per round keeps the pace watchable.
                time.sleep(3 if acted else 2)
        except Exception as exc:  # Keep serving; the log says where it stopped.
            self.note(f'Autoplay stopped: {exc}')
        finally:
            self.autoplaying = None

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
        if path.startswith('/evidence/'):
            # Only committed public evidence records, by exact file name.
            name = path.removeprefix('/evidence/')
            return json.loads(EVIDENCE[name].read_text()) if name in EVIDENCE else None
        if path == '/api/public':
            relay = self.relay()
            owners = {}
            for m in relay:
                if m['topic'] == 'manifest':
                    for role in ('alice', 'bob'):
                        if role in m['body']:
                            owners[role] = m['body'][role]['identity']['address']
            tip = status()
            return {'events': self.public.snapshot(self.escrow['address'], relay), 'owners': owners,
                'zcash_height': tip['blocks'], 'apps': {r: PORTS[r] for r in PRIVATE},
                'running': {r: p.poll() is None for r, p in self.apps.items()},
                'token': self.page_token, 'autoplay': self.autoplaying, 'generation': self.generation}
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
                self.advance_eth()
            elif action == 'advance-zec':
                self.advance_zec()
            elif action == 'autoplay' and body.get('path') in ('success', 'refund'):
                self.autoplay(body['path'])
            elif action == 'new-trade':
                self.new_trade()
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
    network.boot()

    class Page(Handler):
        page = 'landing.html'
        pages = {'/stage': 'stage.html', '/network': 'network.html'}
        frame_sources = ' '.join(f'http://127.0.0.1:{PORTS[r]}' for r in PRIVATE)
    server = ThreadingHTTPServer(('127.0.0.1', PORTS['network']), Page)
    server.app = network

    def stop(signum, frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, stop)  # Clean up the apps and Anvil on any stop.
    print(json.dumps({'network': f'http://127.0.0.1:{PORTS["network"]}', 'stage': f'http://127.0.0.1:{PORTS["network"]}/stage',
        'alice': f'http://127.0.0.1:{PORTS["alice"]}', 'bob': f'http://127.0.0.1:{PORTS["bob"]}'}), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        network.shutdown()
        CHILDREN.unlink(missing_ok=True)


if __name__ == '__main__':
    main()
