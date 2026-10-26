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

Hosted on Linux (LATCH_APP_USERS=1), each app runs as its own Unix user
(latch-alice, latch-bob) under a private root that neither the other app nor
this process can open; deploy/ holds the sudo rules that allow exactly that.
With public origins set, one visitor at a time holds the demo controls.
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
import urllib.parse
from http.server import ThreadingHTTPServer
import run_native_evm_gate as evm
import escrow_abi
import evm_wallet
from regtest_node import rpc as zrpc, status
from regtest_wallet import MAX_CAPTURE_HEIGHT, demo_amounts, native
from two_party_http import ROOT, Handler, atomic, call, public_origins

# A second local network (another checkout's demo already on 8790-8792) can
# take three consecutive loopback ports from LATCH_TWO_PARTY_PORT_BASE.
_BASE = os.environ.get('LATCH_TWO_PARTY_PORT_BASE', '8790')
if not _BASE.isascii() or not _BASE.isdecimal() or not 1024 <= int(_BASE) <= 65533:
    raise RuntimeError('LATCH_TWO_PARTY_PORT_BASE must be an unprivileged port')
PORTS = {'network': int(_BASE), 'alice': int(_BASE) + 1, 'bob': int(_BASE) + 2}
TOPICS = ('manifest', 'sealed')
HEX = set('0123456789abcdef')
PRIVATE = {'alice': ('alice', 'alice-source', 'alice-app'), 'bob': ('bob', 'bob-app')}
EVIDENCE = {p.name: p for p in (ROOT / 'evidence').glob('*.json')}
CHILDREN = ROOT / '.local/two-party-children.json'
ORIGINS = public_origins()
USERS = os.environ.get('LATCH_APP_USERS') == '1'
if USERS and not sys.platform.startswith('linux'):
    raise RuntimeError('per-user owner apps are the Linux hosting mode; macOS uses sandbox-exec')
APP_BASE = Path(os.environ.get('LATCH_APP_BASE', '/var/lib/latch'))
LIBEXEC = Path('/usr/local/libexec')
LEASE_IDLE, LEASE_AUTOPLAY = 300, 120  # Seconds a driver keeps the controls.
LEASE_AFTER_AUTOPLAY = 30  # A finished scenario passes the controls on soon.
TRADE_BLOCKS = 400  # Generous bound per trade: funding mines 101 blocks, a refund 72 more.


def listening(port):
    """An app's page loads only once its server accepts connections."""
    with socket.socket() as probe:
        probe.settimeout(.2)
        return probe.connect_ex(('127.0.0.1', port)) == 0


def as_user(role, *command, **options):
    """Run a fixed helper as an owner's Unix user (sudo rules in deploy/)."""
    return subprocess.run(['sudo', '-n', '-u', f'latch-{role}', *map(str, command)], timeout=30, **options)


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


EVENTS = {topic(escrow_abi.LOCKED): 'locked', topic(escrow_abi.CLAIMED): 'claimed',
          topic(escrow_abi.REFUNDED): 'refunded', topic(escrow_abi.WITHDRAWN[1]): 'withdrawn',
          topic(escrow_abi.WITHDRAWN[2]): 'withdrawn'}


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
                # v1 topics: owner, to; v2 topics: order id, owner, to.
                event.update(owner=address(log['topics'][-2]), amount_wei=str(words[0]))
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
        self.scenario, self.interrupted = None, []  # What this trade's Autoplay ran; apps killed.
        self.driver = None  # Public-host mode: {'lease', 'until'} of the visitor driving.
        self.internal = secrets.token_urlsafe(32)  # Autoplay's own presses.

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
        get_code = lambda address: evm.rpc('eth_getCode', [address, 'latest'])
        if escrow.exists():
            deployed = json.loads(escrow.read_text())
            try:
                escrow_abi.verify_code({'contract': deployed['address'],
                    'escrow_version': deployed.get('version', 1)}, get_code)
            except RuntimeError:
                raise RuntimeError('saved escrow missing from restored Anvil state') from None
        else:
            # One public contract for every trade, as on a real network.
            version = escrow_abi.local_default()
            receipt = evm.send({'from': evm.rpc('eth_accounts')[0], 'data': escrow_abi.creation_code(version),
                'gas': hex(5_000_000)})
            code = get_code(receipt['contractAddress'])
            atomic(escrow, {'address': receipt['contractAddress'], 'block': int(receipt['blockNumber'], 16),
                'code_hash': evm_wallet.keccak(bytes.fromhex(code[2:])).hex(), 'version': version})
        self.escrow = json.loads(escrow.read_text())
        tip = status()
        if tip['blocks'] < 2:  # A brand-new chain (a hosted reset): activate NU7.
            zrpc('generate', [2 - tip['blocks']], timeout=300)
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
            if all(self.identity_exists(r) for r in PRIVATE):
                return self.prove_isolation()
            time.sleep(1)

    def app_root(self, role):
        return APP_BASE / role / self.root.name if USERS else self.root

    def app_url(self, role):
        return ORIGINS[role] if ORIGINS else f'http://127.0.0.1:{PORTS[role]}'

    def identity_exists(self, role):
        path = self.app_root(role) / role / 'operator-public.json'
        return as_user(role, LIBEXEC / 'latch-probe', path).returncode == 0 if USERS else path.exists()

    def shutdown(self):
        for role in list(self.apps):
            self.crash(role, None)
        if getattr(self, 'anvil', None) and self.anvil.poll() is None:
            os.killpg(self.anvil.pid, signal.SIGTERM)  # Anvil writes its --state file on exit.
            self.anvil.wait(timeout=20)

    def new_trade(self):
        """Each workspace holds one trade: start a fresh one with new keys, a
        fresh escrow and fresh apps. The previous workspace stays on disk."""
        if status()['blocks'] + TRADE_BLOCKS > MAX_CAPTURE_HEIGHT:
            raise ValueError('The demo chain is nearly full. A fresh chain starts at the next daily reset.')
        self.shutdown()
        root = self.root.parent / time.strftime('two-party-%Y%m%d-%H%M%S')
        if root.exists():
            root = root.with_name(root.name + '-' + secrets.token_hex(2))
        self.root, self.apps, self.events, self.isolation = root, {}, [], False
        # An Autoplay of the old trade notices the new root and stops by itself.
        self.scenario, self.interrupted, self.autoplaying = None, [], None
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
        the ETH order expire and the native refund mature instead. 'crash' kills
        Bob's app right after Alice's claim and restarts it a few seconds later,
        so Bob learns t only from Ethereum."""
        if self.autoplaying:
            raise ValueError('A live demo is already running. You can watch it.')
        self.autoplaying = path
        self.scenario = {'path': path, 'started': int(time.time()), 'ended': None}
        threading.Thread(target=self.play, args=(path, self.root), daemon=True).start()

    def play(self, path, root):
        urls = {r: f'http://127.0.0.1:{PORTS[r]}' for r in PRIVATE}
        advanced = {'eth': 0, 'zec': 0}
        presses = {}  # A press that succeeds moves the app on; one that keeps reappearing failed.
        try:
            for _ in range(900):
                if self.root != root:
                    return
                if self.driver:
                    self.driver['until'] = max(self.driver['until'], time.time() + LEASE_AUTOPLAY)
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
                    if path == 'refund' and r == 'alice' and (a.get('wait') or '').startswith(('ETH order expired', 'Bob never locked')):
                        if advanced['zec'] < 3:
                            advanced['zec'] += 1
                            self.advance_zec()
                        continue
                    if not a.get('id'):
                        continue
                    presses[r, a['id']] = presses.get((r, a['id']), 0) + 1
                    if presses[r, a['id']] > 4:
                        raise RuntimeError(f'{r.capitalize()}’s “{a["label"]}” keeps failing; that app shows why')
                    body = {'action': a['id'], 'lease': self.internal}
                    if a['id'] == 'trust':
                        body['fingerprint'] = a['fingerprint']
                        if a.get('source_fingerprint'):
                            body['source_fingerprint'] = a['source_fingerprint']
                    if a['id'] == 'offer':
                        body['zec_amount'], body['eth_amount'] = demo_amounts()
                    try:
                        call(urls[r], '/api/act', body, v['token'])
                    except urllib.error.HTTPError:
                        raise
                    except OSError:
                        continue  # The app was stopped mid-press; try again once it is back.
                    self.note(f'Autoplay: {r.capitalize()} pressed “{a["label"]}”')
                    if path == 'crash' and r == 'alice' and a['id'] == 'claim' and 'bob' not in self.interrupted:
                        time.sleep(1)
                        with self.lock:
                            self.crash('bob', 'scenario: right after Alice’s claim')
                        time.sleep(8)
                        if self.root != root:
                            return
                        with self.lock:
                            self.launch('bob')
                    acted = True
                    break  # One press per round keeps the pace watchable.
                time.sleep(3 if acted else 2)
        except Exception as exc:  # Keep serving; the log says where it stopped.
            self.note(f'Autoplay stopped: {exc}')
        finally:
            if self.root == root:
                self.autoplaying = None
                if self.scenario:
                    self.scenario['ended'] = int(time.time())
                # The driver keeps the controls only by pressing again soon.
                if self.driver:
                    self.driver['until'] = min(self.driver['until'], time.time() + LEASE_AFTER_AUTOPLAY)

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
        # File access alone does not stop connect() to a Unix socket inside a
        # denied directory (the v2 claim pre-check's private node), so deny that too.
        return '(version 1)(allow default)' + ''.join(
            f'(deny file-read* file-write* (subpath {json.dumps(str(p))}))'
            f'(deny network-outbound (remote unix-socket (subpath {json.dumps(str(p))})))' for p in denied)

    def prove_isolation(self):
        # Under each app's exact policy, reading the other owner's identity
        # file must fail with a permission error, not merely be unused.
        if USERS:
            return self.prove_user_isolation()
        for role, other in (('alice', 'bob'), ('bob', 'alice')):
            target = self.root / other / 'operator-public.json'
            probe = subprocess.run(['/usr/bin/sandbox-exec', '-p', self.policy(role), sys.executable, '-c',
                'import sys\ntry: open(sys.argv[1]).read()\nexcept PermissionError: sys.exit(0)\nelse: sys.exit(9)', str(target)],
                capture_output=True, timeout=20)
            if not target.exists() or probe.returncode:
                raise RuntimeError('sandbox isolation not proven')
        self.isolation = True
        self.note("Sandbox checked: neither app can read the other owner's files")

    def prove_user_isolation(self):
        # Each owner can read its own identity file; the other owner's Unix
        # user gets a permission error (exit 13), and so does this process.
        for role, other in (('alice', 'bob'), ('bob', 'alice')):
            target = self.app_root(other) / other / 'operator-public.json'
            own = as_user(other, LIBEXEC / 'latch-probe', target).returncode
            foreign = as_user(role, LIBEXEC / 'latch-probe', target).returncode
            try:
                target.read_bytes()
                network = 'read'
            except PermissionError:
                network = 'denied'
            if (own, foreign, network) != (0, 13, 'denied'):
                raise RuntimeError('user isolation not proven')
        self.isolation = True
        self.note("Unix users checked: neither app, nor the network, can read an owner's files")

    def launch(self, role):
        log = (self.root / 'network' / f'{role}-app.log').open('a')
        arguments = ['--role', role, '--root', str(self.app_root(role)), '--port', str(PORTS[role]),
            '--network', f'http://127.0.0.1:{PORTS["network"]}']
        if USERS:
            # sudo passes only the variables its rule keeps (deploy/sudoers).
            command = ['sudo', '-n', '-u', f'latch-{role}', str(LIBEXEC / 'latch-app'), *arguments]
        else:
            command = ['/usr/bin/sandbox-exec', '-p', self.policy(role), sys.executable,
                str(ROOT / 'scripts/party_app.py'), *arguments]
        process = subprocess.Popen(command, cwd=ROOT, stdout=log, stderr=log, start_new_session=True,
            env=dict(os.environ, LATCH_RELAY_TOKEN=self.app_tokens[role], RAYON_NUM_THREADS='2'))
        self.apps[role] = process
        self.record_children()
        self.note(f'{role.capitalize()} app started (' + ('as its own Unix user)' if USERS else 'sandboxed)'))

    def crash(self, role, reason='demo interruption'):
        process = self.apps.get(role)
        if process and process.poll() is None:
            if USERS:  # Everything that user runs: the app, its signer and any command.
                as_user(role, '/usr/bin/pkill', '-KILL', '-u', f'latch-{role}')
            else:
                os.killpg(process.pid, signal.SIGKILL)  # The app, its signer and any running command.
            process.wait()
            if reason:
                self.interrupted.append(role)
                self.note(f'{role.capitalize()} app killed (SIGKILL): {reason}')

    # One driver at a time (public-host mode) --------------------------------
    def lease_ok(self, lease):
        if not ORIGINS:
            return True
        if not isinstance(lease, str) or not lease:
            return False
        if secrets.compare_digest(lease, self.internal):
            return True
        driver = self.driver
        if driver and driver['until'] > time.time() and secrets.compare_digest(lease, driver['lease']):
            driver['until'] = max(driver['until'], time.time() + LEASE_IDLE)
            return True
        return False

    def drive(self, lease):
        """Hand the manual controls to a visitor if nobody holds them (or
        renew). A running scenario keeps them until it ends."""
        if not ORIGINS:
            return {'lease': None, 'until': None}
        if self.autoplaying and not self.lease_ok(lease):
            raise ValueError('A live demo is running. You can watch it; the controls free up when it ends.')
        if not self.lease_ok(lease):
            if self.driver and self.driver['until'] > time.time():
                raise ValueError('Another visitor has the controls until '
                    f'{time.strftime("%H:%M", time.gmtime(self.driver["until"]))} UTC. You can watch meanwhile.')
            self.driver = {'lease': secrets.token_urlsafe(24), 'until': time.time() + LEASE_IDLE}
        return {'lease': self.driver['lease'], 'until': int(self.driver['until'])}

    def driver_view(self, lease):
        # Polling only reads the lease; it never extends it.
        driver = self.driver
        if not (ORIGINS and driver and driver['until'] > time.time()):
            return None
        mine = isinstance(lease, str) and bool(lease) and secrets.compare_digest(lease, driver['lease'])
        return {'until': int(driver['until']), 'mine': mine}

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
                    'escrow': self.escrow, 'isolation_proven': getattr(self, 'isolation', False), 'isolation_by': 'users' if USERS else 'sandbox', 'apps': {r: {'running': p.poll() is None, 'port': PORTS[r], 'url': self.app_url(r)} for r, p in self.apps.items()},
                    'relay': [{k: m.get(k) for k in ('seq', 'from', 'to', 'topic', 'at', 'bytes', 'sha256')} for m in self.relay()],
                    'events': self.events[::-1]}
        if path == '/api/relay':
            return {'messages': self.relay(), 'escrow': self.escrow}
        if path.startswith('/evidence/'):
            # Only committed public evidence records, by exact file name.
            name = path.removeprefix('/evidence/')
            return json.loads(EVIDENCE[name].read_text()) if name in EVIDENCE else None
        if path == '/api/public':
            lease = urllib.parse.parse_qs(urllib.parse.urlsplit(raw).query).get('lease', [''])[0]
            relay = self.relay()
            owners = {}
            for m in relay:
                if m['topic'] == 'manifest':
                    for role in ('alice', 'bob'):
                        if role in m['body']:
                            owners[role] = m['body'][role]['identity']['address']
            tip = status()
            return {'events': self.public.snapshot(self.escrow['address'], relay), 'owners': owners,
                'zcash_height': tip['blocks'], 'apps': {r: self.app_url(r) for r in PRIVATE},
                'running': {r: p.poll() is None for r, p in self.apps.items()},
                'ready': {r: r in self.apps and self.apps[r].poll() is None and listening(PORTS[r]) for r in PRIVATE},
                'token': self.page_token, 'autoplay': self.autoplaying, 'generation': self.generation,
                'scenario': self.scenario, 'interrupted': sorted(set(self.interrupted)), 'now': int(time.time()),
                'public': bool(ORIGINS), 'driver': self.driver_view(lease),
                'isolation': {'proven': bool(getattr(self, 'isolation', False)), 'by': 'users' if USERS else 'sandbox'},
                'trades_left': max(0, (MAX_CAPTURE_HEIGHT - tip['blocks']) // TRADE_BLOCKS)}
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
            if path == '/api/lease' and role:
                # An owner app asks whether a page press comes from the driver.
                return {'ok': self.lease_ok(body.get('lease'))}
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
            if action == 'drive':
                return self.drive(body.get('lease'))
            if action == 'autoplay' and body.get('path') in ('success', 'crash', 'refund'):
                # Any visitor may start a scenario: one runs at a time, and
                # none starts while someone operates the apps by hand.
                driver = self.driver
                if ORIGINS and driver and driver['until'] > time.time() and not self.lease_ok(body.get('lease')):
                    raise ValueError('Someone is operating the apps by hand until '
                        f'{time.strftime("%H:%M", time.gmtime(driver["until"]))} UTC. You can watch meanwhile.')
                if self.autoplaying:
                    raise ValueError('A live demo is already running. You can watch it.')
                if body.get('fresh') is True:  # A finished trade: start a new one first.
                    self.new_trade()
                self.autoplay(body['path'])
                return {'ok': True}
            if not self.lease_ok(body.get('lease')):
                raise ValueError('Take the controls first.')
            if action == 'release':
                self.driver = None
            elif action == 'advance-eth':
                self.advance_eth()
            elif action == 'advance-zec':
                self.advance_zec()
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
    where = p.add_mutually_exclusive_group(required=True)
    where.add_argument('root', type=Path, nargs='?', help='workspace for this trade')
    where.add_argument('--latest-in', type=Path, metavar='DIR',
        help='resume the newest trade in DIR, or start one there (for a service restart)')
    a = p.parse_args()
    os.umask(0o077)
    if a.latest_in:
        trades = sorted(a.latest_in.resolve().glob('two-party-*'))
        root = trades[-1] if trades else a.latest_in.resolve() / time.strftime('two-party-%Y%m%d-%H%M%S')
    else:
        root = a.root.resolve()
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    # Exclusive for the lifetime of this network: the single-window demo and
    # chain checks cannot start their own Anvil or mine underneath it.
    lock = (ROOT / '.local/chain-driver.lock').open('a')
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    reap_orphans()
    if USERS:  # Apps left by an earlier network that did not shut down cleanly.
        for role in PRIVATE:
            as_user(role, '/usr/bin/pkill', '-KILL', '-u', f'latch-{role}')
    network = Network(root)
    network.boot()

    class Page(Handler):
        page = 'landing.html'
        pages = {'/stage': 'stage.html', '/network': 'network.html'}
        frame_sources = ' '.join(network.app_url(r) for r in PRIVATE)
        public_origin = ORIGINS and ORIGINS['site']
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
