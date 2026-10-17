#!/usr/bin/env python3
"""One owner's app in the two-party demo. It holds only this owner's private roots.

Alice's app runs her participant and her own source operator; Bob's app runs
his participant. Only identity manifests cross the relay in the clear; every
other message is sealed to the peer's pinned relay key. Every
action calls the same latch_operator commands as the separate-operator gate, so
keys, witnesses, journals and recovery data never leave the owner's roots.
"""
import argparse
import json
import os
from pathlib import Path
import secrets
import signal
import subprocess
import sys
import threading
import time
from http.server import ThreadingHTTPServer
import run_native_evm_gate as evm
import fee_policy
from latch_operator import manifest_digest
from regtest_node import rpc as zrpc, status
from otc_offer import decimal_amount
from two_party_http import ROOT, Handler, atomic, call

SIGNER_PORT = {'alice': 18741, 'bob': 18742}
OPERATOR = [sys.executable, str(ROOT / 'scripts/latch_operator.py')]
NATIVE = ROOT / 'target/release/shielded-swap-native'


def read(path):
    return json.loads(Path(path).read_text())


def short(value):
    return f'{value[:10]}…{value[-6:]}' if isinstance(value, str) and len(value) > 20 else value


class App:
    def __init__(self, role, root, network):
        self.role, self.root, self.network = role, root, network
        self.peer = 'bob' if role == 'alice' else 'alice'
        self.me, self.source = root / role, root / 'alice-source'
        self.home = root / f'{role}-app'
        self.home.mkdir(mode=0o700, exist_ok=True)
        self.page_token = secrets.token_urlsafe(32)
        self.relay_token = os.environ['LATCH_RELAY_TOKEN']
        self.lock = threading.RLock()
        self.busy, self.error, self.signer = None, None, None
        self.opened = {}  # Envelope SHA-256 -> opened message, or None if refused.
        self.state = read(self.home / 'state.json') if (self.home / 'state.json').exists() else {}
        self.initialize()
        threading.Thread(target=self.background, daemon=True).start()

    # Plumbing ----------------------------------------------------------------
    def tokens(self):
        return {self.page_token}

    def save(self, **values):
        self.state.update(values)
        atomic(self.home / 'state.json', self.state)

    def log(self, text):
        with (self.home / 'app.log').open('a') as handle:
            handle.write(f'{time.strftime("%H:%M:%S")} {text}\n')

    def operator(self, action, directory, packet=None, role=None, timeout=900):
        args = [*OPERATOR, action, str(directory)] + (['--role', role] if role else [])
        stdin = None if action in ('init', 'identity', 'serve', 'ready') else json.dumps(packet or {})
        result = subprocess.run(args, input=stdin, capture_output=True, text=True, cwd=ROOT, timeout=timeout)
        if result.returncode:
            self.log(f'{action} refused: {result.stderr.strip()[-400:]}')
            raise RuntimeError(f'{action} refused')
        return json.loads(result.stdout)

    def relay(self):
        return call(self.network, '/api/relay')

    def envelope(self, command, packet):
        result = subprocess.run([str(NATIVE), command, str(self.me)], input=json.dumps(packet),
            capture_output=True, text=True, cwd=ROOT, timeout=60)
        if result.returncode:
            raise RuntimeError(f'{command} refused')
        return json.loads(result.stdout)

    def peer_relay_key(self):
        pinned = self.me / 'trusted-peer.json'
        return read(pinned).get('relay_public_key') if pinned.exists() else None

    def publish(self, topic, body):
        if topic != 'manifest':
            key = self.peer_relay_key()
            if not key:
                raise RuntimeError('peer identity not trusted yet')
            body = self.envelope('relay-seal', {'from': self.role, 'to': self.peer, 'peer': key, 'topic': topic, 'body': body})
            topic = 'sealed'
        return call(self.network, '/api/relay', {'topic': topic, 'body': body}, self.relay_token)

    def inbox(self):
        """The relay as this owner reads it: identity manifests, plus the pinned
        peer's sealed messages opened locally. Anything else is ignored."""
        messages = self.relay()['messages']
        self.relay_total = len(messages)
        key = self.peer_relay_key()
        pending = [m for m in messages if m['topic'] == 'sealed' and m['from'] == self.peer and m['sha256'] not in self.opened]
        if key and pending:
            opened = self.envelope('relay-open', {'from': self.peer, 'to': self.role, 'peer': key,
                'envelopes': [m['body'] for m in pending]})['messages']
            for message, inner in zip(pending, opened):
                self.opened[message['sha256']] = inner
        readable = []
        for m in messages:
            if m['topic'] == 'manifest':
                readable.append(m)
            elif m['topic'] == 'sealed' and m['from'] == self.peer and self.opened.get(m['sha256']):
                inner = self.opened[m['sha256']]
                readable.append({'seq': m['seq'], 'from': m['from'], 'topic': inner['topic'], 'body': inner['body']})
        return readable

    @staticmethod
    def latest(messages, topic, sender):
        found = [m for m in messages if m['topic'] == topic and m['from'] == sender]
        return found[-1]['body'] if found else None

    def manifest(self, role):
        directory = self.source if role == 'coordinator' else self.root / role
        return read(directory / 'operator-public.json')

    # Setup -------------------------------------------------------------------
    def initialize(self):
        if not (self.me / 'operator-public.json').exists():
            self.operator('init', self.me, role=self.role)
        if self.role == 'alice':
            if not (self.source / 'operator-public.json').exists():
                self.operator('init', self.source, role='coordinator')
            # Alice's own source operator: she pins it without any exchange.
            pin = lambda m: {'manifest': m, 'expected_manifest_sha256': manifest_digest(m)}
            if not (self.me / 'trusted-coordinator.json').exists():
                self.operator('trust-coordinator', self.me, dict(pin(self.manifest('coordinator')), port=SIGNER_PORT['alice']))
            if not (self.source / 'alice-public.json').exists():
                self.operator('register-owner', self.source, dict(pin(self.manifest('alice')),
                    host='127.0.0.1', port=SIGNER_PORT['alice']))
        if not self.state.get('manifest_posted'):
            body = {self.role: self.manifest(self.role)}
            if self.role == 'alice':
                body['coordinator'] = self.manifest('coordinator')
            self.publish('manifest', body)
            self.save(manifest_posted=True)

    def start_signer(self):
        if self.signer and self.signer.poll() is None:
            return
        log = (self.home / 'signer.log').open('a')
        self.signer = subprocess.Popen([*OPERATOR, 'serve', str(self.me)], stdout=subprocess.PIPE,
            stderr=log, text=True, cwd=ROOT)
        if not json.loads(self.signer.stdout.readline() or '{}').get('ready'):
            raise RuntimeError('signer service did not start')

    def stop_signer(self):
        if self.signer and self.signer.poll() is None:
            self.signer.terminate()
            self.signer.wait(timeout=10)

    # Observations --------------------------------------------------------------
    def chain(self):
        seen = {'zcash_height': status()['blocks']}
        block = evm.rpc('eth_getBlockByNumber', ['latest', False])
        seen['eth_time'] = int(block['timestamp'], 16)
        agreement = self.state.get('agreement')
        if agreement:
            try:
                tx = zrpc('getrawtransaction', [agreement['native']['funding_txid'], 1])
                seen['funding_confirmations'] = tx.get('confirmations', 0) if tx.get('in_active_chain') else 0
            except RuntimeError:
                seen['funding_confirmations'] = None
            order = evm.rpc('eth_call', [{'to': agreement['contract'], 'data': evm.calldata(
                'orderId(address,bytes32)', agreement['maker'], agreement['eth_salt'])}, 'latest'])
            words = evm.rpc('eth_call', [{'to': agreement['contract'], 'data': evm.calldata('orders(bytes32)', order)}, 'latest'])
            seen['order'] = order
            seen['order_state'] = int(words[2 + 64 * 4: 2 + 64 * 5], 16) if len(words) > 2 + 64 * 5 else 0
            seen['eth_expired'] = seen['eth_time'] >= agreement['eth_expiry']
            seen['native_refund_ready'] = seen['zcash_height'] > agreement['native']['refund_height']
        return seen

    # Background work -------------------------------------------------------------
    def background(self):
        parent = os.getppid()
        while True:
            if os.getppid() != parent:
                # The network is gone. Take this app's whole process group
                # (its signer service and any running command) down with it.
                os.killpg(os.getpgid(0), signal.SIGKILL)
            try:
                with self.lock:
                    if not self.busy:
                        self.advance()
            except Exception as exc:  # Keep serving; the private log keeps the cause.
                self.log(f'background: {exc!r}')
            time.sleep(2)

    def advance(self):
        """Steps that need no decision: pinning received data and exporting exits."""
        messages = self.inbox()
        if self.role == 'alice':
            trade = self.latest(messages, 'acceptance', 'bob')
            if trade and self.state.get('offer') and not (self.me / 'accepted-trade.json').exists():
                self.operator('offer-accept', self.me, trade)
                self.save(trade=trade)
            consent = self.latest(messages, 'consent', 'bob')
            if consent and self.state.get('agreement') and not self.state.get('peer_consent'):
                self.save(peer_consent=consent)
        else:
            # Once Bob accepts or consents, what he signed is pinned: a later
            # relay message can never change what this page shows or uses.
            offer = self.latest(messages, 'offer', 'alice')
            if offer and (self.me / 'trusted-peer.json').exists() and not self.state.get('trade') and self.state.get('offer') != offer:
                review = self.operator('offer-review', self.me, offer)
                self.save(offer=offer, review=review)
            agreement = self.latest(messages, 'agreement', 'alice')
            if agreement and not self.state.get('consent') and self.state.get('agreement') != agreement:
                self.save(agreement=agreement)
            if self.state.get('trade') and not (self.me / 'recovery').exists():
                # Alice posts her terms only after staging finished, so the
                # signer is no longer needed once both exist.
                if (self.me / 'native/recovery-receipt.json').exists() and self.state.get('agreement'):
                    self.operator('ready', self.me)  # Export my own verified exit.
                    self.stop_signer()
                elif not self.signer or self.signer.poll() is not None:
                    self.start_signer()  # Also after a restart: Alice may still be staging.
                    self.publish('signer-ready', {'port': SIGNER_PORT['bob']})

    def run(self, label, work):
        def wrapped():
            try:
                work()
                self.error = None
            except Exception as exc:
                self.log(f'{label}: {exc!r}')
                self.error = f'{label} stopped. Private state retained; the next attempt resumes from it.'
            finally:
                self.busy = None
        self.busy = label
        threading.Thread(target=wrapped, daemon=True).start()

    # Actions -------------------------------------------------------------------------
    def act(self, body):
        action = body.get('action')
        messages = self.inbox()
        if action == 'trust':
            manifests = self.latest(messages, 'manifest', self.peer) or {}
            peer = manifests.get(self.peer)
            if not peer or body.get('fingerprint') != manifest_digest(peer):
                raise ValueError('The fingerprint on screen no longer matches the relay. Compare again.')
            pin = lambda m: {'manifest': m, 'expected_manifest_sha256': manifest_digest(m)}
            self.operator('trust-peer', self.me, pin(peer))
            if self.role == 'alice':
                self.operator('register-owner', self.source, dict(pin(peer), host='127.0.0.1', port=SIGNER_PORT['bob']))
            else:
                coordinator = manifests.get('coordinator')
                if not coordinator or body.get('source_fingerprint') != manifest_digest(coordinator):
                    raise ValueError("Alice's source fingerprint changed. Compare again.")
                self.operator('trust-coordinator', self.me, dict(pin(coordinator), port=SIGNER_PORT['bob']))
            return
        if action == 'offer' and self.role == 'alice':
            offer = self.operator('offer-create', self.me, {'zec_amount': body.get('zec_amount'), 'eth_amount': body.get('eth_amount')})
            self.publish('offer', offer)
            self.save(offer=offer)
            return
        if action == 'accept' and self.role == 'bob':
            trade = self.operator('offer-accept', self.me, self.state['offer'])
            call(self.network, '/api/faucet', {'address': self.manifest('bob')['identity']['address']}, self.relay_token)
            self.publish('acceptance', trade)
            self.save(trade=trade)
            return
        if action == 'prepare' and self.role == 'alice':
            return self.run('Preparing exits', self.prepare)
        if action == 'consent':
            consent = self.operator('consent', self.me, self.state['agreement'])
            if self.role == 'bob':
                self.publish('consent', consent)
                self.save(consent=consent)
                return
            self.save(consent=consent)
            return self.run('Funding ZEC', self.fund)
        if action in ('lock', 'claim', 'withdraw', 'refund'):
            return self.run({'lock': 'Locking ETH', 'claim': 'Claiming ETH', 'withdraw': 'Withdrawing ETH',
                'refund': 'Refunding ETH'}[action], lambda: self.eth(action))
        if action in ('native-claim', 'native-refund'):
            return self.run('Completing the ZEC claim' if action == 'native-claim' else 'Returning ZEC', lambda: self.native(action))
        raise ValueError('That action is not available now.')

    def prepare(self):
        trade = read(self.me / 'accepted-trade.json')
        call(self.network, '/api/faucet', {'address': self.manifest('alice')['identity']['address']}, self.relay_token)
        bank = self.source / 'bank'
        if not (bank / 'funded.json').exists():
            # Local faucet: mines regtest coinbase to Alice's own source wallet.
            subprocess.run([sys.executable, str(ROOT / 'scripts/regtest_wallet.py'), 'fund', str(bank)],
                cwd=ROOT, check=True, capture_output=True, timeout=600)
        if not (self.source / 'swap/terms.json').exists():
            for _ in range(60):
                if self.latest(self.inbox(), 'signer-ready', 'bob'):
                    break
                time.sleep(2)
            else:
                raise RuntimeError("Bob's signer is not online")
            self.start_signer()
            try:
                self.operator('stage', self.source, {'bank': str(bank), 'trade': trade})
            finally:
                self.stop_signer()
        if not (self.me / 'recovery').exists():
            self.operator('ready', self.me)
        if not self.state.get('agreement'):
            terms = read(self.source / 'swap/terms.json')
            escrow = self.relay()['escrow']
            now = int(evm.rpc('eth_getBlockByNumber', ['latest', False])['timestamp'], 16)
            pins = {r: read(self.root / r / 'operator-public.json')['identity'] if r == 'alice'
                else read(self.me / 'trusted-peer.json')['identity'] for r in ('alice', 'bob')}
            agreement = {'native': terms, 'eth_chain_id': evm.CHAIN, 'contract': escrow['address'],
                'maker': pins['bob']['address'], 'recipient': pins['alice']['address'],
                'amount_wei': trade['offer']['payload']['eth_amount_wei'], 'eth_expiry': now + 3600,
                'fee_policy': fee_policy.default(), 'consent_version': 1, 'eth_salt': '0x' + os.urandom(32).hex(),
                'eth_code_hash': escrow['code_hash'], 'scope': 'two-party local demo; each owner in its own sandboxed app'}
            self.publish('agreement', agreement)
            self.save(agreement=agreement)

    def fund(self):
        consents = {'alice': self.state['consent'], 'bob': self.state['peer_consent']}
        result = self.operator('source-fund', self.source, {'agreement': self.state['agreement'], 'consents': consents})
        self.save(funding=result)

    def eth(self, action):
        agreement = self.state['agreement']
        packet = {'salt': agreement['eth_salt']} if action == 'lock' else {'order': self.chain()['order']}
        result = self.operator(action, self.me, packet)
        self.save(**{action: result})
        if action == 'lock':
            self.publish('lock', {'order': result['order']})

    def native(self, action):
        order = self.chain()['order']
        for _ in range(60):
            result = self.operator(action, self.me, {'order': order})
            self.save(**{action.replace('-', '_'): result})
            if result.get('state') == 'confirmed':
                return
            time.sleep(3)  # The network mines pending transactions.
        raise RuntimeError('native exit not yet confirmed')

    # View --------------------------------------------------------------------------
    def view(self):
        messages = self.inbox()
        seen = self.chain()
        s = self.state
        manifests = self.latest(messages, 'manifest', self.peer) or {}
        peer = manifests.get(self.peer)
        trusted = (self.me / 'trusted-peer.json').exists()
        own = self.manifest(self.role)
        steps, action = [], None

        def step(key, title, done, detail=''):
            steps.append({'key': key, 'title': title, 'done': bool(done), 'detail': detail})

        if self.role == 'alice':
            step('trust', 'Trust Bob’s identity', trusted, 'Fingerprint compared out of band.' if trusted else '')
            step('quote', 'Sign a quote', s.get('offer'), self.quote_text(s.get('offer')))
            step('accepted', 'Bob accepts the quote', (self.me / 'accepted-trade.json').exists())
            step('prepare', 'Prepare and verify both exits', s.get('agreement'),
                f'Refund unlocks after block #{s["agreement"]["native"]["refund_height"]}.' if s.get('agreement') else '')
            step('fund', 'Both sign the full terms; ZEC funded', (seen.get('funding_confirmations') or 0) >= 2,
                f'F {short(s["agreement"]["native"]["funding_txid"])} · {seen.get("funding_confirmations")} confirmations' if s.get('funding') else '')
            # The last two steps follow the path actually taken: reveal, or none.
            refund_path = not s.get('claim') and (seen.get('order_state') == 3 or (seen.get('eth_expired') and seen.get('order_state') == 1))
            if refund_path:
                refunded = s.get('native_refund', {}).get('state') == 'confirmed'
                step('expired', 'No reveal: the ETH order expired', True, 'The secret t was never published.')
                step('refund', 'My prepared ZEC refund confirmed', refunded,
                    f'Tx {short(s["native_refund"]["txid"])} · decrypted by my wallet' if refunded else '')
            else:
                step('claim', 'Claim the ETH (reveals the secret)', s.get('claim'), f'Tx {short(s["claim"]["txid"])}' if s.get('claim') else '')
                step('withdraw', 'Withdraw the ETH', s.get('withdraw'), f'Tx {short(s["withdraw"]["txid"])}' if s.get('withdraw') else '')
            if not trusted:
                action = self.trust_action(peer, manifests)
            elif not s.get('offer'):
                action = {'id': 'offer', 'label': 'Sign quote', 'fields': True}
            elif not (self.me / 'accepted-trade.json').exists():
                action = {'wait': 'Waiting for Bob to review and accept the quote.'}
            elif not s.get('agreement'):
                action = {'id': 'prepare', 'label': 'Prepare exits', 'note': 'Funds your local source wallet, runs DKG with Bob’s signer and verifies both exits.'}
            elif not s.get('peer_consent'):
                action = {'wait': 'Waiting for Bob to sign the full terms.'}
            elif not s.get('funding'):
                action = {'id': 'consent', 'label': 'Sign full terms and fund ZEC', 'note': 'Your source wallet releases the funding only with both signatures.'}
            elif seen.get('order_state') == 1 and not s.get('claim') and not seen.get('eth_expired'):
                action = {'id': 'claim', 'label': 'Claim ETH (reveals the secret)', 'danger': True,
                    'note': 'Once sent, t is public: Bob can complete his ZEC claim with it.'}
            elif seen.get('order_state') == 2 and not s.get('withdraw'):
                action = {'id': 'withdraw', 'label': 'Withdraw ETH'}
            elif seen.get('order_state') in (1, 3) and seen.get('eth_expired') and not s.get('claim') and not s.get('native_refund', {}).get('state') == 'confirmed':
                action = {'id': 'native-refund', 'label': 'Refund my ZEC', 'note': 'No secret was revealed.'} if seen.get('native_refund_ready') else \
                    {'wait': f'ETH order expired. Your ZEC refund unlocks after block #{s["agreement"]["native"]["refund_height"]}.'}
            elif s.get('funding') and not seen.get('order_state'):
                action = {'wait': 'Waiting for Bob to lock the ETH.'}
        else:
            step('trust', 'Trust Alice’s identity', trusted, 'Fingerprints compared out of band.' if trusted else '')
            step('accept', 'Review and accept Alice’s quote', s.get('trade'), self.quote_text(s.get('offer')))
            step('ready', 'My exit verified and saved', (self.me / 'recovery').exists(), 'Claim pre-signed for me; Alice’s refund verified.' if (self.me / 'recovery').exists() else '')
            step('consent', 'Sign the full terms', s.get('consent'))
            step('lock', 'Lock the ETH', s.get('lock'), f'Tx {short(s["lock"]["txid"])}' if s.get('lock') else '')
            claimed = s.get('native_claim', {}).get('state') == 'confirmed'
            if seen.get('order_state') == 3 or (seen.get('order_state') == 1 and seen.get('eth_expired')):
                step('refund', 'No reveal: refund my ETH at expiry', seen.get('order_state') == 3,
                    f'Tx {short(s["refund"]["txid"])}' if s.get('refund') else '')
                step('withdraw', 'Withdraw the refunded ETH', s.get('withdraw'), f'Tx {short(s["withdraw"]["txid"])}' if s.get('withdraw') else '')
            else:
                step('claim', 'Complete my ZEC claim', claimed,
                    f'Tx {short(s["native_claim"]["txid"])} · decrypted by my wallet' if claimed else '')
            if not trusted:
                action = self.trust_action(peer, manifests)
            elif not s.get('offer'):
                action = {'wait': 'Waiting for Alice’s quote.'}
            elif not s.get('trade'):
                action = {'id': 'accept', 'label': 'Accept quote', 'review': s.get('review')}
            elif not (self.me / 'recovery').exists():
                action = {'wait': 'My signer is online. Waiting for Alice to prepare both exits.'}
            elif not s.get('agreement'):
                action = {'wait': 'Waiting for Alice’s full terms.'}
            elif not s.get('consent'):
                action = {'id': 'consent', 'label': 'Sign the full terms', 'terms': self.terms_text(s['agreement'])}
            elif (seen.get('funding_confirmations') or 0) < 2:
                action = {'wait': 'Waiting for Alice’s ZEC funding to confirm.'}
            elif not seen.get('order_state'):
                action = {'id': 'lock', 'label': 'Lock ETH', 'note': f'Locks {self.eth_text(s["agreement"])} for Alice, claimable only with t.'}
            elif seen.get('order_state') == 2 and not claimed:
                action = {'id': 'native-claim', 'label': 'Claim my ZEC', 'danger': True, 'note': 'The secret is public. Claim before the native refund deadline.'}
            elif seen.get('order_state') == 1 and seen.get('eth_expired'):
                action = {'id': 'refund', 'label': 'Refund my ETH', 'note': 'Alice never revealed the secret.'}
            elif seen.get('order_state') == 3 and not s.get('withdraw'):
                action = {'id': 'withdraw', 'label': 'Withdraw refunded ETH'}
            elif seen.get('order_state') == 1:
                action = {'wait': 'ETH locked. Waiting for Alice to claim it.'}
        return {'role': self.role, 'token': self.page_token, 'busy': self.busy, 'error': self.error,
            'me': {'fingerprint': manifest_digest(own), 'address': own['identity']['address']},
            'steps': steps, 'action': action, 'chain': seen, 'relay_count': self.relay_total,
            'shared': self.shared(), 'complete': self.complete(seen)}

    def trust_action(self, peer, manifests):
        if not peer or (self.role == 'bob' and not manifests.get('coordinator')):
            return {'wait': f'Waiting for {self.peer.capitalize()}’s identity on the relay.'}
        action = {'id': 'trust', 'label': f'Fingerprints match: trust {self.peer.capitalize()}',
            'fingerprint': manifest_digest(peer)}
        if self.role == 'bob':
            action['source_fingerprint'] = manifest_digest(manifests['coordinator'])
        return action

    @staticmethod
    def quote_text(offer):
        if not offer:
            return ''
        p = offer['offer']['payload']
        return f'Bob receives {decimal_amount(p["payout_zatoshi"], 8)} ZEC · Alice receives {decimal_amount(p["eth_amount_wei"], 18)} ETH'

    @staticmethod
    def eth_text(agreement):
        return f'{decimal_amount(agreement["amount_wei"], 18)} ETH'

    def terms_text(self, agreement):
        return [f'Escrow {short(agreement["contract"])} (code hash checked)', f'ETH {self.eth_text(agreement)} to Alice {short(agreement["recipient"])}',
            f'ETH expiry at {time.strftime("%H:%M", time.localtime(agreement["eth_expiry"]))} (chain time)', f'ZEC refund unlocks after block #{agreement["native"]["refund_height"]}',
            f'Funding transaction {short(agreement["native"]["funding_txid"])}']

    def shared(self):
        peer = self.peer.capitalize()
        return {'sent': ['Identity fingerprint and ETH address', 'Signed quote or acceptance', 'Signature on the full terms',
            'My one-time ZEC receive address (not a viewing key)'],
            'kept': ['ETH key and FROST share', 'Recovery journals and exits'] + (['The secret t, until I claim'] if self.role == 'alice' else []),
            'peer': peer}

    def complete(self, seen):
        s = self.state
        if self.role == 'alice':
            if s.get('withdraw'):
                return {'title': 'Exchange complete', 'text': f'Received {self.eth_text(s["agreement"])}; withdrawal checked.'}
            if s.get('native_refund', {}).get('state') == 'confirmed':
                return {'title': 'ZEC returned', 'text': 'Prepared refund confirmed and decrypted by my wallet.'}
        elif s.get('native_claim', {}).get('state') == 'confirmed':
            return {'title': 'Exchange complete', 'text': f'Received {decimal_amount(s["native_claim"]["received_zatoshi"], 8)} ZEC, decrypted by my wallet.'}
        elif s.get('withdraw') and seen.get('order_state') == 3:
            return {'title': 'ETH returned', 'text': 'Refunded at expiry and withdrawn.'}
        return None

    def get(self, path, raw):
        if path == '/api/state':
            # Read-only and lock-free, so a long background step never stalls the page.
            try:
                return self.view()
            except (OSError, RuntimeError, KeyError, ValueError) as exc:
                self.log(f'view: {exc!r}')
                return {'role': self.role, 'token': self.page_token, 'offline': True,
                    'busy': self.busy, 'error': 'Network or relay unreachable. Retrying.'}
        return None

    def post(self, path, body, token):
        if path != '/api/act':
            raise ValueError('Not found.')
        with self.lock:
            if self.busy:
                raise ValueError(f'{self.busy} is still running.')
            self.act(body)
            return {'ok': True}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--role', choices=('alice', 'bob'), required=True)
    p.add_argument('--root', type=Path, required=True)
    p.add_argument('--port', type=int, required=True)
    p.add_argument('--network', required=True)
    a = p.parse_args()
    os.umask(0o077)
    app = App(a.role, a.root.resolve(), a.network)

    class Page(Handler):
        page = 'party.html'
    server = ThreadingHTTPServer(('127.0.0.1', a.port), Page)
    server.app = app
    server.serve_forever()


if __name__ == '__main__':
    main()
