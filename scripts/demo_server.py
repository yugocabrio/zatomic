#!/usr/bin/env python3
"""Latch local control panel. Only disposable, owned chains; never serves wallets."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import threading
import time
import demo_otc
from otc_offer import decimal_amount
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit
from regtest_node import ROOT, status as node_status

DEMO = ROOT / '.local/demo'
WEB = ROOT / 'web'
SCENARIOS = {'success': ('success', None), 'claim-stop': ('success', 'eth-claimed'),
             'refund-stop': ('refund', 'eth-locked')}
STAGES = ('00-funding-preview-rejected', '01-prepared', '01-consented', '01-authorized', '02-funded', '03-early-refund-rejected', '04-eth-locked',
          '05-eth-claimed', '05-eth-refunded', '06-zec-claimed', '06-zec-refunded',
          '07-conflicting-refund-rejected', '08-complete', '09-recovered')
PUBLIC_EVIDENCE = {p.name: p for p in (ROOT / 'evidence').glob('*.json')}
# Any of these means funds or a source reservation may exist: such a run must be
# recovered (or cancelled) before either chain advances for a new offer.
COMMITTED = ('source-setup.json', 'swap/terms.json', '02-funded.json', 'owner-flow.json')
# Fields stored in job.json. Everything else in a snapshot is derived from the
# run directory on every read, so stale derived flags are never persisted.
PERSISTED = ('id', 'state', 'quote', 'driver', 'scenario', 'started_at', 'recovery_started_at', 'updated_at', 'exit_code')
QUOTE_BINDING = ('zec_amount', 'eth_amount', 'quote_digest', 'alice_signed', 'bob_accepted')


def persisted(job):
    return {key: job[key] for key in PERSISTED if key in job}


def atomic(path, value):
    temporary = path.with_suffix('.tmp')
    with temporary.open('w') as handle:
        json.dump(value, handle, sort_keys=True)
        handle.flush()
        os.fsync(handle.fileno())
    temporary.replace(path)
    fd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def driver_busy():
    with (ROOT / '.local/chain-driver.lock').open('a') as handle:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return True
        return False


class Manager:
    def __init__(self):
        DEMO.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self.worker = None
        self.token = secrets.token_urlsafe(32)
        self.node = {'available': False}
        self.node_at = 0
        self.check_node()

    def check_node(self):
        if time.monotonic() - self.node_at > 3:
            try:
                info = node_status()
                self.node = {'available': True, 'height': info['blocks'], 'network': 'Zebra NU7 regtest'}
            except Exception:
                self.node = {'available': False, 'network': 'Zebra NU7 regtest'}
            self.node_at = time.monotonic()

    def records(self):
        return sorted(DEMO.glob('*/job.json'), key=lambda p: p.parent.name, reverse=True)

    def one(self, path):
        job = json.loads(path.read_text())
        run = path.parent / 'run'
        job['events'] = []
        for name in STAGES:
            p = run / f'{name}.json'
            if p.exists():
                # Only these deliberately public stage records. Never terms,
                # PCZT, note data, wallet directories, logs or EVM snapshots.
                try:
                    value = json.loads(p.read_text())
                except json.JSONDecodeError:
                    continue  # An immutable stage file may still be flushing.
                job['events'].append({'stage': name, 'value': value})
        if job['state'] in ('running', 'recovering') and (self.worker is None or not self.worker.is_alive()) and not driver_busy():
            job['state'] = 'complete' if any(e['stage'] == '08-complete' for e in job['events']) else 'interrupted'
        if job['state'] == 'complete' and not any(e['stage'] == '08-complete' for e in job['events']):
            job['state'] = 'interrupted'
        if job.get('driver') in ('owner-consent-v2', 'owner-consent-v3'):
            checkpoint = all((run / name).exists() for name in ('owner-flow.json',
                'consent-packet.json', 'evm-checkpoint.json', 'coordinator-native-offline/funding.hex'))
        elif job.get('driver') == 'owner-clients-v1':
            checkpoint = all((run / name).exists() for name in ('owner-flow.json',
                'agreement.json', 'evm-checkpoint.json', 'owners/bob/eth-intent-lock.json'))
        else:
            checkpoint = (run / '04-eth-locked.json').exists()
            checkpoint |= all((run / name).exists() for name in ('agreement.json', 'evm-checkpoint.json', 'evm-outgoing'))
            checkpoint |= (run / 'swap/terms.json').exists() and not (run / 'agreement.json').exists()
        job['cancellable_setup'] = (job.get('driver') == 'owner-consent-v3'
            and (run / 'source-setup.json').is_file() and not (run / 'source-release.json').exists()
            and job['state'] != 'complete')
        if job.get('driver') == 'owner-consent-v3':
            checkpoint |= (run / 'source-release.json').exists()
        checkpoint |= job['cancellable_setup']
        job['recoverable'] = checkpoint and job['state'] not in ('running', 'recovering')
        job['blocks_new_offer'] = job['state'] != 'complete' and any((run / name).exists() for name in COMMITTED)
        job['eth_setup_started'] = (run / 'agreement.json').exists()
        # Existence-only progress inside the long first stage. No file content,
        # names of private artifacts or paths leave the server.
        # The intent flags tell the browser which recovery route applies: a
        # claim intent means the witness may be public, so no refund fallback.
        job['milestones'] = {'setup_started': (run / 'setup.json').exists(),
            'dkg_complete': any((run / d / 'joint-fvk.bin').exists() for d in ('swap', 'coordinator-native-offline')),
            'escrow_deployed': (run / 'agreement.json').exists(),
            'source_released': (run / 'source-release.json').exists(),
            'lock_intent': (run / 'owners/bob/eth-intent-lock.json').exists(),
            'claim_intent': (run / 'owners/alice/eth-intent-claim.json').exists()}
        complete = next((e['value'] for e in job['events'] if e['stage'] == '08-complete'), {})
        if 'native_amount_zatoshi' in complete and 'eth_wei_received' in complete:
            job['settled_amounts'] = {'zec': decimal_amount(complete['native_amount_zatoshi'], 8),
                'eth': decimal_amount(complete['eth_wei_received'], 18)}
        return job

    def snapshot(self):
        with self.lock:
            self.check_node()
            jobs = [self.one(p) for p in self.records()[:30]]
            ready = self.node['available'] and (ROOT / 'target/release/shielded-swap-native').is_file() and (ROOT / '.local/forge-out/PointEscrow.sol/PointEscrow.json').is_file() and bool(shutil.which('anvil')) and bool(shutil.which('cast'))
            # Probing takes the driver flock for an instant; never do it while our
            # own runner may be acquiring it, or that runner could fail to start.
            busy = (self.worker is not None and self.worker.is_alive()) or driver_busy()
            return {'token': self.token, 'node': self.node, 'ready': ready,
                    'busy': busy, 'jobs': jobs,
                    'evidence': sorted(PUBLIC_EVIDENCE),
                    'scope': 'Real transactions on isolated local chains. No mainnet or public-testnet claim.'}

    def quote_path(self, identifier):
        if not isinstance(identifier, str) or not re.fullmatch(r'\d{13}-[a-f0-9]{8}', identifier):
            raise ValueError('Unknown offer.')
        path = DEMO / identifier / 'job.json'
        if not path.is_file(): raise ValueError('Unknown offer.')
        return path

    def create_offer(self, body):
        with self.lock:
            if self.worker is not None and self.worker.is_alive() or driver_busy():
                raise ValueError('A chain operation is active.')
            if any(self.one(old)['blocks_new_offer'] for old in self.records()):
                raise ValueError('Recover the existing run before creating another offer.')
            # Canonical parser rejects floats, exponents and excess precision.
            demo_otc.otc_offer.units(body.get('zec_amount'), 8, 100_000_000)
            demo_otc.otc_offer.units(body.get('eth_amount'), 18, 10*10**18)
            identifier = f'{int(time.time()*1000):013d}-{secrets.token_hex(4)}'
            folder = DEMO / identifier; folder.mkdir(mode=0o700)
            summary = demo_otc.create(folder / 'quote', body['zec_amount'], body['eth_amount'])
            atomic(folder / 'job.json', {'id': identifier, 'state': 'offered', 'quote': summary,
                'driver': 'owner-consent-v3', 'scenario': 'success', 'started_at': int(time.time())})
            return identifier

    def accept_offer(self, identifier):
        with self.lock:
            path = self.quote_path(identifier); job = self.one(path)
            if job['state'] not in ('offered', 'accepted'):
                raise ValueError('Only an unfunded offer can be accepted.')
            job['quote'] = demo_otc.accept(path.parent / 'quote')
            job['state'] = 'accepted'
            atomic(path, persisted(job))
            return identifier

    def start(self, scenario, recovery_id=None, quote_id=None):
        with self.lock:
            if self.worker is not None and self.worker.is_alive() or driver_busy():
                raise ValueError('Another chain operation is active. Let it finish before starting another.')
            if recovery_id:
                if not re.fullmatch(r'\d{13}-[a-f0-9]{8}', recovery_id):
                    raise ValueError('Unknown run.')
                path = DEMO / recovery_id / 'job.json'
                if not path.is_file():
                    raise ValueError('Unknown run.')
                job = self.one(path)
                if not job['recoverable']:
                    raise ValueError('No supported recovery checkpoint. See the local recovery guide.')
                job.update(state='recovering', recovery_started_at=int(time.time()))
                if job.get('driver') in ('owner-consent-v2','owner-consent-v3'):
                    args = ['python3', str(ROOT / 'scripts/prefunding_swap.py'), 'recover', str(path.parent / 'run')]
                elif job.get('driver') == 'owner-clients-v1':
                    args = ['python3', str(ROOT / 'scripts/owner_swap.py'), 'recover', str(path.parent / 'run')]
                else:
                    args = ['python3', str(ROOT / 'scripts/recover_regtest_swap.py'), str(path.parent / 'run')]
            else:
                if scenario not in SCENARIOS:
                    raise ValueError('Choose one of the three supported scenarios.')
                if not self.snapshot()['ready']:
                    raise ValueError('Local dependencies are not ready. Follow docs/reproduce.md.')
                if any(self.one(old)['blocks_new_offer'] for old in self.records()):
                    raise ValueError('Recover the existing funded run before advancing either chain.')
                path = self.quote_path(quote_id)
                job = self.one(path)
                if job['state'] != 'accepted' or not job.get('quote', {}).get('bob_accepted'):
                    raise ValueError('Bob must review and accept the signed offer before funding.')
                folder = path.parent
                summary = demo_otc.describe(folder / 'quote')
                if (any(summary.get(k) != job['quote'].get(k) for k in QUOTE_BINDING)
                        or not summary['bob_accepted']):
                    raise ValueError('Accepted offer changed; no funding authorized.')
                job.update(scenario=scenario, state='running', started_at=int(time.time()))
                job.pop('updated_at', None)
                job.pop('recovery_started_at', None)
                mode, fault = SCENARIOS[scenario]
                args = ['python3', str(ROOT / 'scripts/prefunding_swap.py'), mode, str(folder / 'run'),
                        '--accepted-quote', str(folder / 'quote')]
                # Every run funds its own source note. Its refund auxiliary is
                # created from that run's funding change, only if it refunds.
                if fault:
                    args += ['--fault-after', fault]
            job = persisted(job)
            atomic(path, job)
            self.worker = threading.Thread(target=self.execute, args=(path, job, args), daemon=True)
            self.worker.start()
            return job['id']

    def execute(self, path, job, args):
        # Runner output goes to a private log, never to an API or the browser.
        try:
            with (path.parent / 'runner.log').open('a') as log:
                result = subprocess.run(args, cwd=ROOT, stdout=log, stderr=log,
                                        env=dict(os.environ, RAYON_NUM_THREADS='2'))
            state = {0: 'complete', 75: 'interrupted'}.get(result.returncode, 'error')
            code = result.returncode
        except Exception:
            state, code = 'error', -1
        with self.lock:
            job.update(state=state, exit_code=code, updated_at=int(time.time()))
            atomic(path, job)


class Handler(BaseHTTPRequestHandler):
    server_version = 'LatchLocal/0.1'

    def log_message(self, fmt, *args):
        pass  # Keep tokens/identifiers out of shared server output.

    def send(self, code, data, kind='application/json'):
        if not isinstance(data, bytes):
            data = json.dumps(data).encode()
        self.send_response(code)
        self.send_header('Content-Type', kind)
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
        self.end_headers()
        self.wfile.write(data)

    def domain_ok(self):
        port = self.server.server_address[1]
        host = self.headers.get('Host', '')
        origin = self.headers.get('Origin')
        allowed = {f'127.0.0.1:{port}', f'localhost:{port}'}
        return host in allowed and (origin is None or origin in {f'http://{h}' for h in allowed})

    def do_GET(self):
        if not self.domain_ok():
            return self.send(403, {'error': 'Local origin required.'})
        path = urlsplit(self.path).path
        files = {'/': ('index.html', 'text/html; charset=utf-8'),
                 '/app.js': ('app.js', 'application/javascript'),
                 '/style.css': ('style.css', 'text/css; charset=utf-8'),
                 '/favicon.svg': ('favicon.svg', 'image/svg+xml'),
                 '/mark.svg': ('mark.svg', 'image/svg+xml')}
        if path in files:
            name, kind = files[path]
            return self.send(200, (WEB / name).read_bytes(), kind)
        if path == '/api/state':
            return self.send(200, self.server.manager.snapshot())
        if path.startswith('/api/evidence/'):
            name = path.removeprefix('/api/evidence/')
            if name in PUBLIC_EVIDENCE:
                return self.send(200, PUBLIC_EVIDENCE[name].read_bytes())
        return self.send(404, {'error': 'Not found.'})

    def do_POST(self):
        if not self.domain_ok() or self.headers.get('X-Latch-Token', '') != self.server.manager.token:
            return self.send(403, {'error': 'Local session required.'})
        if self.headers.get('Content-Type') != 'application/json':
            return self.send(415, {'error': 'JSON required.'})
        try:
            length = int(self.headers.get('Content-Length', '0'))
            if not 0 < length <= 4096:
                raise ValueError('Invalid request size.')
            body = json.loads(self.rfile.read(length))
            if not isinstance(body, dict):
                raise ValueError('JSON object required.')
            if self.path == '/api/start':
                job = self.server.manager.start(body.get('scenario'), quote_id=body.get('id'))
            elif self.path == '/api/offer':
                job = self.server.manager.create_offer(body)
            elif self.path == '/api/accept':
                job = self.server.manager.accept_offer(body.get('id'))
            elif self.path == '/api/recover':
                job = self.server.manager.start(None, body.get('id'))
            else:
                return self.send(404, {'error': 'Not found.'})
            return self.send(202, {'id': job})
        except (RuntimeError, OSError, subprocess.SubprocessError):
            return self.send(409, {'error': 'Owner operation refused. Private state retained; no new funding authorized.'})
        except (ValueError, TypeError) as exc:
            return self.send(409, {'error': str(exc)})


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', type=int, default=8787)
    args = parser.parse_args()
    os.umask(0o077)
    manager = Manager()
    with ThreadingHTTPServer(('127.0.0.1', args.port), Handler) as server:
        server.manager = manager
        print(f'Latch local demo: http://127.0.0.1:{args.port}', flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
