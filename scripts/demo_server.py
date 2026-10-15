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
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit
from regtest_node import ROOT, status as node_status

DEMO = ROOT / '.local/demo'
WEB = ROOT / 'web'
SCENARIOS = {'success': ('success', None), 'claim-stop': ('success', 'eth-claimed'),
             'refund-stop': ('refund', 'eth-locked')}
STAGES = ('01-prepared', '02-funded', '03-early-refund-rejected', '04-eth-locked',
          '05-eth-claimed', '05-eth-refunded', '06-zec-claimed', '06-zec-refunded',
          '07-conflicting-refund-rejected', '08-complete', '09-recovered')
PUBLIC_EVIDENCE = {p.name: p for p in (ROOT / 'evidence').glob('*.json')}


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
            job['state'] = 'complete' if (run / '08-complete.json').exists() else 'interrupted'
        checkpoint = (run / '04-eth-locked.json').exists()
        native_only = (run / 'swap/terms.json').exists() and not (run / 'agreement.json').exists()
        job['recoverable'] = (checkpoint or native_only) and job['state'] not in ('running', 'recovering')
        return job

    def snapshot(self):
        with self.lock:
            self.check_node()
            jobs = [self.one(p) for p in self.records()[:30]]
            ready = self.node['available'] and (ROOT / 'target/release/shielded-swap-native').is_file() and (ROOT / '.local/forge-out/PointEscrow.sol/PointEscrow.json').is_file() and bool(shutil.which('anvil')) and bool(shutil.which('cast'))
            return {'token': self.token, 'node': self.node, 'ready': ready,
                    'busy': driver_busy(), 'jobs': jobs,
                    'evidence': sorted(PUBLIC_EVIDENCE),
                    'scope': 'Real transactions on isolated local chains. No mainnet or public-testnet claim.'}

    def start(self, scenario, recovery_id=None):
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
                    raise ValueError('This run has no recoverable ETH checkpoint. See the local recovery guide.')
                job.pop('events', None)
                job.pop('recoverable', None)
                job['state'] = 'recovering'
                args = ['python3', str(ROOT / 'scripts/recover_regtest_swap.py'), str(path.parent / 'run')]
            else:
                if scenario not in SCENARIOS:
                    raise ValueError('Choose one of the three supported scenarios.')
                if not self.snapshot()['ready']:
                    raise ValueError('Local dependencies are not ready. Follow docs/reproduce.md.')
                for old in self.records():
                    recorded = self.one(old)
                    if recorded['state'] != 'complete' and (old.parent / 'run/swap/terms.json').exists():
                        raise ValueError('Recover the existing funded run before advancing either chain.')
                job_id = f'{int(time.time()*1000):013d}-{secrets.token_hex(4)}'
                folder = DEMO / job_id
                folder.mkdir(mode=0o700)
                path = folder / 'job.json'
                job = {'id': job_id, 'scenario': scenario, 'state': 'running', 'started_at': int(time.time())}
                mode, fault = SCENARIOS[scenario]
                args = ['python3', str(ROOT / 'scripts/run_regtest_swap.py'), mode, str(folder / 'run')]
                if fault:
                    args += ['--fault-after', fault]
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
                 '/favicon.svg': ('favicon.svg', 'image/svg+xml')}
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
                job = self.server.manager.start(body.get('scenario'))
            elif self.path == '/api/recover':
                job = self.server.manager.start(None, body.get('id'))
            else:
                return self.send(404, {'error': 'Not found.'})
            return self.send(202, {'id': job})
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
