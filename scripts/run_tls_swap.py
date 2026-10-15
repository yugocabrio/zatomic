#!/usr/bin/env python3
"""Exercise the real local swap over mutually authenticated signer channels.

Generates disposable fixture identities on this host. Operators on separate
hosts must generate their own identities and authenticate certificate pins out
of band; this fixture does not establish independent operation or remote wallet
artifact distribution. No listeners are bound beyond loopback.
"""
import argparse
import contextlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
from regtest_node import ROOT
from regtest_wallet import save


def configure(directory, run):
    directory.mkdir(mode=0o700)
    for name in ('alice', 'bob', 'coordinator'):
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
            '-nodes', '-sha256', '-days', '2', '-subj', f'/CN=latch-{name}',
            '-addext', f'subjectAltName=DNS:latch-{name}',
            '-addext', 'extendedKeyUsage=serverAuth,clientAuth',
            '-addext', 'basicConstraints=critical,CA:FALSE',
            '-keyout', str(directory / f'{name}.key'), '-out', str(directory / f'{name}.pem')],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    commands = {}
    for role, name in enumerate(('alice', 'bob'), 1):
        server = {'role': role, 'port': 18640 + role, 'bind': '127.0.0.1',
            'cert': str(directory / f'{name}.pem'), 'key': str(directory / f'{name}.key'),
            'peer_cert': str(directory / 'coordinator.pem'),
            'wallet': str(run / 'swap' / name), 'binary': str(ROOT / 'target/release/shielded-swap-native')}
        client = {'role': role, 'port': server['port'], 'host': '127.0.0.1', 'server_name': f'latch-{name}',
            'cert': str(directory / 'coordinator.pem'), 'key': str(directory / 'coordinator.key'),
            'peer_cert': str(directory / f'{name}.pem')}
        save(directory / f'{name}-server.json', server)
        save(directory / f'{name}-client.json', client)
        commands[name] = [sys.executable, str(ROOT / 'scripts/signer_transport.py'), 'connect', str(directory / f'{name}-client.json')]
    save(directory / 'commands.json', commands)
    return directory / 'commands.json'


@contextlib.contextmanager
def services(directory):
    children = []
    try:
        for name in ('alice', 'bob'):
            process = subprocess.Popen([sys.executable, str(ROOT / 'scripts/signer_transport.py'), 'serve', str(directory / f'{name}-server.json')],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
            children.append(process)
            ready = process.stdout.readline()
            if not ready or not json.loads(ready).get('ready'):
                raise RuntimeError('owned authenticated signer service failed to start')
        yield
    finally:
        for process in children:
            # Only process groups created above; never a shared service or node.
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()


def run(mode, directory, existing_bank=None):
    transport = directory.with_name(directory.name + '-transport')
    commands = configure(transport, directory)
    with services(transport):
        args = [sys.executable, str(ROOT / 'scripts/run_regtest_swap.py'), mode, str(directory)]
        if existing_bank:
            args.extend(['--existing-bank', str(existing_bank)])
        subprocess.run(args, check=True, cwd=ROOT,
            env=dict(os.environ, LATCH_SIGNER_COMMANDS=str(commands), RAYON_NUM_THREADS='2'))
    result = json.loads((directory / '08-complete.json').read_text())
    return {'scope': 'actual chain swap via TLS 1.3 signer services on one host',
        'mutual_certificate_pins': True, 'role_and_protocol_checked': True,
        'independent_hosts': False, 'remote_wallet_distribution': False, 'swap': result}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['success', 'refund'])
    parser.add_argument('directory', type=Path)
    parser.add_argument('--existing-bank', type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    print(json.dumps(run(args.mode, args.directory.resolve(), args.existing_bank.resolve() if args.existing_bank else None), indent=2))
