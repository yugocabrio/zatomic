#!/usr/bin/env python3
"""Adversarial TLS checks using actual persisted native signers, no broadcast.

The supplied fixture must already be completed. A fresh nonce attempt is
reserved then abandoned to check replay protection across TLS reconnects.
"""
import argparse
import copy
import fcntl
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
from run_tls_swap import configure, services
from signer_transport import PROTOCOL, authenticate, configuration, context


def opened(cfg, ctx=None, hostname=None):
    raw = socket.create_connection((cfg['host'], cfg['port']), timeout=5)
    try:
        connection = (ctx or context(cfg, False)).wrap_socket(raw, server_hostname=hostname or cfg['server_name'])
        connection.settimeout(5)
        return connection
    except Exception:
        raw.close()
        raise


def reject(cfg, ctx=None, hostname=None, packet=None):
    try:
        with opened(cfg, ctx, hostname) as connection:
            if packet is not None:
                with connection.makefile('rb') as stream:
                    assert stream.readline(), 'authenticated hello expected before malformed request'
                    connection.sendall(packet)
                    assert stream.readline() == b'', 'unexpected response to forbidden frame'
                return
            assert connection.recv(1) == b'', 'unexpected unauthenticated application data'
    except (ssl.SSLError, ConnectionResetError, BrokenPipeError):
        return


def client(folder, name):
    process = subprocess.Popen([sys.executable, 'scripts/signer_transport.py', 'connect', str(folder / f'{name}-client.json')],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    hello = process.stdout.readline()
    if not hello or not json.loads(hello).get('resumed'):
        process.kill(); process.wait()
        raise AssertionError('actual signer did not resume over TLS')
    return process


def run(run_directory, folder):
    assert (run_directory / '08-complete.json').exists(), 'completed fixture required'
    configure(folder, run_directory)
    before = {name: sorted(p.name for p in (run_directory / 'swap' / name).glob('attempt-*.json')) for name in ('alice','bob')}
    rejected = []
    with services(folder):
        cfg = configuration(folder / 'alice-client.json')
        no_cert = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        no_cert.minimum_version = ssl.TLSVersion.TLSv1_3
        no_cert.load_verify_locations(cafile=cfg['peer_cert'])
        no_cert.set_alpn_protocols([PROTOCOL])
        reject(cfg, no_cert); rejected.append('missing client certificate')
        wrong = dict(cfg, cert=str(folder / 'bob.pem'), key=str(folder / 'bob.key'))
        reject(cfg, context(wrong, False)); rejected.append('untrusted client certificate')
        wrong = dict(cfg, peer_cert=str(folder / 'bob.pem'))
        reject(cfg, context(wrong, False)); rejected.append('untrusted server certificate')
        reject(cfg, hostname='not-latch'); rejected.append('server hostname mismatch')
        no_protocol = context(cfg, False)
        no_protocol.set_alpn_protocols(['other-protocol'])
        reject(cfg, no_protocol); rejected.append('application protocol mismatch')
        pin = dict(cfg, peer_digest=b'\0' * 32)
        with opened(cfg) as connection:
            try:
                authenticate(connection, pin)
            except RuntimeError:
                rejected.append('exact certificate pin mismatch')
            else:
                raise AssertionError('wrong exact pin accepted')
        reject(cfg, packet=b'{"command":"read_file","path":"spending-key.bin"}\n')
        rejected.append('unsupported file operation')
        reject(cfg, packet=b' ' * 200001 + b'\n'); rejected.append('oversized frame')
        for name in ('alice','bob'):
            assert before[name] == sorted(p.name for p in (run_directory/'swap'/name).glob('attempt-*.json'))
        # A second service/config cannot use this wallet while its lock is held.
        wallet = run_directory/'swap/alice'
        with (wallet.parent/'alice.service.lock').open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            reject(cfg)
        rejected.append('concurrent use of signer state')
        # Verify the bridge's endpoint-role check on an existing safe journal.
        wrong_cfg = json.loads((folder/'alice-client.json').read_text())
        wrong_cfg['role'] = 2
        path = folder/'wrong-role.json'
        path.write_text(json.dumps(wrong_cfg))
        result = subprocess.run([sys.executable,'scripts/signer_transport.py','connect',str(path)],input='',capture_output=True,text=True,timeout=10)
        assert result.returncode != 0 and not result.stdout
        rejected.append('configured signer role mismatch')
        swap = run_directory/'swap'
        policy = json.loads((swap/'claim-policy.json').read_text())
        pre = json.loads((swap/'bob/presignature.json').read_text())
        policy['session'] = os.urandom(32).hex()
        packet = {'command':'commit','policy':policy,'adaptor_point':pre['adaptor_point'],
                  'pczt':(swap/'bob/claim.pczt').read_bytes().hex()}
        first = client(folder, 'bob')
        try:
            first.stdin.write(json.dumps(packet)+'\n'); first.stdin.flush()
            reply = json.loads(first.stdout.readline())
            marker = swap/'bob'/f'attempt-{policy["session"]}.json'
            assert json.loads(marker.read_text())['message'] == reply['message']
        finally:
            first.kill(); first.wait()
        second = client(folder, 'bob')
        try:
            out, _ = second.communicate(json.dumps(packet)+'\n', timeout=10)
            assert second.returncode != 0 and not out
        finally:
            if second.poll() is None:
                second.kill(); second.wait()
        rejected.append('nonce attempt replay after TLS disconnect')
    return {'scope':'actual TLS 1.3 and native signer processes on one host; no chain mutation',
        'mutual_authentication':True, 'unknown_peers_receive_no_application_data':True,
        'nonce_reserved_before_response':True, 'rejected':rejected,
        'independent_host_execution':False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('completed_run',type=Path)
    parser.add_argument('new_transport_directory',type=Path)
    args=parser.parse_args()
    os.umask(0o077)
    print(json.dumps(run(args.completed_run.resolve(),args.new_transport_directory.resolve()),indent=2))
