#!/usr/bin/env python3
"""Mutually authenticated TLS 1.3 channel to one fixed native signer.

The service owns a fixed role and wallet path. It exposes only the existing
bounded signer protocol, never file operations or arbitrary commands. A pinned
coordinator is authorized to propose transaction graphs; the Rust participant
still checks its own payout and durable signing agreement. This is transport,
not a wallet UI, remote chain verifier, or an OS sandbox.
"""
import argparse
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import select
import socket
import ssl
import stat
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
LIMIT = 200_000
PROTOCOL = 'latch-signer/1'
COMMANDS = {'dkg2', 'dkg3', 'commit', 'sign', 'quit'}


def private_file(path, limit=65536):
    p = Path(path)
    info = p.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > limit or info.st_mode & 0o077:
        raise RuntimeError('private bounded regular file required')
    return p.read_bytes()


def configuration(path):
    cfg = json.loads(private_file(path))
    if cfg['role'] not in (1, 2) or not 1024 <= cfg['port'] <= 65535:
        raise RuntimeError('invalid fixed signer endpoint')
    private_file(cfg['key'])
    # Public certificates may be shared, but private keys and config may not.
    cfg['peer_der'] = ssl.PEM_cert_to_DER_cert(Path(cfg['peer_cert']).read_text())
    cfg['peer_digest'] = hashlib.sha256(cfg['peer_der']).digest()
    return cfg


def context(cfg, server):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER if server else ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(cfg['cert'], cfg['key'])
    ctx.load_verify_locations(cafile=cfg['peer_cert'])
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.set_alpn_protocols([PROTOCOL])
    return ctx


def authenticate(connection, cfg):
    actual = connection.getpeercert(binary_form=True)
    if connection.version() != 'TLSv1.3' or connection.selected_alpn_protocol() != PROTOCOL or not actual or not hmac.compare_digest(hashlib.sha256(actual).digest(), cfg['peer_digest']):
        raise RuntimeError('peer certificate/protocol pin mismatch')


def line(stream):
    value = stream.readline(LIMIT + 1)
    if not value:
        return None
    if len(value) > LIMIT or not value.endswith(b'\n'):
        raise RuntimeError('signer frame bound exceeded')
    packet = json.loads(value)
    if not isinstance(packet, dict):
        raise RuntimeError('signer frame must be an object')
    return value


def child_line(process, timeout=30):
    # The native signer emits one flushed JSON line. Bound both bytes and wait
    # time even if its process stalls or fails midway through a response.
    value = bytearray()
    deadline = time.monotonic() + timeout
    fd = process.stdout.fileno()
    while b'\n' not in value:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([fd], [], [], remaining)[0]:
            raise RuntimeError('native signer response timed out')
        chunk = os.read(fd, min(16384, LIMIT + 1 - len(value)))
        if not chunk:
            raise RuntimeError('native signer rejected request or exited')
        value.extend(chunk)
        if len(value) > LIMIT:
            raise RuntimeError('native signer response too large')
    if value.count(b'\n') != 1 or not value.endswith(b'\n') or not isinstance(json.loads(value), dict):
        raise RuntimeError('unexpected native signer response')
    return bytes(value)


def serve(path):
    cfg = configuration(path)
    ctx = context(cfg, True)
    # A per-wallet lock prevents two authenticated sessions using one signer
    # concurrently, even if separately configured services target that wallet.
    wallet = Path(cfg['wallet']).resolve()
    lock_path = wallet.parent / (wallet.name + '.service.lock')
    with socket.socket() as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((cfg.get('bind', '127.0.0.1'), cfg['port']))
        listener.listen(4)
        print(json.dumps({'ready': True, 'role': cfg['role'], 'port': cfg['port']}), flush=True)
        while True:
            raw, _ = listener.accept()
            process = None
            lock = None
            try:
                raw.settimeout(10)
                with ctx.wrap_socket(raw, server_side=True) as connection:
                    authenticate(connection, cfg)  # Before touching signer state.
                    connection.settimeout(300)
                    lock_path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
                    lock = lock_path.open('a')
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    process = subprocess.Popen([cfg['binary'], 'participant', str(wallet), str(cfg['role'])],
                        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                        bufsize=0, env=dict(os.environ, RAYON_NUM_THREADS='2'))
                    hello = json.loads(child_line(process))
                    envelope = {'protocol': PROTOCOL, 'role': cfg['role'], 'hello': hello}
                    connection.sendall(json.dumps(envelope).encode() + b'\n')
                    with connection.makefile('rb') as stream:
                        while (packet := line(stream)) is not None:
                            request = json.loads(packet)
                            if request.get('command') not in COMMANDS:
                                raise RuntimeError('unsupported signer operation')
                            remaining = memoryview(packet)
                            while remaining:
                                written = process.stdin.write(remaining)
                                if not written:
                                    raise RuntimeError('native signer input ended')
                                remaining = remaining[written:]
                            if request['command'] == 'quit':
                                process.wait(timeout=10)
                                break
                            connection.sendall(child_line(process))
            except (OSError, RuntimeError, ValueError, RecursionError, subprocess.SubprocessError):
                # Never serialize errors containing keys, PCZTs or peer input.
                print(json.dumps({'connection_closed': True, 'role': cfg['role']}), flush=True)
            finally:
                raw.close()
                if process is not None:
                    if process.poll() is None:
                        process.kill()
                    process.wait()
                if lock is not None:
                    lock.close()


def connect(path):
    cfg = configuration(path)
    ctx = context(cfg, False)
    with socket.create_connection((cfg['host'], cfg['port']), timeout=10) as raw:
        with ctx.wrap_socket(raw, server_hostname=cfg['server_name']) as connection:
            authenticate(connection, cfg)
            connection.settimeout(300)
            with connection.makefile('rb') as stream:
                envelope = json.loads(line(stream) or b'{}')
                if envelope.get('protocol') != PROTOCOL or envelope.get('role') != cfg['role']:
                    raise RuntimeError('signer role/protocol mismatch')
                sys.stdout.buffer.write(json.dumps(envelope['hello']).encode() + b'\n')
                sys.stdout.buffer.flush()
                while (packet := line(sys.stdin.buffer)) is not None:
                    command = json.loads(packet).get('command')
                    if command not in COMMANDS:
                        raise RuntimeError('unsupported signer operation')
                    connection.sendall(packet)
                    if command == 'quit':
                        return
                    response = line(stream)
                    if response is None:
                        raise RuntimeError('signer connection ended')
                    sys.stdout.buffer.write(response)
                    sys.stdout.buffer.flush()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['serve', 'connect'])
    parser.add_argument('config', type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    try:
        (serve if args.action == 'serve' else connect)(args.config)
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError):
        print('Authenticated signer transport failed; private state preserved.', file=sys.stderr)
        raise SystemExit(1)
