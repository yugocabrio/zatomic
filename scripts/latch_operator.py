#!/usr/bin/env python3
"""Portable Latch operator commands for the isolated chain profile.

Each operator invokes this locally with only their own state directory. Exchange
public identity manifests over an authenticated channel and verify fingerprints
before trust/register. Native preparation uses the existing pinned TLS channel;
ETH signing and settlement are never exposed as remotely callable services.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import ssl
import subprocess
import sys
import time
import evm_wallet
import native_funding
import otc_offer
from evm_participant import read
from funding_wallet import authorize
from regtest_node import ROOT, rpc
from regtest_wallet import native, save, funding_capture
from run_client_swap import client

ROLES = ('alice', 'bob')
OPERATIONS = ('init', 'identity', 'trust-coordinator', 'trust-peer', 'register-owner',
    'serve', 'ready', 'stage', 'consent', 'source-fund', 'lock', 'claim', 'refund',
    'withdraw', 'native-claim', 'native-refund', 'offer-create', 'offer-review', 'offer-accept')


def manifest_digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def validate_manifest(value, role):
    if value['version'] != 1 or value['role'] != role or role not in (*ROLES, 'coordinator'):
        raise RuntimeError('unexpected operator identity role')
    cert = value['certificate_pem']
    if len(cert) > 16_384 or hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert)).hexdigest() != value['certificate_sha256']:
        raise RuntimeError('operator certificate fingerprint mismatch')
    if role in ROLES:
        identity = value['identity']
        public = bytes.fromhex(identity['public_key'])
        if (len(public) != 65 or public[0] != 4 or identity['role'] != role or identity['chain_id'] != 31338
                or identity['address'] != '0x' + evm_wallet.keccak(public[1:])[-20:].hex()):
            raise RuntimeError('operator ETH identity mismatch')
        prime = 2**256 - 2**32 - 977
        x, y = int.from_bytes(public[1:33]), int.from_bytes(public[33:])
        if x >= prime or y >= prime or (y*y - x*x*x - 7) % prime:
            raise RuntimeError('operator ETH public key not on curve')
        if 'relay_public_key' in value and not compressed_point(value['relay_public_key']):
            raise RuntimeError('operator relay key not on curve')
    return value


def compressed_point(text):
    """A compressed secp256k1 point, checked without trusting the sender."""
    raw = bytes.fromhex(text) if isinstance(text, str) and len(text) == 66 else b''
    if len(raw) != 33 or raw[0] not in (2, 3):
        return False
    prime = 2**256 - 2**32 - 977
    x = int.from_bytes(raw[1:])
    rhs = (x*x*x + 7) % prime
    return x < prime and pow(rhs, (prime + 1) // 4, prime)**2 % prime == rhs


def initialize(directory, role):
    if role == 'coordinator':
        native('regtest-setup-init', directory)
    else:
        directory.mkdir(mode=0o700)
        client('key-init', directory, role=role)
    tls = directory / 'tls'
    tls.mkdir(mode=0o700)
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
        '-nodes', '-sha256', '-days', '30', '-subj', f'/CN=latch-{role}',
        '-addext', f'subjectAltName=DNS:latch-{role}', '-addext', 'extendedKeyUsage=serverAuth,clientAuth',
        '-addext', 'basicConstraints=critical,CA:FALSE',
        '-keyout', str(tls / 'identity.key'), '-out', str(tls / 'identity.pem')],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    pem = (tls / 'identity.pem').read_text()
    value = {'version': 1, 'role': role, 'certificate_pem': pem,
        'certificate_sha256': hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem)).hexdigest()}
    if role in ROLES:
        value['identity'] = read(directory / 'identity.json')
        # Separate from the ETH key; the compared fingerprint pins it too.
        value['relay_public_key'] = native('relay-key-init', directory)['relay_public_key']
    save(directory / 'operator-public.json', value)
    return value


def pin(directory, name, packet, role):
    value = validate_manifest(packet['manifest'], role)
    # The expected hash must come from the operator's authenticated exchange,
    # not be copied blindly from an unauthenticated incoming offer.
    if packet['expected_manifest_sha256'] != manifest_digest(value):
        raise RuntimeError('operator fingerprint differs from trusted input')
    save(directory / name, value)
    return value


def configure_owner(directory, packet, own):
    peer = pin(directory, 'trusted-coordinator.json', packet, 'coordinator')
    certificate = directory / 'tls/coordinator.pem'
    if certificate.exists() and certificate.read_text() != peer['certificate_pem']:
        raise RuntimeError('coordinator certificate changed')
    certificate.write_text(peer['certificate_pem'])
    port = packet['port']
    if type(port) is not int or not 1024 <= port <= 65535:
        raise RuntimeError('invalid local signer port')
    config = {'role': 1 if own['role'] == 'alice' else 2, 'bind': '127.0.0.1', 'port': port,
        'cert': str(directory / 'tls/identity.pem'), 'key': str(directory / 'tls/identity.key'),
        'peer_cert': str(certificate), 'wallet': str(directory / 'native'),
        'binary': str(ROOT / 'target/release/shielded-swap-native')}
    save(directory / 'signer-server.json', config)
    return {'configured': True, 'role': own['role'], 'loopback_only': True}


def register_owner(directory, packet):
    role = packet['manifest']['role']
    if role not in ROLES:
        raise RuntimeError('expected Alice or Bob')
    peer = pin(directory, role + '-public.json', packet, role)
    host, port = packet['host'], packet['port']
    if not isinstance(host, str) or not host or len(host) > 253 or type(port) is not int or not 1024 <= port <= 65535:
        raise RuntimeError('invalid signer endpoint')
    certificate = directory / 'tls' / (role + '.pem')
    if certificate.exists() and certificate.read_text() != peer['certificate_pem']:
        raise RuntimeError('owner certificate changed')
    certificate.write_text(peer['certificate_pem'])
    save(directory / (role + '-client.json'), {'role': 1 if role == 'alice' else 2,
        'host': host, 'port': port, 'server_name': 'latch-' + role,
        'cert': str(directory / 'tls/identity.pem'), 'key': str(directory / 'tls/identity.key'),
        'peer_cert': str(certificate)})
    return {'registered': role, 'manifest_sha256': manifest_digest(peer)}


def execute(directory, action, packet):
    own = read(directory / 'operator-public.json')
    role = own['role']
    if action == 'identity':
        return dict(manifest=own, manifest_sha256=manifest_digest(own))
    if action in ('register-owner', 'stage', 'source-fund'):
        if role != 'coordinator':
            raise RuntimeError('source operator command required')
        if action == 'register-owner':
            return register_owner(directory, packet)
        pins = {r: read(directory / (r + '-public.json'))['identity'] for r in ROLES}
        save(directory / 'owner-pins.json', pins)
        if action == 'stage':
            if 'trade' in packet:
                candidate = directory / ('trade-candidate-' + manifest_digest(packet['trade']) + '.json')
                save(candidate, packet['trade'])
                native('otc-verify-acceptance', candidate)
                if packet['trade']['offer']['payload']['owners'] != pins:
                    raise RuntimeError('source OTC identity pins differ')
                save(directory / 'accepted-trade.json', packet['trade'])
                os.environ['LATCH_TRADE_TERMS'] = str(directory / 'accepted-trade.json')
            bank = Path(packet['bank']).resolve()  # Local operator input, not a network offer.
            observed = funding_capture(bank)
            commands = {r: [sys.executable, str(ROOT / 'scripts/signer_transport.py'), 'connect',
                str(directory / (r + '-client.json'))] for r in ROLES}
            save(directory / 'signer-commands.json', commands)
            os.environ['LATCH_SIGNER_COMMANDS'] = str(directory / 'signer-commands.json')
            os.environ['LATCH_REMOTE_OWNERS'] = '1'
            save(directory / 'source-bank.json', {'bank': str(bank)})
            return native('regtest-stage', bank, observed['file'], directory / 'swap', directory / 'owner-pins.json')
        # Verify untrusted incoming consents before pinning the accepted packet.
        # A bad first delivery must not poison the create-once release journal.
        candidate = directory / ('candidate-' + manifest_digest(packet) + '.json')
        save(candidate, packet)
        native('regtest-check-consent', directory / 'swap', candidate)
        save(directory / 'consent-packet.json', packet)
        bank = Path(read(directory / 'source-bank.json')['bank'])
        result = authorize(bank, directory / 'swap', directory / 'consent-packet.json')
        seen = native_funding.current(result['funding_txid'])
        sent = not seen.get('in_active_chain') and result['funding_txid'] not in rpc('getrawmempool')
        if sent and rpc('sendrawtransaction', [Path(result['file']).read_text().strip()], timeout=180) != result['funding_txid']:
            raise RuntimeError('funding broadcast identity changed')
        return {'txid': result['funding_txid'], 'new_transaction': sent, 'state': 'broadcast' if sent else 'observed',
            'source_operator_only': True, 'client_mined_blocks': False}
    if role not in ROLES:
        raise RuntimeError('participant operator required')
    if action.startswith('offer-'):
        return otc_offer.execute(directory, action, packet)
    if action == 'trust-coordinator':
        return configure_owner(directory, packet, own)
    if action == 'trust-peer':
        peer = pin(directory, 'trusted-peer.json', packet, 'bob' if role == 'alice' else 'alice')
        return {'trusted_peer': peer['role'], 'manifest_sha256': manifest_digest(peer)}
    if action == 'serve':
        if (directory / 'accepted-trade.json').exists():
            otc_offer.verify(directory, read(directory / 'accepted-trade.json'), True)
            os.environ['LATCH_TRADE_TERMS'] = str(directory / 'accepted-trade.json')
        os.execv(sys.executable, [sys.executable, str(ROOT / 'scripts/signer_transport.py'), 'serve',
            str(directory / 'signer-server.json')])
    if action == 'ready':
        return client('init', directory, role=role)
    if action == 'consent':
        peer = read(directory / 'trusted-peer.json')
        if (packet['native']['owner_pins'][peer['role']] != peer['identity']
                or packet['native']['owner_pins'][role] != own['identity']):
            raise RuntimeError('offer owners differ from independently trusted identities')
        selected = directory / 'accepted-trade.json'
        if packet['native'].get('trade') != (read(selected) if selected.exists() else None):
            raise RuntimeError('full agreement differs from locally accepted OTC quote')
    return client(action, directory, packet)


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('action', choices=OPERATIONS)
    p.add_argument('directory', type=Path)
    p.add_argument('--role', choices=(*ROLES, 'coordinator'))
    a = p.parse_args()
    os.umask(0o077)
    try:
        directory = a.directory.resolve()
        if a.action == 'init':
            if not a.role:
                raise RuntimeError('initialization role required')
            manifest = initialize(directory, a.role)
            result = {'manifest': manifest, 'manifest_sha256': manifest_digest(manifest)}
        else:
            if a.action in ('identity', 'serve', 'ready'):
                packet = {}
            else:
                raw = sys.stdin.buffer.read(200_001)
                if len(raw) > 200_000:
                    raise RuntimeError('operator message exceeds size limit')
                packet = json.loads(raw)
                if not isinstance(packet, dict):
                    raise RuntimeError('operator message object required')
            result = execute(directory, a.action, packet)
        print(json.dumps(result))
    except (OSError, RuntimeError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        # The caller learns only that the action was refused. The cause goes to
        # this operator's own private directory, for its owner to diagnose.
        detail = exc.stderr if isinstance(exc, subprocess.CalledProcessError) and exc.stderr else ''
        try:
            with (a.directory / 'operator-errors.log').open('a') as log:
                log.write(f'{time.strftime("%H:%M:%S")} {a.action}: {type(exc).__name__}: {exc} {str(detail)[-600:]}'.rstrip() + '\n')
        except OSError:
            pass
        print('Operator action rejected; private state retained.', file=sys.stderr)
        sys.exit(1)
