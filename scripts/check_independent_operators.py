#!/usr/bin/env python3
"""Same-host OS-isolated operators, real TLS preparation and actual settlement.

macOS sandbox-exec denies the other operators' private roots for every child.
Only this test harness provisions nodes/mines and transfers public messages.
It is not a test of independently administered hosts or an adversarial OS.
"""
import argparse
import contextlib
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import owned_process
import owner_swap as flow
import run_native_evm_gate as evm
import evm_wallet
import fee_policy
from evm_journal import checkpoint, send
from latch_operator import manifest_digest
from regtest_node import ROOT, rpc, status
from regtest_wallet import save, require_capacity


class Operators:
    def __init__(self, root):
        self.root = root
        self.paths = {r: root / r for r in ('alice', 'bob', 'coordinator')}

    def command(self, role, args):
        # No wildcards or shell evaluation; every denied path is this new run's
        # exact operator root. Include offline aliases before moving a peer.
        denied = [self.root / 'harness']
        denied += [p for r, p in self.paths.items() if r != role]
        denied += [p.with_name(p.name + '-offline') for r, p in self.paths.items() if r != role]
        policy = '(version 1)(allow default)' + ''.join(
            '(deny file-read* file-write* (subpath ' + json.dumps(str(p)) + '))' for p in denied)
        return ['/usr/bin/sandbox-exec', '-p', policy, *args]

    def invoke(self, role, action, packet=None, reject=False):
        args = [sys.executable, str(ROOT / 'scripts/latch_operator.py'), action, str(self.paths[role])]
        if action == 'init':
            args += ['--role', role]
        p = owned_process.run(self.command(role, args), input=json.dumps(packet or {}),
            capture_output=True, text=True, cwd=ROOT, timeout=600)
        if p.returncode != (1 if reject else 0):
            (self.root / 'harness' / (role + '-' + action + '-error.log')).write_text(p.stdout + '\n' + p.stderr)
            raise RuntimeError('isolated operator action failed: ' + role + '/' + action)
        return {} if reject else json.loads(p.stdout)

    def isolation(self):
        for role in self.paths:
            for other in self.paths:
                if role == other:
                    continue
                # Even a PUBLIC marker inside another private root must be
                # inaccessible, so this probe never needs to open a real key.
                args = [sys.executable, '-c',
                    'from pathlib import Path; import sys\ntry: Path(sys.argv[1]).read_bytes()\n'
                    'except PermissionError: sys.exit(0)\nelse: sys.exit(9)',
                    str(self.paths[other] / 'operator-public.json')]
                result = owned_process.run(self.command(role, args), capture_output=True, timeout=10)
                if result.returncode:
                    raise RuntimeError('OS private-root read denial not enforced')

    @contextlib.contextmanager
    def services(self):
        with contextlib.ExitStack() as stack:
            for role in ('alice', 'bob'):
                args = [sys.executable, str(ROOT / 'scripts/latch_operator.py'), 'serve', str(self.paths[role])]
                p = stack.enter_context(owned_process.popen(self.command(role, args),
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True))
                if not json.loads(p.stdout.readline()).get('ready'):
                    raise RuntimeError('isolated signer service not ready')
            yield


def setup(actors, harness, quote=None):
    manifest = {r: actors.invoke(r, 'init')['manifest'] for r in actors.paths}
    actors.isolation()
    packet = lambda m: {'manifest': m, 'expected_manifest_sha256': manifest_digest(m)}
    for role, port in (('alice', 18741), ('bob', 18742)):
        actors.invoke(role, 'trust-coordinator', dict(packet(manifest['coordinator']), port=port))
        actors.invoke(role, 'trust-peer', packet(manifest['bob' if role == 'alice' else 'alice']))
        actors.invoke('coordinator', 'register-owner', dict(packet(manifest[role]), host='127.0.0.1', port=port))
    trade = None
    if quote:
        offer = actors.invoke('alice', 'offer-create', quote)
        changed = copy.deepcopy(offer)
        changed['offer']['payload']['payout_zatoshi'] += 1
        actors.invoke('bob', 'offer-review', changed, reject=True)
        review = actors.invoke('bob', 'offer-review', offer)
        trade = actors.invoke('bob', 'offer-accept', offer)
        actors.invoke('alice', 'offer-accept', trade)
        save(harness / 'otc-review.json', review)
    bank = actors.paths['coordinator'] / 'bank'
    funded = owned_process.run(actors.command('coordinator', [sys.executable,
        str(ROOT / 'scripts/regtest_wallet.py'), 'fund', str(bank)]), capture_output=True, text=True, timeout=300)
    if funded.returncode:
        (harness / 'source-funding-error.log').write_text(funded.stderr)
        raise RuntimeError('isolated source wallet fixture funding failed')
    with actors.services():
        terms = actors.invoke('coordinator', 'stage', dict(bank=str(bank), **({'trade': trade} if trade else {})))
    for role in ('alice', 'bob'):
        actors.invoke(role, 'ready')
    pins = {r: manifest[r]['identity'] for r in ('alice', 'bob')}
    accounts = evm.rpc('eth_accounts')
    for pin in pins.values():
        evm.rpc('anvil_setBalance', [pin['address'], hex(10**18 + (trade['offer']['payload']['eth_amount_wei'] if trade else 10**16))])
    artifact = flow.read(ROOT / '.local/forge-out/PointEscrow.sol/PointEscrow.json')
    contract = send(harness, {'from': accounts[0], 'data': artifact['bytecode']['object'],
        'gas': hex(5_000_000)}, kind='deploy')['contractAddress']
    now = int(evm.rpc('eth_getBlockByNumber', ['latest', False])['timestamp'], 16)
    agreement = {'native': terms, 'eth_chain_id': evm.CHAIN, 'contract': contract,
        'maker': pins['bob']['address'], 'recipient': pins['alice']['address'], 'amount_wei': trade['offer']['payload']['eth_amount_wei'] if trade else 10**16,
        'eth_expiry': now + 3600, 'fee_policy': fee_policy.default(), 'consent_version': 1, 'eth_salt': '0x' + os.urandom(32).hex(),
        'eth_code_hash': evm_wallet.keccak(bytes.fromhex(evm.rpc('eth_getCode', [contract, 'latest'])[2:])).hex(),
        'scope': 'same-host OS-isolated operators; actual owned chain fixture'}
    changed = copy.deepcopy(agreement)
    changed['native']['owner_pins']['bob']['address'] = '0x' + '11' * 20
    actors.invoke('alice', 'consent', changed, reject=True)
    consents = {r: actors.invoke(r, 'consent', agreement) for r in ('alice', 'bob')}
    damaged = copy.deepcopy(consents)
    damaged['bob']['payload']['agreement_digest'] = '00' * 32
    actors.invoke('coordinator', 'source-fund', {'agreement': agreement, 'consents': damaged}, reject=True)
    if any((actors.paths['coordinator'] / p).exists() for p in ('consent-packet.json', 'source-release.json', 'swap/funding.hex')):
        raise RuntimeError('bad incoming consent poisoned source authorization')
    save(harness / 'setup-checks.json', {'changed_peer_identity_and_invalid_source_consent_rejected': True})
    save(harness / 'public-agreement.json', agreement)
    save(harness / 'public-consents.json', consents)
    checkpoint(harness)
    return agreement, consents


def complete(actors, harness, agreement, consents, mode):
    terms = agreement['native']
    funding_sent = False
    try:
        funding = rpc('getrawtransaction', [terms['funding_txid'], 1])
    except RuntimeError:
        funding = {}
    if not funding.get('in_active_chain'):
        funding_sent = actors.invoke('coordinator', 'source-fund', {'agreement': agreement, 'consents': consents})['new_transaction']
    depth = funding.get('confirmations', 0) if funding.get('in_active_chain') else 0
    if depth < 2:
        rpc('generate', [2 - depth], timeout=300)
    checkpoint(harness)
    locked = actors.invoke('bob', 'lock', {'salt': agreement['eth_salt']})
    checkpoint(harness)
    order = locked['order']
    if mode == 'success':
        eth_exit = actors.invoke('alice', 'claim', {'order': order})
        owner, peer, action, paid = 'bob', 'alice', 'native-claim', 'alice'
    else:
        now = int(evm.rpc('eth_getBlockByNumber', ['latest', False])['timestamp'], 16)
        if now < agreement['eth_expiry']:
            evm.rpc('evm_setNextBlockTimestamp', [agreement['eth_expiry']])
            evm.rpc('evm_mine')
        eth_exit = actors.invoke('bob', 'refund', {'order': order})
        owner, peer, action, paid = 'alice', 'bob', 'native-refund', 'bob'
        wait = max(0, terms['refund_height'] + 1 - status()['blocks'])
        if wait:
            rpc('generate', [wait], timeout=300)
    checkpoint(harness)
    peer_path = actors.paths[peer]
    offline = peer_path.with_name(peer_path.name + '-offline')
    save(harness / 'offline-peer.json', {'role': peer})
    peer_path.rename(offline)
    try:
        result = actors.invoke(owner, action, {'order': order})
        if result['state'] in ('pending', 'confirming'):
            rpc('generate', [2 - result['confirmations']], timeout=300)
        confirmed = actors.invoke(owner, action, {'order': order})
        repeat = actors.invoke(owner, action, {'order': order})
        if (confirmed['state'] != 'confirmed' or confirmed['received_zatoshi'] != terms['payout_zatoshi']
                or confirmed['new_transaction'] or repeat['new_transaction']):
            raise RuntimeError('independent native settlement/restart failed')
    finally:
        offline.rename(peer_path)
    withdrawn = actors.invoke(paid, 'withdraw', {'order': order})
    checkpoint(harness)
    receipt = evm.rpc('eth_getTransactionReceipt', [withdrawn['txid']])
    target = agreement['recipient' if mode == 'success' else 'maker']
    topic = '0x' + evm_wallet.keccak(b'Withdrawn(address,address,uint256)').hex()
    address_topic = '0x' + target[2:].rjust(64, '0')
    if not any(log['address'].lower() == agreement['contract'].lower()
               and log['topics'] == [topic, address_topic, address_topic]
               and int(log['data'], 16) == agreement['amount_wei'] for log in receipt['logs']):
        raise RuntimeError('independent ETH withdrawal mismatch')
    return {'scope': 'same-host OS file isolation, actual owned chains; not independent administration',
        'mode': mode, 'funding_txid': terms['funding_txid'], 'native_exit': confirmed, 'native_repeat': repeat,
        'eth_withdraw_txid': withdrawn['txid'], 'eth_wei_received': agreement['amount_wei'],
        'new_native_transactions': int(funding_sent) + int(result['new_transaction']),
        'new_evm_transactions': int(locked['new_transaction']) + int(eth_exit['new_transaction']) + int(withdrawn['new_transaction']),
        'all_six_cross_operator_root_reads_denied': True, 'keys_generated_by_own_operator': True,
        'changed_peer_identity_and_invalid_source_consent_rejected': (harness / 'setup-checks.json').exists(),
        'private_roots_shared_by_protocol': False, 'native_setup_via_tls_only': True,
        'both_signed_consents_before_source_authorization': True, 'peer_directory_unavailable_during_exit': True,
        'owner_exit_without_mining_or_node_restore': True, 'independent_hosts': False, 'public_testnet': False}


def check(root, mode, resume, quote=None):
    actors = Operators(root)
    harness = root / 'harness'
    if not resume:
        root.mkdir(mode=0o700)
        harness.mkdir(mode=0o700)
        save(harness / 'mode.json', {'mode': mode})
    else:
        mode = flow.read(harness / 'mode.json')['mode']
        for role in ('alice', 'bob'):
            offline = root / (role + '-offline')
            if offline.exists():
                if actors.paths[role].exists():
                    raise RuntimeError('ambiguous operator location')
                offline.rename(actors.paths[role])
    with flow.chain_lock(), flow.node(harness, restore=resume):
        if resume:
            agreement = flow.read(harness / 'public-agreement.json')
            consents = flow.read(harness / 'public-consents.json')
        else:
            require_capacity(133)
            agreement, consents = setup(actors, harness, quote)
        result = complete(actors, harness, agreement, consents, mode)
        if (harness / 'complete.json').exists():
            original = flow.read(harness / 'complete.json')
            if (original['funding_txid'] != result['funding_txid']
                    or original['native_exit']['txid'] != result['native_exit']['txid']
                    or original['eth_withdraw_txid'] != result['eth_withdraw_txid']):
                raise RuntimeError('independent recovery changed completed payment identities')
        else:
            save(harness / 'complete.json', result)
    return result


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('mode', choices=['success', 'refund', 'recover'])
    p.add_argument('directory', type=Path)
    p.add_argument('--zec-amount')
    p.add_argument('--eth-amount')
    a = p.parse_args()
    if bool(a.zec_amount) != bool(a.eth_amount):
        p.error('both OTC decimal amounts are required')
    os.umask(0o077)
    print(json.dumps(check(a.directory.resolve(), a.mode, a.mode == 'recover',
        {'zec_amount': a.zec_amount, 'eth_amount': a.eth_amount} if a.zec_amount else None), indent=2))
