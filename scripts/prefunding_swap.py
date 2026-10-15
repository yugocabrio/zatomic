#!/usr/bin/env python3
"""Two-owner consent BEFORE release of ZEC funding, on owned isolated chains.

Identity pins are provisioned locally, not discovered from an untrusted offer.
The legacy owner lifecycle still handles completed ETH setup/replay. Explicit
setup checkpoints below are supported; arbitrary setup-instruction crashes and
independently operated source wallets are not claimed.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import run_native_evm_gate as evm
import evm_wallet
import owner_swap as owners
from evm_participant import agreement_digest
from evm_journal import checkpoint, send, InjectedStop
from funding_wallet import authorize
from regtest_node import ROOT, rpc as zrpc, status
from regtest_wallet import native, fund, capture, save, require_capacity
from run_regtest_swap import event, reject_native, require_aux_unspent, reserve_aux, broadcast
from run_tls_swap import configure, services
from run_client_swap import client

VERSION = 'owner-consent-v2'
FAULTS = ('both-consented', 'funding-authorized', 'zec-broadcast', 'zec-funded') + owners.FAULTS


def stop(fault, boundary):
    if fault == boundary:
        raise InjectedStop(boundary)


def setup(directory, mode, bank):
    require_capacity((0 if bank else 104) + 23)
    directory.mkdir(mode=0o700)
    bank = bank or directory / 'bank'
    save(directory / 'setup.json', {'driver': VERSION, 'mode': mode, 'bank': str(bank)})
    (directory / 'owners').mkdir(mode=0o700)
    pins = {}
    for role in ('alice', 'bob'):
        owner = directory / 'owners' / role
        owner.mkdir(mode=0o700)
        pins[role] = client('key-init', owner, role=role)
    save(directory / 'owner-pins.json', pins)
    source = capture(bank) if bank.exists() else fund(bank)
    transport = directory.with_name(directory.name + '-transport')
    commands = configure(transport, directory)
    with services(transport):
        # One heavy prover only. Its output is public terms, never a PCZT/key.
        result = subprocess.run([str(ROOT / 'target/release/shielded-swap-native'),
            'regtest-stage', str(bank), source['file'], str(directory / 'swap'),
            str(directory / 'owner-pins.json')], capture_output=True, text=True,
            env=dict(os.environ, LATCH_SIGNER_COMMANDS=str(commands), RAYON_NUM_THREADS='2'))
        if result.returncode:
            (directory / 'native-stage-error.log').write_text(result.stderr)
            raise RuntimeError('staged native preparation failed; private diagnostics withheld')
        terms = json.loads(result.stdout)
    if (directory / 'swap/funding.hex').exists():
        raise RuntimeError('staging exposed a broadcastable funding transaction')
    event(directory, '01-prepared', {'funding_txid': terms['funding_txid'],
        'refund_height': terms['refund_height'], 'both_exits_before_funding': True,
        'funding_withheld_until_cross_chain_consent': True})
    require_aux_unspent(terms)
    reserve_aux(bank, directory, terms)
    for role in ('alice', 'bob'):
        owner = directory / 'owners' / role
        (directory / 'swap' / role).rename(owner / 'native')
        client('init', owner, role=role)
    staged = directory / 'coordinator-native-offline'
    (directory / 'swap').rename(staged)
    preview = json.loads((staged / 'claim-policy.json').read_text())['funding']
    (staged / 'funding-preview.hex').write_text(preview)
    rejection = reject_native(staged / 'funding-preview.hex')
    if not any(s in rejection.lower() for s in ('signature','redpallas','halo2 proof verification failed')):
        raise RuntimeError('funding preview rejected for unexpected reason')
    event(directory, '00-funding-preview-rejected', {'same_funding_txid': True,
        'broadcast_before_consents_prevented': True, 'node_error': rejection})
    return pins, terms


def offer(directory, pins, terms):
    accounts = evm.rpc('eth_accounts')
    for pin in pins.values():
        if pin['address'] in [a.lower() for a in accounts]:
            raise RuntimeError('owner key unexpectedly unlocked')
        evm.rpc('anvil_setBalance', [pin['address'], hex(10**18)])
        try:
            evm.rpc('eth_signTransaction', [{'from':pin['address'],'to':accounts[0],
                'gas':hex(21000),'value':'0x0'}])
        except RuntimeError:
            pass
        else:
            raise RuntimeError('node could sign for an owner')
    artifact = owners.read(ROOT / '.local/forge-out/PointEscrow.sol/PointEscrow.json')
    deployed = send(directory, {'from': accounts[0], 'data': artifact['bytecode']['object'],
        'gas': hex(5_000_000)}, kind='deploy')
    now = int(evm.rpc('eth_getBlockByNumber', ['latest', False])['timestamp'], 16)
    agreement = {'native': terms, 'eth_chain_id': evm.CHAIN, 'contract': deployed['contractAddress'],
        'maker': pins['bob']['address'], 'recipient': pins['alice']['address'], 'amount_wei': 10**16,
        'eth_expiry': now + 3600, 'consent_version': 1, 'eth_salt': '0x' + os.urandom(32).hex(),
        'eth_code_hash': evm_wallet.keccak(bytes.fromhex(evm.rpc('eth_getCode', [deployed['contractAddress'],'latest'])[2:])).hex(),
        'scope': 'signed prefunding consent on isolated chains; locally provisioned owner pins'}
    save(directory / 'agreement.json', agreement)
    save(directory / 'owner-flow.json', {'version': owners.VERSION, 'mode': owners.read(directory / 'setup.json')['mode'],
        'addresses': {role: pin['address'] for role, pin in pins.items()}, 'agreement_digest': agreement_digest(agreement)})
    save(directory / 'owner-lock-request.json', {'salt': agreement['eth_salt']})
    checkpoint(directory)
    consents = {role: client('consent', directory / 'owners' / role, agreement) for role in ('alice','bob')}
    packet = {'agreement': agreement, 'consents': consents}
    save(directory / 'consent-packet.json', packet)
    native('regtest-check-consent', directory / 'coordinator-native-offline', directory / 'consent-packet.json')
    event(directory, '01-consented', {'both_owner_signatures_verified': True,
        'agreement_digest': agreement_digest(agreement), 'before_native_funding': True})
    return agreement


def release(directory, agreement, fault=None):
    setup = owners.read(directory / 'setup.json')
    staged = directory / 'coordinator-native-offline'
    result = authorize(Path(setup['bank']), staged, directory / 'consent-packet.json')
    event(directory, '01-authorized', {'funding_txid': result['funding_txid'],
        'both_owner_signatures_verified': True, 'agreement_digest': result['agreement_digest']})
    stop(fault, 'funding-authorized')
    observed = broadcast(Path(result['file']), result['funding_txid'], fault == 'zec-broadcast')
    event(directory, '02-funded', observed)
    stop(fault, 'zec-funded')


def settle(directory, agreement, fault=None):
    locked = owners.owner_call(directory, 'lock', 'bob', owners.read(directory / 'owner-lock-request.json'),
        fault == 'eth-lock-broadcast')
    owners.record_once(directory, '04-eth-locked', locked)
    stop(fault, 'eth-locked')
    if owners.read(directory / 'setup.json')['mode'] == 'success':
        with owners.peer_offline(directory / 'owners', 'bob'):
            claimed = owners.owner_call(directory, 'claim', 'alice', {'order': locked['order']},
                fault == 'eth-claim-broadcast')
        owners.record_once(directory, '05-eth-claimed', {'txid': claimed['txid'], 'owner_signed': True})
        stop(fault, 'eth-claimed')
    return owners.finish(directory, agreement, locked['order'], fault=fault)


def run(directory, mode, bank=None, fault=None):
    with owners.chain_lock():
        pins, terms = setup(directory, mode, bank)
        with owners.node(directory):
            agreement = offer(directory, pins, terms)
            stop(fault, 'both-consented')
            release(directory, agreement, fault)
            return settle(directory, agreement, fault)


def resume(directory, fault=None):
    # Explicit continuation of a fully signed, still-unfunded offer. Recovery
    # is separate: it never starts an ETH deposit that had no prior intent.
    if (directory / 'coordinator-native-offline/funding.hex').exists():
        raise RuntimeError('resume expects an unreleased offer; use recover after release')
    with owners.chain_lock(), owners.node(directory, restore=True):
        agreement = owners.read(directory / 'consent-packet.json')['agreement']
        if agreement != owners.read(directory / 'agreement.json'):
            raise RuntimeError('persisted offer changed')
        owners.validate_owners(directory, agreement)
        release(directory, agreement, fault)
        return settle(directory, agreement, fault)


def recover(directory):
    if (directory / 'owners/bob/eth-intent-lock.json').exists():
        return owners.recover(directory)
    with owners.chain_lock(), owners.node(directory, restore=True):
        status()  # Check the isolated native genesis/branch before any replay.
        staged = directory / 'coordinator-native-offline'
        packet = directory / 'consent-packet.json'
        verified = native('regtest-check-consent', staged, packet)
        agreement = owners.read(packet)['agreement']
        owners.validate_owners(directory, agreement)
        if not (staged / 'funding.hex').exists():
            # Retain the staged offer for explicit resume. No source signature
            # has been released and no swap principal can have been broadcast.
            return {'unfunded': True, 'source_authorization_withheld': True,
                'new_native_transactions': 0, 'new_evm_transactions': 0}
        if owners.read(staged / 'funding-consent.json') != verified:
            raise RuntimeError('released funding consent changed')
        # Reconcile an already-authorized F even if its post-send journal was
        # lost; never sign a new funding transaction during recovery.
        txid = verified['funding_txid']
        try:
            existing = zrpc('getrawtransaction', [txid, 1])
        except RuntimeError:
            existing = None
        funded_now = not existing
        if not existing:
            if zrpc('sendrawtransaction', [(staged / 'funding.hex').read_text()], timeout=180) != txid:
                raise RuntimeError('funding replay identity changed')
        if not existing or existing.get('confirmations', 0) < 2:
            zrpc('generate', [2], timeout=300)
        owners.record_once(directory,'02-funded',{'txid':txid,'in_active_chain':True,'confirmations':2})
        owners.validate_recovery(directory)
        # Complete local owner journals are required. Missing identities or a
        # possible exposed claim fail closed before choosing original-asset R.
        if (directory / 'owners/alice/eth-intent-claim.json').exists():
            raise RuntimeError('claim intent without lock intent; recovery state incomplete')
        order = evm.rpc('eth_call', [{'to':agreement['contract'], 'data':evm.calldata(
            'orderId(address,bytes32)', agreement['maker'], agreement['eth_salt'])}, 'latest'])
        raw = evm.rpc('eth_call', [{'to':agreement['contract'], 'data':evm.calldata('orders(bytes32)',order)}, 'latest'])
        if int(raw,16) != 0:
            raise RuntimeError('ETH order exists without its owner journal')
        blocks = max(0, agreement['native']['refund_height'] + 1 - status()['blocks'])
        if blocks:
            zrpc('generate', [blocks], timeout=300)
        with owners.peer_offline(directory / 'owners', 'bob'):
            refunded, sent = owners.native_exit(directory / 'owners/alice/recovery', 'refund')
        observed = capture(directory / 'owners/alice/recovery/alice')
        if not any(n['txid'] == refunded and n['value'] == 1_000_000 for n in owners.read(Path(observed['file']))['notes']):
            raise RuntimeError('source owner did not decrypt refund')
        result = {'scope':'isolated prefunding setup recovery','mode':'funding-only-refund',
            'native_txid':refunded,'native_amount_zatoshi':1_000_000,'eth_wei_locked':0,'eth_not_locked':True,
            'peer_offline_during_native_exit':True,'public_testnet':False}
        owners.record_once(directory,'08-complete',result)
        owners.record_once(directory,'09-recovered',result)
        return dict(result,new_native_transactions=int(sent)+int(funded_now),new_evm_transactions=0)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['success','refund','resume','recover'])
    parser.add_argument('directory', type=Path)
    parser.add_argument('--existing-bank', type=Path)
    parser.add_argument('--fault-after', choices=FAULTS)
    args = parser.parse_args()
    os.umask(0o077)
    if args.action in ('resume','recover') and args.existing_bank:
        parser.error('continuation does not accept a source bank override')
    if args.action == 'recover' and args.fault_after:
        parser.error('recovery does not accept new faults')
    if args.action == 'resume' and args.fault_after == 'both-consented':
        parser.error('resume starts after the consent checkpoint')
    mode = (owners.read(args.directory / 'setup.json')['mode'] if args.action == 'resume' else args.action)
    if mode == 'refund' and args.fault_after in ('eth-claimed','eth-claim-broadcast'):
        parser.error('refund scenario never sends a claim')
    try:
        directory = args.directory.resolve()
        result = (recover(directory) if args.action == 'recover' else resume(directory,args.fault_after)
            if args.action == 'resume' else run(directory,args.action,
                args.existing_bank.resolve() if args.existing_bank else None,args.fault_after))
        print(json.dumps(result,indent=2))
    except InjectedStop as exc:
        print(json.dumps({'interrupted':True,'boundary':str(exc)}))
        sys.exit(75)
