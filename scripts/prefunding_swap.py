#!/usr/bin/env python3
"""Two-owner consent BEFORE release of ZEC funding, on owned isolated chains.

Identity pins are provisioned locally, not discovered from an untrusted offer.
The legacy owner lifecycle still handles completed ETH setup/replay.
Unreleased setup can be permanently cancelled after an interruption. Release
decisions are journaled before signing; independent hosts remain unproven.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import owned_process
import run_native_evm_gate as evm
import evm_wallet
import fee_policy
import owner_swap as owners
from evm_participant import agreement_digest
from evm_journal import checkpoint, send, InjectedStop
from funding_wallet import authorize
from regtest_node import ROOT, rpc as zrpc, status
from regtest_wallet import native, fund, capture, funding_capture, save, require_capacity, FUNDING_ANCHOR_LAG
from run_regtest_swap import event, reject_native, require_aux_unspent, reserve_aux, broadcast
from run_tls_swap import configure, services
from run_client_swap import client

VERSION = 'owner-consent-v3'
SETUP_FAULTS = ('alice-key', 'source-ready', 'native-in-flight', 'native-staged', 'alice-migrated',
                'eth-deployed', 'alice-consented')
FAULTS = SETUP_FAULTS + ('source-release-intent',) + ('both-consented', 'funding-authorized', 'zec-broadcast', 'zec-funded') + owners.FAULTS + owners.RECOVERY_FAULTS


def stop(fault, boundary):
    if fault == boundary:
        raise InjectedStop(boundary)


def setup(directory, mode, bank, fault=None):
    require_capacity((0 if bank else 104) + 23 + FUNDING_ANCHOR_LAG)
    native('regtest-setup-init', directory)
    bank = bank or directory / 'bank'
    save(directory / 'setup.json', {'driver': VERSION, 'mode': mode, 'bank': str(bank)})
    (directory / 'owners').mkdir(mode=0o700)
    pins = {}
    for role in ('alice', 'bob'):
        owner = directory / 'owners' / role
        owner.mkdir(mode=0o700)
        pins[role] = client('key-init', owner, role=role)
        stop(fault, f'{role}-key')
    save(directory / 'owner-pins.json', pins)
    if not bank.exists():
        fund(bank)
    source = funding_capture(bank)
    stop(fault, 'source-ready')
    transport = directory.with_name(directory.name + '-transport')
    commands = configure(transport, directory)
    with services(transport):
        # One heavy prover only. Its output is public terms, never a PCZT/key.
        with owned_process.popen([str(ROOT / 'target/release/shielded-swap-native'),
            'regtest-stage', str(bank), source['file'], str(directory / 'swap'),
            str(directory / 'owner-pins.json')], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, env=dict(os.environ, LATCH_SIGNER_COMMANDS=str(commands), RAYON_NUM_THREADS='2')) as process:
            try:
                if fault == 'native-in-flight':
                    # Kill only this child after actual DKG, while native preparation
                    # is still live. TLS services below also own/clean their children.
                    deadline = time.monotonic() + 120
                    while not (directory / 'swap/joint-fvk.bin').exists():
                        if process.poll() is not None or time.monotonic() > deadline:
                            raise RuntimeError('native kill boundary was not reached')
                        time.sleep(.05)
                    if process.poll() is not None:
                        raise RuntimeError('native preparation already ended before kill')
                    process.kill()
                    process.communicate(timeout=20)
                    raise InjectedStop('native-in-flight-sigkill')
                output, errors = process.communicate()
                if process.returncode:
                    (directory / 'native-stage-error.log').write_text(errors)
                    raise RuntimeError('staged native preparation failed; private diagnostics withheld')
                terms = json.loads(output)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.communicate(timeout=20)
    stop(fault, 'native-staged')
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
        stop(fault, f'{role}-migrated')
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


def offer(directory, pins, terms, fault=None):
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
    stop(fault, 'eth-deployed')
    now = int(evm.rpc('eth_getBlockByNumber', ['latest', False])['timestamp'], 16)
    agreement = {'native': terms, 'eth_chain_id': evm.CHAIN, 'contract': deployed['contractAddress'],
        'maker': pins['bob']['address'], 'recipient': pins['alice']['address'], 'amount_wei': 10**16,
        'eth_expiry': now + 3600, 'fee_policy': fee_policy.default(), 'consent_version': 1, 'eth_salt': '0x' + os.urandom(32).hex(),
        'eth_code_hash': evm_wallet.keccak(bytes.fromhex(evm.rpc('eth_getCode', [deployed['contractAddress'],'latest'])[2:])).hex(),
        'scope': 'signed prefunding consent on isolated chains; locally provisioned owner pins'}
    save(directory / 'agreement.json', agreement)
    save(directory / 'owner-flow.json', {'version': owners.VERSION, 'mode': owners.read(directory / 'setup.json')['mode'],
        'addresses': {role: pin['address'] for role, pin in pins.items()}, 'agreement_digest': agreement_digest(agreement)})
    save(directory / 'owner-lock-request.json', {'salt': agreement['eth_salt']})
    checkpoint(directory)
    consents = {}
    for role in ('alice','bob'):
        consents[role] = client('consent', directory / 'owners' / role, agreement)
        stop(fault, f'{role}-consented')
    packet = {'agreement': agreement, 'consents': consents}
    save(directory / 'consent-packet.json', packet)
    native('regtest-check-consent', directory / 'coordinator-native-offline', directory / 'consent-packet.json')
    event(directory, '01-consented', {'both_owner_signatures_verified': True,
        'agreement_digest': agreement_digest(agreement), 'before_native_funding': True})
    return agreement


def release(directory, agreement, fault=None):
    setup = owners.read(directory / 'setup.json')
    staged = directory / 'coordinator-native-offline'
    result = authorize(Path(setup['bank']), staged, directory / 'consent-packet.json',
        stop_before_sign=fault == 'source-release-intent')
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
        pins, terms = setup(directory, mode, bank, fault)
        with owners.node(directory):
            agreement = offer(directory, pins, terms, fault)
            stop(fault, 'both-consented')
            release(directory, agreement, fault)
            return settle(directory, agreement, fault)


def resume(directory, fault=None):
    # Explicit continuation of a fully signed, still-unfunded offer. Recovery
    # is separate: it never starts an ETH deposit that had no prior intent.
    if (directory / 'source-cancelled.json').exists():
        raise RuntimeError('source setup permanently cancelled; use a fresh offer')
    if (directory / 'coordinator-native-offline/funding.hex').exists():
        raise RuntimeError('resume expects an unreleased offer; use recover after release')
    with owners.chain_lock(), owners.node(directory, restore=True):
        agreement = owners.read(directory / 'consent-packet.json')['agreement']
        if agreement != owners.read(directory / 'agreement.json'):
            raise RuntimeError('persisted offer changed')
        owners.validate_owners(directory, agreement)
        release(directory, agreement, fault)
        return settle(directory, agreement, fault)


def cancel(directory):
    with owners.chain_lock():
        return cancel_locked(directory)


def cancel_locked(directory):
    result = native('regtest-cancel-setup', directory)
    owners.record_once(directory, '08-complete', result)
    owners.record_once(directory, '09-recovered', result)
    return result


def recover(directory, fault=None):
    with owners.chain_lock():
        return recover_locked(directory, fault)


def recover_locked(directory, fault=None):
    # Keep the lease across reconciliation and route selection. Otherwise a
    # concurrent recovery could temporarily hide Bob's lock intent between them.
    restored = owners.peer_workspace.reconcile(directory)
    # This decision is rechecked inside the native OS lock. No node startup,
    # signature, or broadcast is needed to abandon an unreleased v3 setup.
    if (directory / 'source-setup.json').exists() and not (directory / 'source-release.json').exists():
        return cancel_locked(directory)
    if (directory / 'owners/bob/eth-intent-lock.json').exists():
        result = owners.recover_locked(directory, fault)
        result['peer_workspace_reconciled'] = restored or result.get('peer_workspace_reconciled')
        return result
    with owners.node(directory, restore=True):
        status()  # Check the isolated native genesis/branch before any replay.
        staged = directory / 'coordinator-native-offline'
        packet = directory / 'consent-packet.json'
        verified = native('regtest-check-consent', staged, packet)
        agreement = owners.read(packet)['agreement']
        owners.validate_owners(directory, agreement)
        if (directory / 'source-release.json').exists() and not (staged / 'funding.hex').exists():
            # Finish the exact already-committed release, then refund. A durable
            # source decision cannot be reclassified as uncommitted on restart.
            native('regtest-authorize-funding', Path(owners.read(directory / 'setup.json')['bank']), staged, packet)
        if not (staged / 'funding.hex').exists():
            # Legacy v2 only. Retain the staged offer for explicit resume. No source signature
            # has been released and no swap principal can have been broadcast.
            return {'unfunded': True, 'source_authorization_withheld': True,
                'new_native_transactions': 0, 'new_evm_transactions': 0}
        if owners.read(staged / 'funding-consent.json') != verified:
            raise RuntimeError('released funding consent changed')
        # Reconcile an already-authorized F even if its post-send journal was
        # lost. Reuse published bytes; any unfinished signature above belongs
        # to the exact durable release decision, never to a fresh offer.
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
            owners.crash(directory, fault, 'native-peer-offline')
            refunded, sent = owners.native_exit(directory / 'owners/alice/recovery', 'refund')
            owners.crash(directory, fault, 'native-exit-confirmed')
        observed = capture(directory / 'owners/alice/recovery/alice')
        if not any(n['txid'] == refunded and n['value'] == 1_000_000 for n in owners.read(Path(observed['file']))['notes']):
            raise RuntimeError('source owner did not decrypt refund')
        result = {'scope':'isolated prefunding setup recovery','mode':'funding-only-refund',
            'native_txid':refunded,'native_amount_zatoshi':1_000_000,'eth_wei_locked':0,'eth_not_locked':True,
            'peer_offline_during_native_exit':True,'public_testnet':False}
        owners.record_once(directory,'08-complete',result)
        owners.record_once(directory,'09-recovered',result)
        return dict(result,new_native_transactions=int(sent)+int(funded_now),new_evm_transactions=0,peer_workspace_reconciled=restored)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['success','refund','resume','recover','cancel'])
    parser.add_argument('directory', type=Path)
    parser.add_argument('--existing-bank', type=Path)
    parser.add_argument('--fault-after', choices=FAULTS)
    args = parser.parse_args()
    os.umask(0o077)
    if args.action in ('resume','recover','cancel') and args.existing_bank:
        parser.error('continuation does not accept a source bank override')
    if args.fault_after and (args.action == 'cancel' or args.action == 'recover' and args.fault_after not in owners.RECOVERY_FAULTS):
        parser.error('recovery does not accept new faults')
    if args.action == 'resume' and args.fault_after in SETUP_FAULTS + ('both-consented',):
        parser.error('resume starts after the consent checkpoint')
    mode = (owners.read(args.directory / 'setup.json')['mode'] if args.action == 'resume' else args.action)
    if mode == 'refund' and args.fault_after in ('eth-claimed','eth-claim-broadcast'):
        parser.error('refund scenario never sends a claim')
    try:
        directory = args.directory.resolve()
        result = (cancel(directory) if args.action == 'cancel' else recover(directory,args.fault_after) if args.action == 'recover' else resume(directory,args.fault_after)
            if args.action == 'resume' else run(directory,args.action,
                args.existing_bank.resolve() if args.existing_bank else None,args.fault_after))
        print(json.dumps(result,indent=2))
    except InjectedStop as exc:
        print(json.dumps({'interrupted':True,'boundary':str(exc)}))
        sys.exit(75)
