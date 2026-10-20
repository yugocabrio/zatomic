#!/usr/bin/env python3
"""Browser lifecycle for owner-held clients on disposable, isolated chains.

Node checkpoints belong to this fixture, never to the owner signing API. An
owner fsyncs its exact intent before sending. We checkpoint before invoking it
and after observing success, so a lost post-send checkpoint replays that intent.
This module resumes checkpointed ETH setup. The newer prefunding driver also
handles partial native setup/cancellation. This is not public-chain recovery or
remote operation.
"""
import argparse
import contextlib
import fcntl
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import owned_process
import peer_workspace
import signal
import run_native_evm_gate as evm
import escrow_abi
import fee_policy
from evm_journal import checkpoint, order_state, verify_contract, InjectedStop
from evm_participant import agreement_digest
from regtest_node import ROOT, rpc as zrpc, status
from regtest_wallet import save
from recover_regtest_swap import topic, record_once, confirmed
from run_client_swap import client
from run_tls_swap import run as tls_run

VERSION = 'owner-clients-v1'
FAULTS = ('eth-locked', 'eth-claimed', 'eth-lock-broadcast',
          'eth-claim-broadcast', 'eth-withdraw-broadcast')


def read(path):
    return json.loads(path.read_text())


@contextlib.contextmanager
def chain_lock():
    with (ROOT / '.local/chain-driver.lock').open('a') as handle:
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with owned_process.chain_lease(handle.fileno()):
            yield


@contextlib.contextmanager
def node(directory, restore=False):
    with socket.socket() as probe:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        probe.bind(('127.0.0.1', evm.PORT))
    with (directory / 'owner-anvil.log').open('a') as log:
        with owned_process.popen(['anvil', '--host', '127.0.0.1', '--port', str(evm.PORT),
            '--chain-id', str(evm.CHAIN), '--silent'], stdout=log, stderr=log, cwd=ROOT) as process:
            try:
                for _ in range(100):
                    if process.poll() is not None:
                        raise RuntimeError('owned lifecycle node exited')
                    try:
                        if int(evm.rpc('eth_chainId'), 16) == evm.CHAIN:
                            break
                    except OSError:
                        pass
                    time.sleep(.1)
                else:
                    raise RuntimeError('owned lifecycle node startup timed out')
                if restore:
                    saved = read(directory / 'evm-checkpoint.json')
                    if saved['chain_id'] != evm.CHAIN or not evm.rpc('anvil_loadState', [saved['state']]):
                        raise RuntimeError('owned checkpoint domain/restore mismatch')
                yield
            finally:
                # Deliberately do not dump state on exit: a post-send fault must
                # exercise recovery from the preceding durable checkpoint.
                if process.poll() is None:
                    process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()



peer_offline = peer_workspace.unavailable
RECOVERY_FAULTS = ('native-peer-offline', 'native-exit-confirmed')


def crash(directory, fault, boundary):
    if fault == boundary:
        save(directory / f'crash-{boundary}.json', {'boundary':boundary,'pid':os.getpid()})
        os.kill(os.getpid(), signal.SIGKILL)


def owner_call(directory, action, role, packet, stop=False):
    checkpoint(directory)
    result = client(action, directory / 'owners' / role, packet, stop=stop)
    if stop:
        if result.get('intentional_stop') != 'owner-send-before-receipt':
            raise RuntimeError('owner send interruption was not reached')
        raise InjectedStop(f'{action}-broadcast-before-node-checkpoint')
    checkpoint(directory)
    return result


def prepare_owners(directory):
    owners = directory / 'owners'
    owners.mkdir(mode=0o700)
    addresses = {}
    for role in ('alice', 'bob'):
        owner = owners / role
        owner.mkdir(mode=0o700)
        (directory / 'swap' / role).rename(owner / 'native')
        addresses[role] = client('init', owner, role=role)['address']
    terms = read(directory / 'swap/terms.json')
    (directory / 'swap').rename(directory / 'coordinator-native-offline')
    return owners, addresses, terms


def setup_eth(directory, addresses, terms, mode):
    accounts = evm.rpc('eth_accounts')
    for address in addresses.values():
        if address.lower() in [a.lower() for a in accounts]:
            raise RuntimeError('owner is unexpectedly unlocked at node')
        evm.rpc('anvil_setBalance', [address, hex(10**18)])
        try:
            evm.rpc('eth_signTransaction', [{'from': address, 'to': accounts[0],
                'value': '0x0', 'gas': hex(21000)}])
        except RuntimeError:
            pass
        else:
            raise RuntimeError('node could sign for owner')
    version = escrow_abi.local_default()
    deployed = evm.send({'from': accounts[0], 'data': escrow_abi.creation_code(version), 'gas': hex(5_000_000)})
    expiry = int(evm.rpc('eth_getBlockByNumber', ['latest', False])['timestamp'], 16) + 3600
    agreement = {'native': terms, 'eth_chain_id': evm.CHAIN, 'contract': deployed['contractAddress'],
        'maker': addresses['bob'], 'recipient': addresses['alice'], 'amount_wei': 10**16,
        'eth_expiry': expiry, 'fee_policy': fee_policy.default(),
        'scope': 'owner-held keys on controlled local chains; not public-network timing policy'}
    if version != 1:
        agreement['escrow_version'] = version
    for role in ('alice', 'bob'):
        accepted = client('accept', directory / 'owners' / role, agreement)
        if accepted['agreement_digest'] != agreement_digest(agreement):
            raise RuntimeError('owner accepted different agreement')
    save(directory / 'agreement.json', agreement)
    save(directory / 'owner-flow.json', {'version': VERSION, 'mode': mode,
        'addresses': addresses, 'agreement_digest': agreement_digest(agreement)})
    save(directory / 'owner-lock-request.json', {'salt': '0x' + os.urandom(32).hex()})
    checkpoint(directory)
    return agreement


def public_event(agreement, signature, order):
    logs = evm.rpc('eth_getLogs', [{'address': agreement['contract'], 'fromBlock': '0x0',
        'toBlock': 'latest', 'topics': [topic(signature), order]}])
    if len(logs) != 1 or logs[0].get('removed', False):
        raise RuntimeError('unique canonical settlement event unavailable')
    found = logs[0]
    receipt = evm.rpc('eth_getTransactionReceipt', [found['transactionHash']])
    block = evm.rpc('eth_getBlockByNumber', [found['blockNumber'], False])
    if not receipt or receipt['status'] != '0x1' or receipt['blockHash'] != found['blockHash'] or block['hash'] != found['blockHash']:
        raise RuntimeError('settlement event is not canonical')
    return found


def validate_recovery(directory, funding_required=True):
    flow, agreement = read(directory / 'owner-flow.json'), read(directory / 'agreement.json')
    if flow['version'] != VERSION or flow['agreement_digest'] != agreement_digest(agreement):
        raise RuntimeError('owner lifecycle agreement changed')
    if funding_required and not confirmed(agreement['native']['funding_txid']):
        raise RuntimeError('native funding no longer canonical')
    verify_contract(agreement)
    validate_owners(directory, agreement)
    return agreement


def validate_owners(directory, agreement):
    flow = read(directory / 'owner-flow.json')
    if flow['agreement_digest'] != agreement_digest(agreement) or read(directory / 'agreement.json') != agreement:
        raise RuntimeError('owner lifecycle agreement changed')
    # Missing owner state is not evidence that no claim was exposed. Require
    # the initialized owners and immutable acceptance before any route decision.
    for role in ('alice', 'bob'):
        owner = directory / 'owners' / role
        identity = read(owner / 'identity.json')
        if identity['role'] != role or identity['address'] != flow['addresses'][role] or read(owner / 'eth-agreement.json') != agreement:
            raise RuntimeError('owner lifecycle identity/agreement mismatch')
        if read(owner / 'eth-acceptance.json')['agreement_digest'] != flow['agreement_digest']:
            raise RuntimeError('owner lifecycle acceptance mismatch')
        ready = read(owner / 'recovery/recovery-ready.json')
        if ready['funding_txid'] != agreement['native']['funding_txid'] or ready['mode'] != ('refund' if role == 'alice' else 'claim'):
            raise RuntimeError('owner recovery workspace mismatch')


def owner_native_exit(directory, role, order, action):
    """Only this disposable-chain harness mines; the owner CLI never does."""
    owner = directory / 'owners' / role
    observed = client(action, owner, {'order': order})
    sent = observed['new_transaction']
    if observed['state'] == 'auxiliary-pending':
        # A deferred refund first puts Alice's auxiliary A on chain.
        zrpc('generate', [2], timeout=300)
        observed = client(action, owner, {'order': order})
        sent = sent or observed['new_transaction']
    if observed['state'] in ('pending', 'confirming'):
        zrpc('generate', [2 - observed['confirmations']], timeout=300)
        observed = client(action, owner, {'order': order})
        if observed['new_transaction']:
            raise RuntimeError('owner resubmitted while observing native confirmation')
    if observed['state'] != 'confirmed':
        raise RuntimeError('owner native settlement is waiting; private state retained')
    return observed['txid'], sent


def finish(directory, agreement, order, recovered=False, fault=None):
    owners, terms = directory / 'owners', agreement['native']
    state = order_state(agreement, terms, order)
    transactions = 0
    claim_intent = owners / 'alice/eth-intent-claim.json'
    if state != 2 and claim_intent.exists():
        # Even if the checkpoint predates inclusion, never choose a no-reveal
        # refund. The owner validates and replays only its exact timely intent.
        claimed = owner_call(directory, 'claim', 'alice', {'order': order})
        transactions += int(claimed['new_transaction'])
        state = order_state(agreement, terms, order)
    if state == 2:
        found = public_event(agreement, 'Claimed(bytes32,uint256)', order)
        record_once(directory, '05-eth-claimed', {'txid': found['transactionHash'], 'owner_signed': True})
        mode, receiver, paid, peer = 'success', 'bob', 'alice', 'alice'
        with peer_offline(owners, peer):
            crash(directory, fault, 'native-peer-offline')
            txid, sent = owner_native_exit(directory, receiver, order, 'native-claim')
            crash(directory, fault, 'native-exit-confirmed')
    elif state in (1, 3):
        # This branch is allowed only when the complete local owner journal
        # has no claim intent. It is not proof of absence on another host.
        if claim_intent.exists():
            raise RuntimeError('possible secret exposure; no refund fallback')
        if state == 1:
            now = int(evm.rpc('eth_getBlockByNumber', ['latest', False])['timestamp'], 16)
            if now < agreement['eth_expiry']:
                evm.rpc('evm_setNextBlockTimestamp', [agreement['eth_expiry']])
                evm.rpc('evm_mine')
            refunded = owner_call(directory, 'refund', 'bob', {'order': order})
            transactions += int(refunded['new_transaction'])
        found = public_event(agreement, 'Refunded(bytes32)', order)
        record_once(directory, '05-eth-refunded', {'txid': found['transactionHash'], 'owner_signed': True})
        blocks = max(0, terms['refund_height'] + 1 - status()['blocks'])
        if blocks:
            zrpc('generate', [blocks], timeout=300)
        mode, receiver, paid, peer = 'refund', 'alice', 'bob', 'bob'
        with peer_offline(owners, peer):
            crash(directory, fault, 'native-peer-offline')
            txid, sent = owner_native_exit(directory, receiver, order, 'native-refund')
            crash(directory, fault, 'native-exit-confirmed')
    else:
        raise RuntimeError('owner order is not funded')
    record_once(directory, '06-zec-claimed' if mode == 'success' else '06-zec-refunded',
        {'txid': txid, 'in_active_chain': True, 'confirmations': 2})
    address = agreement['recipient' if paid == 'alice' else 'maker']
    before = int(evm.rpc('eth_getBalance', [address, 'latest']), 16)
    withdrawn = owner_call(directory, 'withdraw', paid, {'order': order}, fault == 'eth-withdraw-broadcast')
    transactions += int(withdrawn['new_transaction'])
    receipt = evm.rpc('eth_getTransactionReceipt', [withdrawn['txid']])
    # Verify the actual fixed-owner transfer even on a repeated invocation.
    withdrawals = [log for log in receipt['logs'] if escrow_abi.withdrawn_event(escrow_abi.version(agreement),
        log, agreement['contract'], order, address, address, agreement['amount_wei'])]
    if len(withdrawals) != 1:
        raise RuntimeError('exact owner withdrawal event unavailable')
    if withdrawn['new_transaction']:
        after = int(evm.rpc('eth_getBalance', [address, 'latest']), 16)
        fee = int(receipt['gasUsed'], 16) * int(receipt['effectiveGasPrice'], 16)
        if after - before + fee != agreement['amount_wei']:
            raise RuntimeError('owner ETH balance delta differs')
    result = {'scope': 'actual isolated chains; owner-held keys on one host', 'driver': VERSION,
        'escrow_version': escrow_abi.version(agreement), 'mode': mode, 'native_txid': txid, 'native_amount_zatoshi': terms['payout_zatoshi'],
        'eth_wei_received': agreement['amount_wei'], 'eth_withdraw_tx': withdrawn['txid'],
        'owner_signed_eth': True, 'node_cannot_sign_for_owners': True,
        'peer_offline_during_native_exit': True, 'coordinator_native_files_offline': True,
        'public_testnet': False, 'independent_hosts': False}
    if agreement.get('consent_version') == 1:
        result['signed_cross_chain_consent_before_funding'] = True
    record_once(directory, '08-complete', result)
    if recovered:
        record_once(directory, '09-recovered', result)
    return dict(result, new_native_transactions=int(sent), new_evm_transactions=transactions)


def run(directory, mode, bank=None, fault=None):
    paused = tls_run(mode, directory, bank, 'zec-funded')
    if not paused.get('interrupted'):
        raise RuntimeError('native preparation did not stop after funding')
    with chain_lock():
        _, addresses, terms = prepare_owners(directory)
        with node(directory):
            agreement = setup_eth(directory, addresses, terms, mode)
            locked = owner_call(directory, 'lock', 'bob', read(directory / 'owner-lock-request.json'),
                fault == 'eth-lock-broadcast')
            record_once(directory, '04-eth-locked', locked)
            if fault == 'eth-locked':
                raise InjectedStop('eth-locked')
            if mode == 'success':
                with peer_offline(directory / 'owners', 'bob'):
                    claimed = owner_call(directory, 'claim', 'alice', {'order': locked['order']},
                        fault == 'eth-claim-broadcast')
                record_once(directory, '05-eth-claimed', {'txid': claimed['txid'], 'owner_signed': True})
                if fault == 'eth-claimed':
                    raise InjectedStop('eth-claimed')
            return finish(directory, agreement, locked['order'], fault=fault)


def recover(directory, fault=None):
    with chain_lock():
        return recover_locked(directory, fault)


def recover_locked(directory, fault=None):
    """Caller holds the chain lease through directory and settlement decisions."""
    restored = peer_workspace.reconcile(directory)
    with node(directory, restore=True):
        agreement = validate_recovery(directory, funding_required=False)
        native_submissions = 0
        restored_funding = None
        if not confirmed(agreement['native']['funding_txid']):
            # Bob's own client validates the canonical ETH settlement and
            # published funding history. No source wallet/unsigned PCZT is used.
            order = read(directory / 'owners/bob/eth-lock-request.json')['order']
            restored_funding = client('restore-funding', directory / 'owners/bob', {'order': order})
            native_submissions += int(restored_funding['new_transaction'])
        agreement = validate_recovery(directory)
        # A lock-send gap is resumed by the owner from its exact signed bytes;
        # recovery never originates a new lock without a prior owner intent.
        if not (directory / 'owners/bob/eth-intent-lock.json').is_file():
            raise RuntimeError('no owner lock intent; pre-lock setup recovery not implemented')
        locked = owner_call(directory, 'lock', 'bob', read(directory / 'owner-lock-request.json'))
        record_once(directory, '04-eth-locked', locked)
        result = finish(directory, agreement, locked['order'], recovered=True, fault=fault)
        result['new_evm_transactions'] += int(locked['new_transaction'])
        result['new_native_transactions'] += native_submissions
        result['native_funding_recovery'] = restored_funding
        result['peer_workspace_reconciled'] = restored
        return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['success', 'refund', 'recover'])
    parser.add_argument('directory', type=Path)
    parser.add_argument('--existing-bank', type=Path)
    parser.add_argument('--fault-after', choices=FAULTS + RECOVERY_FAULTS)
    args = parser.parse_args()
    os.umask(0o077)
    try:
        if args.action == 'recover' and (args.existing_bank or args.fault_after and args.fault_after not in RECOVERY_FAULTS):
            parser.error('recovery does not accept funding/fault options')
        if args.action == 'refund' and args.fault_after in ('eth-claimed', 'eth-claim-broadcast'):
            parser.error('refund scenario never sends a claim')
        directory = args.directory.resolve()
        result = recover(directory,args.fault_after) if args.action == 'recover' else run(directory, args.action,
            args.existing_bank.resolve() if args.existing_bank else None, args.fault_after)
        print(json.dumps(result, indent=2))
    except InjectedStop as exc:
        print(json.dumps({'interrupted': True, 'boundary': str(exc)}))
        sys.exit(75)
