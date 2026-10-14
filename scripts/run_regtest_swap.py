#!/usr/bin/env python3
"""Actual isolated Zebra + Anvil swap/recovery gate, with explicit local scope.

Setup is a same-host fixture. Settlement/recovery use fresh native processes and
their persisted artifacts. This is not yet the independent-client product.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import time
import run_native_evm_gate as evm
from regtest_node import ROOT, rpc as zrpc, status
from regtest_wallet import fund, capture, native, save


def event(directory, stage, value):
    save(directory / f'{stage}.json', value)
    print(json.dumps({'stage': stage, **value}), flush=True)


def broadcast(path, expected):
    status()  # Genesis and branch check precedes every native broadcast.
    accepted = zrpc('sendrawtransaction', [path.read_text().strip()], timeout=180)
    if accepted != expected:
        raise RuntimeError('accepted a different transaction')
    zrpc('generate', [2], timeout=300)
    tx = zrpc('getrawtransaction', [expected, 1])
    if not tx['in_active_chain'] or tx['confirmations'] < 2:
        raise RuntimeError('transaction not confirmed on controlled chain')
    return {'txid': expected, 'confirmations': tx['confirmations'], 'in_active_chain': True}


def reject_native(path):
    status()
    try:
        zrpc('sendrawtransaction', [path.read_text().strip()], timeout=180)
    except RuntimeError as exc:
        return str(exc)
    raise RuntimeError('expected native rejection, but node accepted transaction')


def run(directory, mode, existing_bank=None, resume_setup=False):
    os.umask(0o077)
    if resume_setup:
        if not directory.is_dir() or not (directory / '02-funded.json').exists() or (directory / '04-eth-locked.json').exists():
            raise RuntimeError('setup recovery only supports confirmed ZEC before ETH funding')
    else:
        directory.mkdir(mode=0o700)
    bank = existing_bank or directory / 'bank'
    swap = directory / 'swap'
    if resume_setup:
        terms = json.loads((swap / 'terms.json').read_text())
    else:
        funded = capture(bank) if existing_bank else fund(bank)
        terms = native('regtest-prepare', bank, funded['file'], swap)
    event(directory, '01-prepared', {'both_exits_before_funding': True,
        'funding_txid': terms['funding_txid'], 'refund_height': terms['refund_height']})
    if resume_setup:
        tx = zrpc('getrawtransaction', [terms['funding_txid'], 1])
        if not tx['in_active_chain'] or tx['confirmations'] < 2:
            raise RuntimeError('recorded funding is no longer canonical')
        confirmed = json.loads((directory / '02-funded.json').read_text())
    else:
        confirmed = broadcast(swap / 'funding.hex', terms['funding_txid'])
    event(directory, '02-funded', confirmed)
    observed = capture(swap)
    refund_file = swap / f'refund-{observed["height"]}.hex'
    refund = (native('regtest-inspect', refund_file) if refund_file.exists()
              else native('regtest-finish', swap, observed['file'], 'refund'))
    early_error = reject_native(Path(refund['file']))
    # Require the failure to be about finality, not a bad proof or signature.
    if not any(s in early_error.lower() for s in ['nonfinal', 'non-final', 'locktime', 'lock time', 'locked until']):
        raise RuntimeError(f'premature refund rejected for unexpected reason: {early_error}')
    event(directory, '03-early-refund-rejected', {'node_error': early_error})
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', evm.PORT))
    with (directory / 'anvil.log').open('x') as log:
        child = subprocess.Popen(['anvil', '--host', '127.0.0.1', '--port', str(evm.PORT),
                                  '--chain-id', str(evm.CHAIN), '--silent'],
                                 stdout=log, stderr=log, cwd=ROOT)
        try:
            for _ in range(100):
                if child.poll() is not None:
                    raise RuntimeError('owned Anvil exited')
                try:
                    if int(evm.rpc('eth_chainId'), 16) == evm.CHAIN:
                        break
                except OSError:
                    pass
                time.sleep(.1)
            else:
                raise RuntimeError('Anvil startup timeout')
            artifact = json.loads((ROOT / '.local/forge-out/PointEscrow.sol/PointEscrow.json').read_text())
            bob, alice, relay = evm.rpc('eth_accounts')[:3]
            deployed = evm.send({'from': bob, 'data': artifact['bytecode']['object'], 'gas': hex(5_000_000)})
            contract = deployed['contractAddress']
            actual_code = evm.rpc('eth_getCode', [contract, 'latest']).removeprefix('0x')
            if actual_code != artifact['deployedBytecode']['object'].removeprefix('0x'):
                raise RuntimeError('deployed escrow code mismatch')
            now = int(evm.rpc('eth_getBlockByNumber', ['latest', False])['timestamp'], 16)
            expiry = now + 3600
            agreement = {'native': terms, 'eth_chain_id': evm.CHAIN, 'contract': contract,
                'maker': bob, 'recipient': alice, 'amount_wei': 10**16, 'eth_expiry': expiry,
                'scope': 'controlled local height/time progression only; not public-network timing policy'}
            terms_hash = '0x' + hashlib.sha256(json.dumps(agreement, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
            save(directory / 'agreement.json', agreement)
            locked = evm.send({'from': bob, 'to': contract, 'value': hex(10**16), 'gas': hex(700_000),
                'data': evm.calldata('lock(bytes32,address,uint64,(uint256,uint256),bytes32)',
                    '0x' + os.urandom(32).hex(), alice, expiry,
                    f'({terms["point_x"]},{terms["point_y"]})', terms_hash)})
            order = locked['logs'][0]['topics'][1]
            event(directory, '04-eth-locked', {'txid': locked['transactionHash'], 'order': order})
            if mode == 'success':
                secret = json.loads((swap / 'alice/witness.json').read_text())
                claimed = evm.send({'from': relay, 'to': contract, 'gas': hex(1_000_000),
                    'data': evm.calldata('claim(bytes32,uint256)', order, secret['witness_uint256'])})
                if claimed['logs'][0]['topics'][1] != order:
                    raise RuntimeError('wrong claim event')
                witness = int(claimed['logs'][0]['data'], 16).to_bytes(32, 'little').hex()
                event(directory, '05-eth-claimed', {'txid': claimed['transactionHash'],
                    'gas': int(claimed['gasUsed'], 16), 'witness_source': 'actual EVM event'})
                # Simulate Alice's local application becoming unavailable. Bob's
                # completion must not read her directory, signing share or secret.
                (swap / 'alice').rename(swap / 'alice-offline')
                try:
                    completed = native('regtest-finish', swap, observed['file'], 'claim', witness)
                finally:
                    (swap / 'alice-offline').rename(swap / 'alice')
                received = broadcast(Path(completed['file']), completed['txid'])
                event(directory, '06-zec-claimed', received)
                bob_scan = capture(swap / 'bob')
                notes = json.loads(Path(bob_scan['file']).read_text())['notes']
                if not any(n['txid'] == completed['txid'] and n['value'] == 1_000_000 for n in notes):
                    raise RuntimeError('Bob did not decrypt expected native payout')
                # Move beyond refund height and try the competing fully valid R.
                blocks = max(0, terms['refund_height'] + 1 - status()['blocks'])
                if blocks:
                    zrpc('generate', [blocks], timeout=300)
                conflict = reject_native(Path(refund['file']))
                if not any(s in conflict.lower() for s in ['nullifier', 'spent', 'conflict']):
                    raise RuntimeError(f'competing refund failed for unexpected reason: {conflict}')
                event(directory, '07-conflicting-refund-rejected', {'node_error': conflict})
                credited = alice
                native_result = {'claim': received, 'bob_received_zatoshi': 1_000_000,
                    'alice_files_unavailable_during_claim': True, 'conflicting_refund_rejected': True}
            else:
                # No witness was revealed. Resume from persisted refund data
                # with Bob's signer files unavailable; Bob recovers ETH by time.
                evm.rpc('evm_setNextBlockTimestamp', [expiry])
                evm.rpc('evm_mine')
                refunded = evm.send({'from': relay, 'to': contract, 'gas': hex(200_000),
                                    'data': evm.calldata('refund(bytes32)', order)})
                event(directory, '05-eth-refunded', {'txid': refunded['transactionHash']})
                blocks = max(0, terms['refund_height'] + 1 - status()['blocks'])
                if blocks:
                    zrpc('generate', [blocks], timeout=300)
                (swap / 'bob').rename(swap / 'bob-offline')
                try:
                    recovered = broadcast(Path(refund['file']), refund['txid'])
                finally:
                    (swap / 'bob-offline').rename(swap / 'bob')
                event(directory, '06-zec-refunded', recovered)
                scan = capture(bank)
                notes = json.loads(Path(scan['file']).read_text())['notes']
                if not any(n['txid'] == refund['txid'] and n['value'] == 1_000_000 for n in notes):
                    raise RuntimeError('Alice did not decrypt her refund')
                credited = bob
                native_result = {'refund': recovered, 'alice_refunded_zatoshi': 1_000_000,
                                 'bob_files_unavailable_during_refund': True}
            credit = int(evm.rpc('eth_call', [{'to': contract,
                'data': evm.calldata('credits(address)', credited)}, 'latest']), 16)
            if credit != 10**16:
                raise RuntimeError('wrong ETH credit')
            before = int(evm.rpc('eth_getBalance', [credited, 'latest']), 16)
            receipt = evm.send({'from': credited, 'to': contract, 'gas': hex(200_000),
                               'data': evm.calldata('withdraw(address)', credited)})
            after = int(evm.rpc('eth_getBalance', [credited, 'latest']), 16)
            fee = int(receipt['gasUsed'], 16) * int(receipt['effectiveGasPrice'], 16)
            if after - before + fee != 10**16:
                raise RuntimeError('wrong ETH withdrawal')
            result = {'scope': 'actual isolated Zebra NU7 + Anvil, controlled local confirmations',
                'mode': mode, 'public_testnet': False, 'same_host_setup': True,
                'native': native_result, 'eth_wei_received': 10**16,
                'early_native_refund_rejected': True, 'exits_prepared_before_funding': True,
                'zec_principal_shielded': True, 'refund_has_transparent_auxiliary': True,
                'zec_recipient_not_in_evm_calldata': True, 'timing_scope': agreement['scope']}
            event(directory, '08-complete', result)
            return result
        finally:
            child.terminate()
            try:
                child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['success', 'refund'])
    parser.add_argument('directory', type=Path)
    parser.add_argument('--existing-bank', type=Path)
    parser.add_argument('--resume-setup', action='store_true')
    args = parser.parse_args()
    run(args.directory.resolve(), args.mode,
        args.existing_bank.resolve() if args.existing_bank else None, args.resume_setup)
