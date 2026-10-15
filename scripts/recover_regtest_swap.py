#!/usr/bin/env python3
"""Resume an isolated-chain swap from durable receipts and chain state.

If ETH was claimed, Bob completes the prepared native claim using the public
witness. Otherwise both original assets are refunded. No new reveal occurs.
This restores the OWNED Anvil snapshot; it is not public-network reorg recovery.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import time
import run_native_evm_gate as evm
from regtest_node import ROOT, rpc as zrpc, status
from regtest_wallet import native, capture, save
from run_regtest_swap import broadcast, send_evm


def topic(signature):
    return subprocess.check_output(['cast', 'keccak', signature], text=True).strip()


def confirmed(txid):
    try:
        tx = zrpc('getrawtransaction', [txid, 1])
    except RuntimeError:
        return False
    return bool(tx.get('in_active_chain') and tx.get('confirmations', 0) >= 2)


def native_exit(swap, mode, witness=None):
    # Reconcile before constructing or re-sending anything. A crash after a
    # broadcast must not cause a second funding or payment.
    files = sorted(swap.glob(f'{mode}-*.hex'))
    for path in files:
        info = native('regtest-inspect', path)
        if confirmed(info['txid']):
            return info['txid'], False
    if files:
        path = files[-1]
        info = native('regtest-inspect', path)
    else:
        observed = capture(swap)
        args = ['regtest-finish', swap, observed['file'], mode]
        if witness is not None:
            args.append(witness)
        info = native(*args)
        path = Path(info['file'])
    broadcast(path, info['txid'])
    return info['txid'], True


def recover(directory):
    os.umask(0o077)
    status()
    swap = directory / 'swap'
    agreement = json.loads((directory / 'agreement.json').read_text())
    terms = json.loads((swap / 'terms.json').read_text())
    checkpoint = json.loads((directory / 'evm-checkpoint.json').read_text())
    locked = json.loads((directory / '04-eth-locked.json').read_text())
    if agreement['native'] != terms or checkpoint['chain_id'] != evm.CHAIN or agreement['eth_chain_id'] != evm.CHAIN:
        raise RuntimeError('recovery journal domain mismatch')
    if not confirmed(terms['funding_txid']):
        raise RuntimeError('recorded native funding is no longer confirmed; refuse cached state')
    with socket.socket() as probe:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        probe.bind(('127.0.0.1', evm.PORT))
    with (directory / 'recovery-anvil.log').open('a') as log:
        process = subprocess.Popen(['anvil', '--host', '127.0.0.1', '--port', str(evm.PORT),
            '--chain-id', str(evm.CHAIN), '--silent'], cwd=ROOT, stdout=log, stderr=log)
        try:
            for _ in range(100):
                if process.poll() is not None:
                    raise RuntimeError('owned recovery node exited')
                try:
                    if int(evm.rpc('eth_chainId'), 16) == evm.CHAIN:
                        break
                except OSError:
                    pass
                time.sleep(.1)
            else:
                raise RuntimeError('recovery node startup timeout')
            if not evm.rpc('anvil_loadState', [checkpoint['state']]):
                raise RuntimeError('snapshot restore failed')
            contract, order = agreement['contract'], locked['order']
            artifact = json.loads((ROOT / '.local/forge-out/PointEscrow.sol/PointEscrow.json').read_text())
            if evm.rpc('eth_getCode', [contract, 'latest']).removeprefix('0x') != artifact['deployedBytecode']['object'].removeprefix('0x'):
                raise RuntimeError('restored contract code mismatch')
            encoded = evm.rpc('eth_call', [{'to': contract, 'data': evm.calldata('orders(bytes32)', order)}, 'latest'])
            words = [int(encoded[2+i:2+i+64], 16) for i in range(0, len(encoded)-2, 64)]
            commitment = hashlib.sha256(json.dumps(agreement, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
            if len(words) != 8 or words[0] != int(agreement['maker'], 16) or words[1] != int(agreement['recipient'], 16) or words[2] != 10**16 or words[3] != agreement['eth_expiry'] or words[5] != int(terms['point_x'], 16) or words[6] != int(terms['point_y'], 16) or words[7] != int(commitment, 16):
                raise RuntimeError('restored order differs from committed agreement')
            state = words[4]
            sent = 0
            if state == 2:
                logs = evm.rpc('eth_getLogs', [{'address': contract, 'fromBlock': '0x0',
                    'toBlock': 'latest', 'topics': [topic('Claimed(bytes32,uint256)'), order]}])
                if len(logs) != 1 or logs[0].get('removed', False):
                    raise RuntimeError('canonical public witness unavailable')
                receipt = evm.rpc('eth_getTransactionReceipt', [logs[0]['transactionHash']])
                if receipt is None or receipt['status'] != '0x1':
                    raise RuntimeError('public witness receipt unavailable')
                witness = int(logs[0]['data'], 16).to_bytes(32, 'little').hex()
                # Does not read Alice's directory or spend share.
                native_txid, native_sent = native_exit(swap, 'claim', witness)
                mode, owner, receiver = 'success', agreement['recipient'], swap / 'bob'
                observed_from_public_event = True
            elif state in (1, 3):
                if state == 1:
                    current = int(evm.rpc('eth_getBlockByNumber', ['latest', False])['timestamp'], 16)
                    if current < agreement['eth_expiry']:
                        evm.rpc('evm_setNextBlockTimestamp', [agreement['eth_expiry']])
                        evm.rpc('evm_mine')
                    send_evm(directory, {'from': agreement['maker'], 'to': contract, 'gas': hex(200_000),
                        'data': evm.calldata('refund(bytes32)', order)})
                    sent += 1
                missing = max(0, terms['refund_height'] + 1 - status()['blocks'])
                if missing:
                    zrpc('generate', [missing], timeout=300)
                native_txid, native_sent = native_exit(swap, 'refund')
                mode, owner, receiver = 'refund', agreement['maker'], swap / 'alice'
                observed_from_public_event = False
            else:
                raise RuntimeError('restored order is not funded')
            scanned = capture(receiver)
            notes = json.loads(Path(scanned['file']).read_text())['notes']
            if not any(n['txid'] == native_txid and n['value'] == 1_000_000 for n in notes):
                raise RuntimeError('recovered native amount not decrypted by recipient')
            credit = int(evm.rpc('eth_call', [{'to': contract, 'data': evm.calldata('credits(address)', owner)}, 'latest']), 16)
            if credit == 10**16:
                before = int(evm.rpc('eth_getBalance', [owner, 'latest']), 16)
                withdrawn = send_evm(directory, {'from': owner, 'to': contract, 'gas': hex(200_000),
                    'data': evm.calldata('withdraw(address)', owner)})
                sent += 1
                after = int(evm.rpc('eth_getBalance', [owner, 'latest']), 16)
                fee = int(withdrawn['gasUsed'], 16) * int(withdrawn['effectiveGasPrice'], 16)
                if after - before + fee != 10**16:
                    raise RuntimeError('recovered ETH amount differs')
            elif credit == 0:
                owner_topic = '0x' + owner.removeprefix('0x').lower().zfill(64)
                logs = evm.rpc('eth_getLogs', [{'address': contract, 'fromBlock': '0x0', 'toBlock': 'latest',
                    'topics': [topic('Withdrawn(address,address,uint256)'), owner_topic, owner_topic]}])
                if not any(int(log['data'], 16) == 10**16 and not log.get('removed', False) for log in logs):
                    raise RuntimeError('zero credit without a verified previous withdrawal')
            else:
                raise RuntimeError('unexpected recovery credit')
            result = {'scope': 'resumed owned local chains; not public-network reorg proof',
                'mode': mode, 'public_testnet': False, 'same_host_setup': True,
                'independent_signer_processes': terms.get('independent_signer_processes', False),
                'native_txid': native_txid, 'native_amount_zatoshi': 1_000_000,
                'native_canonical_with_at_least_two_confirmations': True,
                'eth_wei_received': 10**16, 'witness_recovered_from_public_event': observed_from_public_event,
                'no_peer_spend_signature_requested_during_recovery': True,
                'zec_principal_shielded': True, 'refund_has_transparent_auxiliary': True}
            save(directory / '09-recovered.json', result)
            if not (directory / '08-complete.json').exists():
                save(directory / '08-complete.json', result)
            return {**result, 'new_native_transactions': int(native_sent), 'new_evm_transactions': sent}
        finally:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    with (ROOT / '.local/chain-driver.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        print(json.dumps(recover(args.directory.resolve()), indent=2))
