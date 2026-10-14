#!/usr/bin/env python3
"""Real local EVM witness -> real native proof over a SYNTHETIC Zcash note.

This gate does not broadcast Zcash and does not establish chain-level atomicity.
It owns one ephemeral Anvil child; it never connects to a public endpoint.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'target/release/shielded-swap-native'
PORT = 18545
CHAIN = 31338
URL = f'http://127.0.0.1:{PORT}'


def rpc(method, params=None):
    request = urllib.request.Request(URL, json.dumps({
        'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params or []
    }).encode(), {'Content-Type': 'application/json'})
    with urllib.request.urlopen(request, timeout=30) as response:
        value = json.load(response)
    if value.get('error'):
        raise RuntimeError(f'{method}: {value["error"]}')
    return value['result']


def calldata(signature, *args):
    return subprocess.check_output(['cast', 'calldata', signature, *map(str, args)],
                                   text=True, cwd=ROOT).strip()


def send(tx):
    tx_hash = rpc('eth_sendTransaction', [tx])
    for _ in range(100):
        receipt = rpc('eth_getTransactionReceipt', [tx_hash])
        if receipt:
            if receipt['status'] != '0x1':
                raise RuntimeError(f'local EVM transaction reverted: {tx_hash}')
            return receipt
        time.sleep(.1)
    raise RuntimeError('local receipt timeout')


def native(*args):
    env = dict(os.environ, RAYON_NUM_THREADS='2')
    return json.loads(subprocess.check_output([str(NATIVE), *map(str, args)],
                                              cwd=ROOT, env=env, text=True))


def run(directory):
    os.umask(0o077)
    if directory.exists():
        raise RuntimeError('use a new private fixture directory')
    # Check before spawning; never attach to or terminate an unrelated process.
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', PORT))
    prepared = native('prepare-synthetic', directory)
    alice = json.loads((directory / 'alice.json').read_text())
    artifact = json.loads((ROOT / '.local/forge-out/PointEscrow.sol/PointEscrow.json').read_text())
    with (directory / 'anvil.log').open('x') as log:
        process = subprocess.Popen(['anvil', '--host', '127.0.0.1', '--port', str(PORT),
                                    '--chain-id', str(CHAIN), '--silent'],
                                   cwd=ROOT, stdout=log, stderr=log)
        try:
            for _ in range(100):
                if process.poll() is not None:
                    raise RuntimeError('our Anvil child exited')
                try:
                    if int(rpc('eth_chainId'), 16) == CHAIN:
                        break
                except (OSError, RuntimeError):
                    pass
                time.sleep(.1)
            else:
                raise RuntimeError('our Anvil child did not start')
            bob, recipient, relayer = rpc('eth_accounts')[:3]
            deployment = send({'from': bob, 'data': artifact['bytecode']['object'],
                               'gas': hex(5_000_000)})
            contract = deployment['contractAddress']
            now = int(rpc('eth_getBlockByNumber', ['latest', False])['timestamp'], 16)
            terms = '0x' + hashlib.sha256(json.dumps(prepared, sort_keys=True).encode()).hexdigest()
            salt = '0x' + os.urandom(32).hex()
            amount = 10**16
            locked = send({'from': bob, 'to': contract, 'value': hex(amount),
                'gas': hex(700_000), 'data': calldata(
                    'lock(bytes32,address,uint64,(uint256,uint256),bytes32)', salt,
                    recipient, now + 3600, f'({alice["point_x"]},{alice["point_y"]})', terms)})
            order_id = locked['logs'][0]['topics'][1]
            claimed = send({'from': relayer, 'to': contract, 'gas': hex(1_000_000),
                'data': calldata('claim(bytes32,uint256)', order_id, alice['witness_uint256'])})
            if len(claimed['logs']) != 1 or claimed['logs'][0]['topics'][1] != order_id:
                raise RuntimeError('unexpected claim event')
            # Bob reads the on-chain event, not Alice's local secret file.
            witness = int(claimed['logs'][0]['data'], 16).to_bytes(32, 'little').hex()
            credit = int(rpc('eth_call', [{'to': contract,
                'data': calldata('credits(address)', recipient)}, 'latest']), 16)
            thief_credit = int(rpc('eth_call', [{'to': contract,
                'data': calldata('credits(address)', relayer)}, 'latest']), 16)
            if credit != amount or thief_credit != 0:
                raise RuntimeError('fixed recipient failed')
            # Separate process has only Bob's prepared data and public witness.
            completed = native('complete-synthetic', directory, witness)
            before = int(rpc('eth_getBalance', [recipient, 'latest']), 16)
            withdrawal = send({'from': recipient, 'to': contract, 'gas': hex(200_000),
                               'data': calldata('withdraw(address)', recipient)})
            after = int(rpc('eth_getBalance', [recipient, 'latest']), 16)
            fee = int(withdrawal['gasUsed'], 16) * int(withdrawal['effectiveGasPrice'], 16)
            if after - before + fee != amount:
                raise RuntimeError('recipient did not receive exact ETH')
            summary = {'scope': 'Anvil real transactions + synthetic Zcash note/proof',
                'public_network': False, 'native_chain_acceptance': False,
                'prepare': prepared, 'native': completed,
                'evm': {'chain_id': CHAIN, 'contract': contract, 'order_id': order_id,
                    'lock_tx': locked['transactionHash'], 'claim_tx': claimed['transactionHash'],
                    'withdraw_tx': withdrawal['transactionHash'], 'fixed_recipient': True,
                    'withdrawn_wei': amount, 'claim_gas': int(claimed['gasUsed'], 16)},
                'bob_used_public_evm_event': True}
            (directory / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
            return summary
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
    print(json.dumps(run(parser.parse_args().directory.resolve()), indent=2))
