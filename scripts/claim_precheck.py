"""Run a claim against the pinned escrow bytecode on a private, throwaway Anvil.

Before Alice's first exposure of t, a false rejection by the on-chain verifier
would publish t in a reverted transaction while paying her nothing. This check
executes the exact pinned creation code (v2: escrow plus its comb table) on an
ephemeral local node owned by this process, locks an order to the agreed point
and calls claim with t. The witness travels only over loopback HTTP to that
child process: never argv, never a provider, never the agreed chain's node.
"""
import json
import socket
import subprocess
import time
import urllib.request
import escrow_abi


def _free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def verify(v, witness, x, y):
    port = _free_port()
    url = f'http://127.0.0.1:{port}'

    def rpc(method, params):
        body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}).encode()
        request = urllib.request.Request(url, body, {'Content-Type': 'application/json'})
        with urllib.request.urlopen(request, timeout=30) as response:
            value = json.load(response)
        if value.get('error'):
            raise RuntimeError('local claim pre-check rejected')
        return value['result']

    def mined(txid):
        for _ in range(100):
            receipt = rpc('eth_getTransactionReceipt', [txid])
            if receipt:
                if receipt['status'] != '0x1':
                    raise RuntimeError('local claim pre-check setup reverted')
                return receipt
            time.sleep(.05)
        raise RuntimeError('local claim pre-check timeout')

    process = subprocess.Popen(['anvil', '--host', '127.0.0.1', '--port', str(port), '--silent',
        '--chain-id', '31399'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(100):
            try:
                rpc('eth_chainId', [])
                break
            except OSError:
                time.sleep(.05)
        else:
            raise RuntimeError('local claim pre-check node did not start')
        sender = rpc('eth_accounts', [])[0]
        escrow = mined(rpc('eth_sendTransaction', [{'from': sender, 'data': escrow_abi.creation_code(v),
            'gas': hex(10_000_000)}]))['contractAddress']
        now = int(rpc('eth_getBlockByNumber', ['latest', False])['timestamp'], 16)
        salt, terms = '0x' + '01' * 32, '0x' + '02' * 32
        lock = ('0x' + escrow_abi.selector(escrow_abi.LOCK) + escrow_abi.bytes32_word(salt)
                + escrow_abi.address_word(sender) + escrow_abi.word(now + 3600) + escrow_abi.word(int(x, 16))
                + escrow_abi.word(int(y, 16)) + escrow_abi.bytes32_word(terms))
        mined(rpc('eth_sendTransaction', [{'from': sender, 'to': escrow, 'data': lock, 'value': '0x1',
            'gas': hex(1_000_000)}]))
        order_id = rpc('eth_call', [{'to': escrow, 'data': '0x' + escrow_abi.selector('orderId(address,bytes32)')
            + escrow_abi.address_word(sender) + escrow_abi.bytes32_word(salt)}, 'latest'])
        order = escrow_abi.order(sender, sender, 1, now + 3600, x, y, terms) if v == 2 else None
        data = escrow_abi.calldata(v, 'claim', order_id, order, witness=witness)
        rpc('eth_call', [{'from': sender, 'to': escrow, 'data': data, 'gas': hex(5_000_000)}, 'latest'])
        return True
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
