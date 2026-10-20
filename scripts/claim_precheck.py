"""Run a claim against the pinned escrow bytecode on a private, throwaway Anvil.

Before Alice's first exposure of t, a false rejection by the on-chain verifier
would publish t in a reverted transaction while paying her nothing. This check
executes the exact pinned creation code (v2: escrow plus its comb table) on an
ephemeral local node owned by this process, locks an order to the agreed point
and calls claim with t.

The witness travels only over a Unix socket inside a fresh 0700 directory under
the caller's private owner directory, never over TCP: another process cannot
win a port race and pose as the node (review H-1). The child must still be
alive and report its own chain id, and the deployed code must match the pinned
creation, runtime and table hashes (review L-1). The claim runs under the
signed claim gas limit. Callers run this BEFORE recording any claim decision,
so a failure here never marks t as exposed (review M-1).
"""
import json
import os
import shutil
import socket
import subprocess
import tempfile
import time
from pathlib import Path
import escrow_abi
import evm_wallet

CHAIN = 31399
POLICY = Path(__file__).resolve().parents[1] / 'config/public-agreement-policy-v2.json'


class _Node:
    def __init__(self, private_dir):
        self.dir = tempfile.mkdtemp(prefix='precheck-', dir=str(private_dir))
        os.chmod(self.dir, 0o700)
        self.path = os.path.join(self.dir, 'n.ipc')
        if len(self.path.encode()) > 100:
            raise RuntimeError('pre-check socket path too long')
        # HTTP binds an ephemeral loopback port that this check never uses.
        self.process = subprocess.Popen(['anvil', '--ipc', self.path, '--host', '127.0.0.1', '--port', '0',
            '--silent', '--chain-id', str(CHAIN)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.sock = None
        for _ in range(200):
            if self.process.poll() is not None:
                raise RuntimeError('local claim pre-check node exited')
            if os.path.exists(self.path):
                try:
                    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    s.settimeout(30)
                    s.connect(self.path)
                    self.sock = s
                    break
                except OSError:
                    s.close()
            time.sleep(.05)
        else:
            raise RuntimeError('local claim pre-check node did not start')
        if int(self.rpc('eth_chainId', []), 16) != CHAIN:
            raise RuntimeError('local claim pre-check node identity mismatch')

    def rpc(self, method, params):
        if self.process.poll() is not None:
            raise RuntimeError('local claim pre-check node exited')
        self.sock.sendall(json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}).encode() + b'\n')
        buffer, decoder = b'', json.JSONDecoder()
        while True:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise RuntimeError('local claim pre-check node closed the socket')
            buffer += chunk
            try:
                value, _ = decoder.raw_decode(buffer.decode().strip())
                break
            except ValueError:
                continue
        if value.get('error'):
            raise RuntimeError('local claim pre-check rejected')
        return value['result']

    def close(self):
        if self.sock:
            self.sock.close()
        self.process.terminate()
        try:
            self.process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()
        shutil.rmtree(self.dir, ignore_errors=True)


def _hash(hex_code):
    return '0x' + evm_wallet.keccak(bytes.fromhex(hex_code.removeprefix('0x'))).hex()


def verify(v, witness, x, y, private_dir, gas=1_000_000):
    if v != 2:
        raise RuntimeError('claim pre-check is defined for escrow v2')
    pins = json.loads(POLICY.read_text())['escrow']
    creation = escrow_abi.creation_code(v)
    if _hash(creation) != pins['creation_code_hash']:
        raise RuntimeError('local escrow artifact differs from the pinned creation code')
    node = _Node(private_dir)
    try:
        rpc = node.rpc

        def mined(txid):
            for _ in range(100):
                receipt = rpc('eth_getTransactionReceipt', [txid])
                if receipt:
                    if receipt['status'] != '0x1':
                        raise RuntimeError('local claim pre-check setup reverted')
                    return receipt
                time.sleep(.05)
            raise RuntimeError('local claim pre-check timeout')

        sender = rpc('eth_accounts', [])[0]
        escrow = mined(rpc('eth_sendTransaction', [{'from': sender, 'data': creation,
            'gas': hex(10_000_000)}]))['contractAddress']
        if _hash(rpc('eth_getCode', [escrow, 'latest'])) != pins['runtime_code_hash']:
            raise RuntimeError('local escrow runtime differs from the pinned hash')
        table = rpc('eth_call', [{'to': escrow, 'data': '0x' + escrow_abi.selector('combTable()')}, 'latest'])
        if _hash(rpc('eth_getCode', ['0x' + table[-40:], 'latest'])) != pins['table_code_hash']:
            raise RuntimeError('local comb table differs from the pinned hash')
        now = int(rpc('eth_getBlockByNumber', ['latest', False])['timestamp'], 16)
        salt, terms = '0x' + '01' * 32, '0x' + '02' * 32
        lock = ('0x' + escrow_abi.selector(escrow_abi.LOCK) + escrow_abi.bytes32_word(salt)
                + escrow_abi.address_word(sender) + escrow_abi.word(now + 3600) + escrow_abi.word(int(x, 16))
                + escrow_abi.word(int(y, 16)) + escrow_abi.bytes32_word(terms))
        mined(rpc('eth_sendTransaction', [{'from': sender, 'to': escrow, 'data': lock, 'value': '0x1',
            'gas': hex(1_000_000)}]))
        order_id = rpc('eth_call', [{'to': escrow, 'data': '0x' + escrow_abi.selector('orderId(address,bytes32)')
            + escrow_abi.address_word(sender) + escrow_abi.bytes32_word(salt)}, 'latest'])
        order = escrow_abi.order(sender, sender, 1, now + 3600, x, y, terms)
        data = escrow_abi.calldata(v, 'claim', order_id, order, witness=witness)
        rpc('eth_call', [{'from': sender, 'to': escrow, 'data': data, 'gas': hex(gas)}, 'latest'])
        return True
    finally:
        node.close()
