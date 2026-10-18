#!/usr/bin/env python3
"""Receipt gas of the shipped escrow and the benchmark variants on Anvil (BENCHMARK ONLY).

Starts a private Anvil (default hardfork) on a free localhost port, deploys
from the forge artifacts in .local/forge-out (run `forge build` first), and
sends real transactions from Anvil's unlocked dev accounts (no key is read or
written):
  shipped  contracts/src/PointEscrow.sol            Pallas.opens, 7-slot order
  fast     contracts/bench/PointEscrowFast.sol      PallasComb comb, 7-slot order
  hashed   contracts/bench/HashedPointEscrow.sol    PallasComb comb, 1-slot order hash
Each comb table PallasCombTable{4..8} is deployed once and shared by every
escrow of that width. Matrix and scalars: escrow_bench.py. Prints the summary
and writes contracts/bench/gas-results.json.
"""
import json
import random
import socket
import subprocess
import time
import urllib.request

from escrow_bench import (HERE, MAIN, REFUND_SCALARS, ROOT, SWEEP, SWEEP_SCALARS, empty_steps, escrow_initcode,
                          key, scalars, summary, swap_calldata, table_initcode, cast, AMOUNT)


def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


class Node:
    def __init__(self, url):
        self.url = url

    def rpc(self, method, params):
        body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}).encode()
        req = urllib.request.Request(self.url, body, {'Content-Type': 'application/json'})
        reply = json.loads(urllib.request.urlopen(req, timeout=60).read())
        if 'error' in reply: raise RuntimeError(f'{method}: {reply["error"]}')
        return reply['result']

    def send(self, sender, data, to=None, value=0):
        tx = {'from': sender, 'data': data, 'gas': hex(29_000_000), 'value': hex(value)}
        if to: tx['to'] = to
        txid = self.rpc('eth_sendTransaction', [tx])
        for _ in range(200):
            receipt = self.rpc('eth_getTransactionReceipt', [txid])
            if receipt: break
            time.sleep(0.02)
        if not receipt or receipt['status'] != '0x1': raise RuntimeError(f'not included or reverted: {receipt}')
        return receipt

    def gas(self, *args, **kwargs):
        return int(self.send(*args, **kwargs)['gasUsed'], 16)

    def now(self):
        return int(self.rpc('eth_getBlockByNumber', ['latest', False])['timestamp'], 16)


def measure(node, accounts):
    deployer, bob, alice = accounts[:3]
    rng = random.Random(1)
    ks = scalars()
    tables, results = {}, {}
    for t in range(4, 9):
        receipt = node.send(deployer, table_initcode(t))
        tables[t] = (receipt['contractAddress'], int(receipt['gasUsed'], 16))
    for name, teeth in MAIN + SWEEP:
        steps = empty_steps()
        table = tables[teeth][0] if teeth else None
        if teeth: steps['deploy_table'].append(tables[teeth][1])
        deployed = node.send(deployer, escrow_initcode(name, table, teeth))
        escrow = deployed['contractAddress']
        steps['deploy_escrow'].append(int(deployed['gasUsed'], 16))
        labels = ks if (name, teeth) in MAIN else SWEEP_SCALARS
        for label in labels:
            paths = ('claim', 'refund') if (name, teeth) in MAIN and label in REFUND_SCALARS else ('claim',)
            for path in paths:
                salt, terms = '0x' + rng.randbytes(32).hex(), '0x' + rng.randbytes(32).hex()
                refund_at = node.now() + 1800
                oid = cast('call', '--rpc-url', node.url, escrow, 'orderId(address,bytes32)(bytes32)', bob, salt)
                data = swap_calldata(name, oid, bob, alice, ks[label], refund_at, salt, terms)
                steps['lock'].append(node.gas(bob, data['lock'], escrow, AMOUNT))
                if path == 'claim':
                    steps['claim'][label] = node.gas(alice, data['claim'], escrow)
                    steps['withdraw'].append(node.gas(alice, data['withdraw_recipient'], escrow))
                else:
                    node.rpc('evm_increaseTime', [1801])
                    node.rpc('evm_mine', [])
                    steps['refund'].append(node.gas(bob, data['refund'], escrow))
                    steps['refund_withdraw'].append(node.gas(bob, data['withdraw_maker'], escrow))
        results[key(name, teeth)] = steps
    results['deploy_tables'] = {f't{t}': gas for t, (_, gas) in tables.items()}
    results['runtime_bytes_table'] = {f't{t}': len(node.rpc('eth_getCode', [a, 'latest'])) // 2 - 1
                                      for t, (a, _) in tables.items()}
    return results


def main():
    port = free_port()
    log = open(ROOT / '.local/bench-anvil.log', 'w')
    proc = subprocess.Popen(['anvil', '--host', '127.0.0.1', '--port', str(port), '--silent',
                             '--gas-limit', '60000000'], stdout=log, stderr=log)
    try:
        node = Node(f'http://127.0.0.1:{port}')
        for _ in range(100):
            try:
                node.rpc('eth_chainId', [])
                break
            except OSError:
                time.sleep(0.1)
        info = node.rpc('anvil_nodeInfo', [])
        results = measure(node, node.rpc('eth_accounts', []))
    finally:
        proc.terminate()
        proc.wait(timeout=10)
        log.close()
    report = {
        'tool': {'anvil': cast('--version').splitlines()[0].replace('cast', 'foundry'),
                 'hardfork': info.get('hardFork') or info.get('hardfork'), 'chain_id': 31337},
        'method': 'receipt gasUsed of real Anvil transactions; tables shared by escrows of the same width',
        'claim_scalars': {k: hex(v) for k, v in scalars().items()},
        'summary': summary(results), 'raw': results}
    (HERE / 'gas-results.json').write_text(json.dumps(report, indent=1) + '\n')
    print(json.dumps({'summary': report['summary'], 'deploy_tables': results['deploy_tables'],
                      'tool': report['tool']}, indent=1))


if __name__ == '__main__':
    main()
