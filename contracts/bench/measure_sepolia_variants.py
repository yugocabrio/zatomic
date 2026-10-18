#!/usr/bin/env python3
"""Gas of the shipped escrow and the benchmark variants on CURRENT Sepolia rules (BENCHMARK ONLY).

Read-only: eth_simulateV1 against one pinned Sepolia block, the way
scripts/measure_sepolia_gas.py does. Nothing is signed or broadcast and no key
or wallet is read. The deployer, maker and recipient are fresh random addresses
that exist only through balance overrides. Every simulation starts from the
pinned state and deploys what it needs: PallasCombTable{t} (nonce 0) and the
escrow, then lock -> claim -> withdraw, or lock -> (block at refundAt + 60) ->
refund -> withdraw. Matrix and scalars: escrow_bench.py. The benchmark bytecode
is sent to the RPC provider. Writes contracts/bench/sepolia-gas-results.json.

  python3 contracts/bench/measure_sepolia_variants.py [--rpc URL]
"""
import argparse
import json
import secrets
import subprocess
import time

from escrow_bench import (AMOUNT, HERE, MAIN, REFUND_SCALARS, SWEEP, SWEEP_SCALARS, cast, empty_steps,
                          escrow_initcode, key, order_id, scalars, summary, swap_calldata, table_initcode)

CHAIN_ID = 11155111
SHIPPED_RUNTIME_HASH = '0x6267f59be4896a2d311e0eb7bdf9bfb5ada76fcecb140ac6589aaee8a85b569a'
GAS = {'table': 40_000_000, 'escrow': 15_000_000, 'lock': 3_000_000, 'claim': 3_000_000, 'small': 1_000_000}


class Rpc:
    def __init__(self, url):
        self.url = url

    def __call__(self, method, params):
        for attempt in range(6):
            out = subprocess.run(['curl', '-s', '-m', '120', '-X', 'POST', self.url, '-H',
                                  'Content-Type: application/json', '--data-binary', '@-'],
                                 input=json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}),
                                 capture_output=True, text=True).stdout
            try:
                reply = json.loads(out)
            except ValueError:
                reply = {'error': {'message': f'unparsable reply: {out[:200]!r}'}}
            if 'error' not in reply: return reply['result']
            if attempt == 5 or 'rate' not in str(reply['error']).lower() and 'unparsable' not in str(reply['error']):
                raise RuntimeError(f'{method}: {reply["error"]}')
            time.sleep(2 + 3 * attempt)


def simulate(rpc, block, overrides, blocks):
    """blocks: list of (block_overrides or None, [call, ...]); returns the per-block call results."""
    states = []
    for i, (block_overrides, calls) in enumerate(blocks):
        state = {'calls': calls}
        if i == 0: state['stateOverrides'] = overrides
        if block_overrides: state['blockOverrides'] = block_overrides
        states.append(state)
    result = rpc('eth_simulateV1', [{'blockStateCalls': states, 'validation': False}, block])
    out = []
    for b in result:
        for c in b['calls']:
            if c['status'] != '0x1': raise RuntimeError(f'simulated call failed: {c}')
        out.append(b['calls'])
    return out


def one(rpc, block, now, who, name, teeth, k, path):
    deployer, bob, alice = who
    overrides = {a: {'balance': hex(10**20), 'nonce': '0x0'} for a in who}
    calls, nonce, table = [], 0, None
    if teeth:
        table = cast('compute-address', deployer, '--nonce', 0).split()[-1].lower()
        calls.append({'from': deployer, 'data': table_initcode(teeth), 'gas': hex(GAS['table'])})
        nonce = 1
    escrow = cast('compute-address', deployer, '--nonce', nonce).split()[-1].lower()
    calls.append({'from': deployer, 'data': escrow_initcode(name, table, teeth), 'gas': hex(GAS['escrow'])})
    salt, terms = '0x' + secrets.token_hex(32), '0x' + secrets.token_hex(32)
    refund_at = now + 6 * 3600
    data = swap_calldata(name, order_id(CHAIN_ID, escrow, bob, salt), bob, alice, k, refund_at, salt, terms)
    calls.append({'from': bob, 'to': escrow, 'data': data['lock'], 'value': hex(AMOUNT), 'gas': hex(GAS['lock'])})
    if path == 'claim':
        calls += [{'from': alice, 'to': escrow, 'data': data['claim'], 'gas': hex(GAS['claim'])},
                  {'from': alice, 'to': escrow, 'data': data['withdraw_recipient'], 'gas': hex(GAS['small'])}]
        blocks = [(None, calls)]
    else:
        blocks = [(None, calls), ({'time': hex(refund_at + 60)}, [
            {'from': bob, 'to': escrow, 'data': data['refund'], 'gas': hex(GAS['small'])},
            {'from': bob, 'to': escrow, 'data': data['withdraw_maker'], 'gas': hex(GAS['small'])}])]
    res = simulate(rpc, block, overrides, blocks)
    first = res[0]
    deployed = first[1 if teeth else 0]
    # The escrow constructor reverts unless the table's code hash matches; check the
    # shipped runtime against its pin and that the swap calls ran inside the escrow.
    if name == 'shipped' and cast('keccak', deployed['returnData']) != SHIPPED_RUNTIME_HASH:
        raise RuntimeError('shipped runtime hash mismatch')
    later = first[2 if teeth else 1:] + (res[1] if len(res) > 1 else [])
    for c in later:
        if not any(log['address'].lower() == escrow for log in c['logs']):
            raise RuntimeError(f'call did not log from the escrow {escrow}: {c}')
    gas = [int(c['gasUsed'], 16) for c in first]
    out = {'table': gas[0] if teeth else None, 'escrow': gas[1 if teeth else 0]}
    rest = [int(c['gasUsed'], 16) for c in later]
    out.update(dict(zip(('lock', 'claim', 'withdraw') if path == 'claim' else ('lock', 'refund', 'withdraw'), rest)))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--rpc', default='https://ethereum-sepolia-rpc.publicnode.com')
    rpc = Rpc(ap.parse_args().rpc)
    latest = rpc('eth_getBlockByNumber', ['latest', False])
    block, now = latest['number'], int(latest['timestamp'], 16)
    config = rpc('eth_config', [])['current']
    who = tuple('0x' + secrets.token_hex(20) for _ in range(3))
    ks = scalars()
    results = {}
    for name, teeth in MAIN + SWEEP:
        steps = empty_steps()
        labels = ks if (name, teeth) in MAIN else SWEEP_SCALARS
        for label in labels:
            paths = ('claim', 'refund') if (name, teeth) in MAIN and label in REFUND_SCALARS else ('claim',)
            for path in paths:
                g = one(rpc, block, now, who, name, teeth, ks[label], path)
                if teeth: steps['deploy_table'].append(g['table'])
                steps['deploy_escrow'].append(g['escrow'])
                steps['lock'].append(g['lock'])
                if path == 'claim':
                    steps['claim'][label] = g['claim']
                    steps['withdraw'].append(g['withdraw'])
                else:
                    steps['refund'].append(g['refund'])
                    steps['refund_withdraw'].append(g['withdraw'])
                time.sleep(0.3)
        results[key(name, teeth)] = steps
        print(key(name, teeth), 'done', flush=True)
    report = {
        'rpc': rpc.url, 'client': rpc('web3_clientVersion', []),
        'block': int(block, 16), 'block_timestamp': now,
        'fork': {'activation_time': config['activationTime'], 'fork_id': config['forkId']},
        'method': 'eth_simulateV1 (validation false) at the pinned block; fresh addresses with balance '
                  'overrides; each simulation deploys its own table and escrow',
        'addresses_without_keys': dict(zip(('deployer', 'maker', 'recipient'), who)),
        'gas_limits_per_call': GAS,
        'claim_scalars': {k: hex(v) for k, v in ks.items()},
        'summary': summary(results), 'raw': results, 'broadcast': False}
    (HERE / 'sepolia-gas-results.json').write_text(json.dumps(report, indent=1) + '\n')
    print(json.dumps({k: report[k] for k in ('client', 'block', 'fork')}, indent=1))
    print(json.dumps(report['summary'], indent=1))


if __name__ == '__main__':
    main()
