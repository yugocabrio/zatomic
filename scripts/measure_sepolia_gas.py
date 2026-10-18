#!/usr/bin/env python3
"""Measure PointEscrow gas on CURRENT Sepolia rules with eth_simulateV1.

Read-only: simulated calls against the provider's latest state; nothing is
signed or sent, and no key or wallet is read. Uses fresh test scalars only
(never a swap secret), including the worst case 2^254-1 (most point additions
in Pallas.opens). Fails unless every signed limit keeps at least 15% headroom.
Re-run right before a public deployment: testnet gas schedules change.
"""
import json
import secrets
import subprocess
from pathlib import Path

RPC = 'https://ethereum-sepolia-rpc.publicnode.com'
ROOT = Path(__file__).resolve().parents[1]
HEADROOM = 1.15
P = 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001
Q = 0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001
G = (0x375523b328f1d6063b8d187c3e5f445f0c7f0ce37b70a10c8d1a7284b875c963,
     0x1ad0357fdf1a66db7b10bcfcfed624fbdfc914fec005bdd84ce33e817b0c3bc9)
DEPLOYER = '0x1031f99883aad2746869f019a10b228c1c28fa44'
ALICE = '0x4c0fda0c71f0444e8890cc128bc0f6a78c588f7b'
BOB = '0x752bd47a7608944fe21895060e71b8b6c09c370c'
AMOUNT = 10**15


def add(a, b):
    if a is None: return b
    if b is None: return a
    if a[0] == b[0] and (a[1] + b[1]) % P == 0: return None
    if a == b:
        m = 3 * a[0] * a[0] * pow(2 * a[1], -1, P) % P
    else:
        m = (b[1] - a[1]) * pow(b[0] - a[0], -1, P) % P
    x = (m * m - a[0] - b[0]) % P
    return (x, (m * (a[0] - x) - a[1]) % P)


def mul(k, point=G):
    r = None
    for bit in bin(k)[2:]:
        r = add(r, r)
        if bit == '1': r = add(r, point)
    return r


def call(method, params):
    out = subprocess.run(['curl', '-s', '-m', '60', '-X', 'POST', RPC, '-H', 'Content-Type: application/json',
        '--data-binary', '@-'], input=json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}),
        capture_output=True, text=True, check=True).stdout
    reply = json.loads(out)
    if 'error' in reply: raise RuntimeError(f'{method}: {reply["error"]}')
    return reply['result']


def cast(*args):
    return subprocess.run(['cast', *map(str, args)], capture_output=True, text=True, check=True).stdout.strip()


def main():
    art = json.loads((ROOT / '.local/forge-out/PointEscrow.sol/PointEscrow.json').read_text())
    code = art['bytecode']['object']; code = code if code.startswith('0x') else '0x' + code
    contract = cast('compute-address', DEPLOYER, '--nonce', 0).split()[-1].lower()
    latest = call('eth_getBlockByNumber', ['latest', False])
    now = int(latest['timestamp'], 16)
    refund_at = now + 6 * 3600
    rich = {'balance': hex(10**18)}
    overrides = {DEPLOYER: rich, ALICE: rich, BOB: rich}
    results = {'block': int(latest['number'], 16), 'deploy': [], 'lock': [], 'claim': {}, 'withdraw_alice': [],
               'refund': [], 'withdraw_bob': []}
    scalars = {'worst_case_2^254-1': 2**254 - 1}
    for i in range(5):
        scalars[f'random_{i}'] = secrets.randbelow(Q - 1) + 1
    for name, t in scalars.items():
        T = mul(t)
        salt = '0x' + secrets.token_hex(32)
        terms = '0x' + secrets.token_hex(32)
        order = cast('keccak', cast('abi-encode', 'f(uint256,address,address,bytes32)', 11155111, contract, BOB, salt))
        lock = cast('calldata', 'lock(bytes32,address,uint64,(uint256,uint256),bytes32)', salt, ALICE, refund_at,
            f'({T[0]},{T[1]})', terms)
        claim = cast('calldata', 'claim(bytes32,uint256)', order, t)
        withdraw_a = cast('calldata', 'withdraw(address)', ALICE)
        refund = cast('calldata', 'refund(bytes32)', order)
        withdraw_b = cast('calldata', 'withdraw(address)', BOB)
        success = call('eth_simulateV1', [{'blockStateCalls': [{'stateOverrides': overrides, 'calls': [
            {'from': DEPLOYER, 'data': code, 'gas': hex(30_000_000)},
            {'from': BOB, 'to': contract, 'data': lock, 'value': hex(AMOUNT), 'gas': hex(5_000_000)},
            {'from': ALICE, 'to': contract, 'data': claim, 'gas': hex(5_000_000)},
            {'from': ALICE, 'to': contract, 'data': withdraw_a, 'gas': hex(5_000_000)}]}],
            'validation': False}, 'latest'])
        calls = success[0]['calls']
        if any(c['status'] != '0x1' for c in calls): raise RuntimeError(f'{name}: simulated success path failed: {calls}')
        gas = [int(c['gasUsed'], 16) for c in calls]
        if name == 'worst_case_2^254-1':
            no_reveal = call('eth_simulateV1', [{'blockStateCalls': [
                {'stateOverrides': overrides, 'calls': [
                    {'from': DEPLOYER, 'data': code, 'gas': hex(30_000_000)},
                    {'from': BOB, 'to': contract, 'data': lock, 'value': hex(AMOUNT), 'gas': hex(5_000_000)}]},
                {'blockOverrides': {'time': hex(refund_at + 60)}, 'calls': [
                    {'from': BOB, 'to': contract, 'data': refund, 'gas': hex(5_000_000)},
                    {'from': BOB, 'to': contract, 'data': withdraw_b, 'gas': hex(5_000_000)}]}],
                'validation': False}, 'latest'])
            later = no_reveal[1]['calls']
            if any(c['status'] != '0x1' for c in later): raise RuntimeError(f'refund path failed: {later}')
            results['refund'].append(int(later[0]['gasUsed'], 16))
            results['withdraw_bob'].append(int(later[1]['gasUsed'], 16))
        results['deploy'].append(gas[0]); results['lock'].append(gas[1])
        results['claim'][name] = gas[2]; results['withdraw_alice'].append(gas[3])
    return results


def check(results):
    import fee_policy
    import public_deploy
    limits = dict(fee_policy.DEFAULT['gas_limits'], deploy=public_deploy.GAS)
    worst = {'deploy': max(results['deploy']), 'lock': max(results['lock']),
        'claim': max(results['claim'].values()), 'refund': max(results['refund']),
        'withdraw': max(results['withdraw_alice'] + results['withdraw_bob'])}
    short = {k: (worst[k], limits[k]) for k in worst if worst[k] * HEADROOM > limits[k]}
    if short:
        raise SystemExit(f'gas limits lack 15% headroom on current Sepolia: {short}')
    return {'measured_worst': worst, 'limits': limits, 'headroom_ok': True,
        'block': results['block'], 'broadcast': False}


if __name__ == '__main__':
    measured = main()
    print(json.dumps({'measured': measured, 'check': check(measured)}, indent=1))
