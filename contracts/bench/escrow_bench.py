"""Shared pieces of the escrow gas benchmarks (BENCHMARK ONLY).

Both measure_escrow_gas.py (real transactions on a private Anvil) and
measure_sepolia_variants.py (eth_simulateV1 on current Sepolia state) run the
same matrix:
  main   shipped PointEscrow, PointEscrowFast t=8, HashedPointEscrow t=8;
         lock -> claim -> withdraw for every scalar in SCALARS, and
         lock -> refund -> withdraw for REFUND_SCALARS
  sweep  PointEscrowFast and HashedPointEscrow at t = 4..7;
         lock -> claim -> withdraw for SWEEP_SCALARS
Test scalars only. Artifacts come from .local/forge-out (run `forge build`).
"""
import json
import random
import statistics
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
OUT = ROOT / '.local/forge-out'
sys.path.insert(0, str(HERE.parent / 'tools'))
from gen_comb_tables import Q, mul  # noqa: E402

AMOUNT = 10**15
LOCK = 'lock(bytes32,address,uint64,(uint256,uint256),bytes32)'
ORDER = '(address,address,uint256,uint64,(uint256,uint256),bytes32)'
ARTIFACT = {'shipped': 'PointEscrow.sol/PointEscrow.json', 'fast': 'PointEscrowFast.sol/PointEscrowFast.json',
            'hashed': 'HashedPointEscrow.sol/HashedPointEscrow.json'}
MAIN = [('shipped', None), ('fast', 8), ('hashed', 8)]
SWEEP = [(name, t) for t in range(4, 8) for name in ('fast', 'hashed')]
REFUND_SCALARS = ('worst_case_2^254-1', 'random_0')
SWEEP_SCALARS = ('worst_case_2^254-1', 'random_0', 'random_1')


def scalars():
    rng = random.Random(20261018)
    out = {'worst_case_2^254-1': 2**254 - 1, 'q_minus_1': Q - 1, 'one': 1}
    for i in range(8):
        out[f'random_{i}'] = rng.randrange(1, Q)
    return out


def key(name, teeth):
    return name if teeth is None else f'{name}_t{teeth}'


def cast(*args):
    return subprocess.run(['cast', *map(str, args)], capture_output=True, text=True, check=True).stdout.strip()


def initcode(artifact):
    code = json.loads((OUT / artifact).read_text())['bytecode']['object']
    return code if code.startswith('0x') else '0x' + code


def table_initcode(teeth):
    return initcode(f'PallasCombTables.sol/PallasCombTable{teeth}.json')


def escrow_initcode(name, table=None, teeth=None):
    code = initcode(ARTIFACT[name])
    if teeth is None: return code
    return code + table[2:].lower().rjust(64, '0') + hex(teeth)[2:].rjust(64, '0')


def order_id(chain_id, escrow, maker, salt):
    return cast('keccak', cast('abi-encode', 'f(uint256,address,address,bytes32)', chain_id, escrow, maker, salt))


def swap_calldata(name, oid, maker, recipient, k, refund_at, salt, terms):
    """Calldata for lock, claim, refund and withdraw(to) of one order."""
    x, y = mul(k)
    order = f'({maker},{recipient},{AMOUNT},{refund_at},({x},{y}),{terms})'
    hashed = name == 'hashed'
    return {
        'lock': cast('calldata', LOCK, salt, recipient, refund_at, f'({x},{y})', terms),
        'claim': cast('calldata', f'claim(bytes32,{ORDER},uint256)', oid, order, k) if hashed
        else cast('calldata', 'claim(bytes32,uint256)', oid, k),
        'refund': cast('calldata', f'refund(bytes32,{ORDER})', oid, order) if hashed
        else cast('calldata', 'refund(bytes32)', oid),
        'withdraw_recipient': cast('calldata', 'withdraw(address)', recipient),
        'withdraw_maker': cast('calldata', 'withdraw(address)', maker),
    }


def empty_steps():
    return {'deploy_escrow': [], 'deploy_table': [], 'lock': [], 'claim': {}, 'withdraw': [],
            'refund': [], 'refund_withdraw': []}


def summary(results):
    rows = {}
    for k, s in results.items():
        if not isinstance(s, dict) or 'claim' not in s: continue
        rand = [v for n, v in s['claim'].items() if n.startswith('random')]
        lock, withdraw = max(s['lock']), max(s['withdraw'] + s['refund_withdraw'])
        row = {'deploy_escrow': max(s['deploy_escrow']), 'lock': [min(s['lock']), lock],
               'claim_random_median': int(statistics.median(rand)), 'claim_random_range': [min(rand), max(rand)],
               'claim_worst_case_2^254-1': s['claim']['worst_case_2^254-1'], 'random_scalars': len(rand),
               'withdraw': [min(s['withdraw'] + s['refund_withdraw']), withdraw]}
        if s['deploy_table']: row['deploy_table'] = max(s['deploy_table'])
        row['swap_random_median'] = lock + row['claim_random_median'] + withdraw
        row['swap_worst_case'] = lock + row['claim_worst_case_2^254-1'] + withdraw
        if s['refund']:
            row['refund'] = [min(s['refund']), max(s['refund'])]
            row['refund_path'] = lock + max(s['refund']) + max(s['refund_withdraw'])
        rows[k] = row
    return rows
