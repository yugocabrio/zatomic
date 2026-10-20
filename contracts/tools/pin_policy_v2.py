#!/usr/bin/env python3
"""Write config/public-agreement-policy-v2.json from v1 and the built PointEscrowV2.

Run after `forge build`. Everything except the escrow block is copied from v1
unchanged: clock, fee and observation policies are the same profile. The escrow
block pins the v2 creation/runtime code, the width-4 comb table and the sources.
"""
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
SOURCES = ('contracts/src/Pallas.sol', 'contracts/src/PallasComb.sol',
           'contracts/src/PallasCombTables.sol', 'contracts/src/PointEscrowV2.sol')


def keccak(hex_code):
    return subprocess.run(['cast', 'keccak', hex_code], capture_output=True, text=True, check=True).stdout.strip()


def main():
    v1 = json.loads((ROOT / 'config/public-agreement-policy-v1.json').read_text())
    art = json.loads((ROOT / '.local/forge-out/PointEscrowV2.sol/PointEscrowV2.json').read_text())
    table = [line for line in (ROOT / 'contracts/src/PallasCombTables.sol').read_text().splitlines()
             if 'CODEHASH_4 =' in line]
    if len(table) != 1:
        raise SystemExit('width-4 table hash not found')
    policy = dict(v1, format='latch-public-agreement-policy-v2')
    # v2 also pins the reviewed short public-testnet timing profile.
    import sys
    sys.path.insert(0, str(ROOT / 'scripts'))
    import timestamp_policy
    policy['timestamp_policy_short'] = timestamp_policy.SHORT
    policy['escrow'] = {
        'version': 2,
        'contract_name': 'PointEscrowV2',
        'chain_id': v1['escrow']['chain_id'],
        'genesis': v1['escrow']['genesis'],
        'compiler': v1['escrow']['compiler'],
        'creation_code_hash': keccak(art['bytecode']['object']),
        'runtime_code_hash': keccak(art['deployedBytecode']['object']),
        'table_code_hash': table[0].split('=')[1].strip().rstrip(';'),
        'source_sha256': {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in SOURCES},
    }
    (ROOT / 'config/public-agreement-policy-v2.json').write_text(json.dumps(policy, indent=2) + '\n')
    print(json.dumps(policy['escrow'], indent=2))


if __name__ == '__main__':
    main()
