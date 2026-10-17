#!/usr/bin/env python3
"""No receiving viewing key reaches the counterparty or the coordinator.

Scans every JSON record of a finished browser/regtest run. Peers may hold the
shared one-time joint key and each other's one-time receive address. A
receiving FVK would let the counterparty follow the payout's later spends.
Reads local private files; prints only field names and counts.
"""
import json
from pathlib import Path
import sys

FORBIDDEN = ('alice_fvk', 'bob_fvk', 'recipient_fvk', 'receiver_fvk')


def walk(value, path, hits):
    if isinstance(value, dict):
        for key, item in value.items():
            if key in FORBIDDEN:
                hits.append(f'{path}:{key}')
            walk(item, path, hits)
    elif isinstance(value, list):
        for item in value:
            walk(item, path, hits)


def check(run):
    hits, scanned = [], 0
    for path in sorted(run.rglob('*.json')):
        try:
            value = json.loads(path.read_text())
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
        scanned += 1
        walk(value, str(path.relative_to(run)), hits)
    policy = json.loads((run / 'coordinator-native-offline/claim-policy.json').read_text())
    if hits or not {'alice_receiver', 'bob_receiver', 'joint_fvk'} <= set(policy):
        raise RuntimeError('receiving viewing key exposed: ' + ', '.join(hits[:5]))
    return {'scope': 'one finished local run', 'json_records_scanned': scanned,
        'receiving_fvks_found': 0, 'policy_fields': sorted(k for k in policy if k.endswith(('_receiver', '_fvk')))}


if __name__ == '__main__':
    print(json.dumps(check(Path(sys.argv[1]).resolve()), indent=2))
