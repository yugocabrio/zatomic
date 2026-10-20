#!/usr/bin/env python3
"""Prepare a conditional public agreement; never deploy, observe or release funds.

The contract address is an intended target, not evidence that code is deployed.
Both signed agreements and fresh code/state/input checks are needed before use.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import fee_policy
import timestamp_policy
from otc_offer import read
from regtest_node import ROOT
from regtest_wallet import native


SOURCES={1:('contracts/src/Pallas.sol','contracts/src/PointEscrow.sol'),
    2:('contracts/src/Pallas.sol','contracts/src/PallasComb.sol','contracts/src/PallasCombTables.sol','contracts/src/PointEscrowV2.sol')}


def validate_policy(version=1):
    """Check BOTH pinned escrow policies against this checkout; return `version`'s.

    v1 pins the deployed PointEscrow; v2 pins PointEscrowV2. Clock, fee and
    observation policies are identical by construction."""
    policies={}
    for v,name in ((1,'config/public-agreement-policy-v1.json'),(2,'config/public-agreement-policy-v2.json')):
        policy=json.loads((ROOT/name).read_text())
        if policy['timestamp_policy']!=timestamp_policy.POLICY or policy['fee_policy']!=fee_policy.DEFAULT:
            raise RuntimeError('compiled agreement and candidate clock/fee policies diverged')
        sources=policy['escrow']['source_sha256']
        if tuple(sources)!=SOURCES[v] or any(hashlib.sha256((ROOT/path).read_bytes()).hexdigest()!=digest
                for path,digest in sources.items()):
            raise RuntimeError('escrow source differs from pinned agreement policy')
        policies[v]=policy
    if policies[1]['observation_policy']!=policies[2]['observation_policy'] or policies[2]['escrow'].get('version')!=2:
        raise RuntimeError('v2 escrow policy diverged from v1 profile')
    if version not in policies:
        raise RuntimeError('unsupported escrow version')
    return policies[version]


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('bundle',type=Path)
    p.add_argument('receipts',type=Path)
    p.add_argument('contract',help='intended Sepolia contract address; no deployment is performed')
    p.add_argument('salt',help='fresh explicit nonzero 0x-prefixed 32-byte order salt')
    p.add_argument('output',type=Path)
    p.add_argument('--escrow-version',type=int,choices=(1,2),default=1)
    a=p.parse_args()
    os.umask(0o077)
    validate_policy(a.escrow_version)
    timestamp_policy.validate(read(a.bundle)['review']['plan'])
    parent=a.output.absolute().parent
    if parent.is_symlink() or parent.stat().st_mode & 0o077:
        raise RuntimeError('private proposal output directory required')
    extra=('escrow-v2',) if a.escrow_version==2 else ()
    print(json.dumps(native('testnet-stage-agreement',a.bundle,a.receipts,a.contract,a.salt,a.output,*extra)))


if __name__=='__main__':
    try:main()
    except (OSError,RuntimeError,ValueError,KeyError,TypeError,subprocess.SubprocessError):
        print('Conditional agreement rejected. No funds released or deployed.',file=sys.stderr)
        sys.exit(1)
