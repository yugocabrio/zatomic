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


def validate_policy():
    policy=json.loads((ROOT/'config/public-agreement-policy-v1.json').read_text())
    if policy['timestamp_policy']!=timestamp_policy.POLICY or policy['fee_policy']!=fee_policy.DEFAULT:
        raise RuntimeError('compiled agreement and candidate clock/fee policies diverged')
    for path,digest in policy['escrow']['source_sha256'].items():
        if path not in ('contracts/src/Pallas.sol','contracts/src/PointEscrow.sol') or hashlib.sha256((ROOT/path).read_bytes()).hexdigest()!=digest:
            raise RuntimeError('escrow source differs from pinned agreement policy')
    return policy


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('bundle',type=Path)
    p.add_argument('receipts',type=Path)
    p.add_argument('contract',help='intended Sepolia contract address; no deployment is performed')
    p.add_argument('salt',help='fresh explicit nonzero 0x-prefixed 32-byte order salt')
    p.add_argument('output',type=Path)
    a=p.parse_args()
    os.umask(0o077)
    validate_policy()
    timestamp_policy.validate(read(a.bundle)['review']['plan'])
    parent=a.output.absolute().parent
    if parent.is_symlink() or parent.stat().st_mode & 0o077:
        raise RuntimeError('private proposal output directory required')
    print(json.dumps(native('testnet-stage-agreement',a.bundle,a.receipts,a.contract,a.salt,a.output)))


if __name__=='__main__':
    try:main()
    except (OSError,RuntimeError,ValueError,KeyError,TypeError,subprocess.SubprocessError):
        print('Conditional agreement rejected. No funds released or deployed.',file=sys.stderr)
        sys.exit(1)
