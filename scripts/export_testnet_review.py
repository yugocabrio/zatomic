#!/usr/bin/env python3
"""Export only owner-review material, never the source funding PCZT/witness.

Offline preparation only. No signing, funding authorization or RPC operations.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
from regtest_wallet import native
from otc_offer import read
import timestamp_policy


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('graph',type=Path)
    p.add_argument('destinations',type=Path)
    p.add_argument('plan',type=Path)
    p.add_argument('output',type=Path)
    a=p.parse_args()
    os.umask(0o077)
    timestamp_policy.validate(read(a.plan))
    parent=a.output.absolute().parent
    if parent.is_symlink() or parent.stat().st_mode & 0o077:
        raise RuntimeError('private output directory required')
    print(json.dumps(native('testnet-export-review',a.graph,a.destinations,a.plan,a.output)))


if __name__=='__main__':
    try:
        main()
    except (OSError,RuntimeError,ValueError,KeyError,TypeError,subprocess.SubprocessError):
        print('Review export rejected; private source retained.',file=sys.stderr)
        sys.exit(1)
