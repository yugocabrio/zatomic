#!/usr/bin/env python3
"""Sign only the reserved refund auxiliary and prepare private native exits.

Requires a real public wallet reservation and its exact unsigned graph. Offline
only: no source spend signature, current-chain assurance or funding consent.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
from otc_offer import read
from regtest_wallet import native
import timestamp_policy


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('wallet',type=Path)
    p.add_argument('package',type=Path)
    p.add_argument('review',type=Path)
    p.add_argument('presignatures',type=Path)
    a=p.parse_args()
    os.umask(0o077)
    timestamp_policy.validate(read(a.review)['plan'])
    # The native entry point owns sync.lock, also for direct CLI callers.
    print(json.dumps(native('testnet-prepare-recovery',a.wallet,a.package,a.review,a.presignatures)))


if __name__=='__main__':
    try:
        main()
    except (OSError,RuntimeError,ValueError,KeyError,TypeError,subprocess.SubprocessError):
        print('Native recovery preparation rejected; reservation retained. No funding authorization.',file=sys.stderr)
        sys.exit(1)
