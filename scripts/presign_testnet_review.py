#!/usr/bin/env python3
"""Offline C/R presigning through explicitly configured owner-local commands.

The commands file is local trusted configuration, not a field from a peer's
offer. Use private pipes or an authenticated encrypted transport. This creates
no source signature, auxiliary signature, full recovery bundle or transaction.
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
    p.add_argument('review',type=Path)
    p.add_argument('commands',type=Path)
    p.add_argument('output',type=Path)
    a=p.parse_args()
    os.umask(0o077)
    timestamp_policy.validate(read(a.review)['plan'])
    commands=read(a.commands)
    if set(commands)!={'alice','bob'} or any(not isinstance(v,list) or not 1<=len(v)<=16
            or any(not isinstance(s,str) or not s for s in v) for v in commands.values()):
        raise RuntimeError('explicit Alice/Bob command arrays required')
    os.environ['LATCH_SIGNER_COMMANDS']=str(a.commands.absolute())
    print(json.dumps(native('testnet-presign-review',a.review,a.output)))


if __name__=='__main__':
    try:
        main()
    except (OSError,RuntimeError,ValueError,KeyError,TypeError,subprocess.SubprocessError):
        print('Presigning rejected; private attempts retained. No funding authorization.',file=sys.stderr)
        sys.exit(1)
