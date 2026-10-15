#!/usr/bin/env python3
"""Conflicting/malformed release artifacts must never permit cancellation."""
import argparse
import json
import os
from pathlib import Path
import subprocess
from regtest_wallet import NATIVE, native, save


def check(directory):
    directory.mkdir(mode=0o700)
    cases = [('truncated_release','source-release.json'),
        ('unexpected_funding','coordinator-native-offline/funding.hex'),
        ('unexpected_eth_intent','owners/bob/eth-intent-lock.json')]
    for name, marker in cases:
        root = directory / name
        native('regtest-setup-init', root)
        path = root / marker
        path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
        path.write_text('{')
        result = subprocess.run([str(NATIVE),'regtest-cancel-setup',str(root)],capture_output=True,text=True)
        if not result.returncode or 'possible source release or ETH lock' not in result.stderr:
            raise RuntimeError('conflicting source state allowed cancellation')
        if (root / 'source-cancelled.json').exists():
            raise RuntimeError('conflicting source state acquired a cancellation receipt')
    value = {'rejected_before_cancellation':[name for name,_ in cases],
        'scope':'synthetic conflicting local journals; no funding or keys'}
    save(directory / 'checks.json', value)
    return value


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory',type=Path)
    args = parser.parse_args(); os.umask(0o077)
    print(json.dumps(check(args.directory.resolve()),indent=2))
