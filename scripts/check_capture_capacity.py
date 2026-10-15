#!/usr/bin/env python3
"""Verify the extended local scanner against actual history past its old cap.

Only mines empty controlled blocks when every recorded funded run is resolved.
Mutations are private copies of a real capture; no wallet state is replaced.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
from owner_swap import chain_lock
from regtest_node import ROOT, status, rpc
from regtest_wallet import capture, save, NATIVE, MAX_CAPTURE_HEIGHT, require_capacity


def rejected(bank, path, expected):
    process = subprocess.run([str(NATIVE), 'regtest-scan', str(bank), str(path)],
        capture_output=True, text=True, env=dict(os.environ, RAYON_NUM_THREADS='2'))
    if process.returncode == 0 or expected not in process.stderr or process.stdout:
        raise RuntimeError('capture mutation did not reject as expected')


def check(bank, directory):
    with chain_lock():
        pending = [p for p in (ROOT / '.local').rglob('02-funded.json')
                   if not (p.parent / '08-complete.json').exists()]
        if pending:
            raise RuntimeError('resolve every recorded funded run before advancing test height')
        directory.mkdir(mode=0o700)
        before = status()['blocks']
        if before < 2005:
            rpc('generate', [2005 - before], timeout=300)
        observed = capture(bank)
        height = status()['blocks']
        original = json.loads(Path(observed['capture_file']).read_text())
        broken = dict(original, blocks=list(original['blocks']))
        broken['blocks'][-1] = dict(broken['blocks'][-1], previousblockhash='00' * 32)
        save(directory / 'broken-chain.json', broken)
        rejected(bank, directory / 'broken-chain.json', 'broken capture chain')
        # Keep this mutation below the independent 50 MB file cap so the
        # block-count check, rather than the byte-size check, is exercised.
        small_block = dict(original['blocks'][0], transactions=[])
        excessive = dict(original, blocks=[small_block] * (MAX_CAPTURE_HEIGHT - 2 + 1))
        save(directory / 'excessive-history.json', excessive)
        rejected(bank, directory / 'excessive-history.json', 'capture history bound')
        try:
            require_capacity(MAX_CAPTURE_HEIGHT)
        except RuntimeError:
            pass
        else:
            raise RuntimeError('future history-budget exhaustion did not reject')
        if status()['blocks'] != height:
            raise RuntimeError('rejection changed the chain')
        return {'scope': 'actual isolated-node capture; no new swap funding',
            'height': height, 'blocks_scanned': len(original['blocks']),
            'original_capture_bytes': Path(observed['capture_file']).stat().st_size,
            'unspent_notes': observed['unspent_notes'], 'new_max_capture_height': MAX_CAPTURE_HEIGHT,
            'json_byte_limit_unchanged': 50_000_000,
            'broken_continuity_rejected': True, 'excessive_history_rejected': True,
            'future_capacity_exhaustion_rejected_without_mining': True}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('bank', type=Path)
    parser.add_argument('directory', type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    print(json.dumps(check(args.bank.resolve(), args.directory.resolve()), indent=2))
