#!/usr/bin/env python3
"""Exercise cancellation on a real interrupted v3 setup (private fixture).

This consumes the offer: it cannot subsequently resume. No public RPC, no fresh
funding. A fully signed offer additionally tests the native signer after cancel.
"""
import argparse
import fcntl
import json
import os
from pathlib import Path
import subprocess
from regtest_node import ROOT, rpc, status
from regtest_wallet import native, NATIVE, save
from prefunding_swap import recover


def rejected(args, fragment):
    result = subprocess.run(list(map(str, args)), capture_output=True, text=True)
    if result.returncode == 0 or fragment not in result.stderr:
        raise RuntimeError('expected refusal not observed: ' + fragment)


def check(directory):
    before = status()['tip']
    pool = rpc('getrawmempool')
    if (directory / 'source-release.json').exists():
        raise RuntimeError('checker only consumes an unreleased setup')
    # Test the same underlying OS lock used by the native source gate.
    with (directory / 'source.lock').open('r+') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        rejected([NATIVE, 'regtest-cancel-setup', directory], 'source operation already active')
    first = recover(directory)
    second = recover(directory)
    if first != second or not first['unfunded_cancelled']:
        raise RuntimeError('cancellation was not idempotent')
    rejected(['python3', ROOT / 'scripts/prefunding_swap.py', 'resume', directory],
             'source setup permanently cancelled')
    signed = (directory / 'consent-packet.json').exists()
    if signed:
        bank = Path(json.loads((directory / 'setup.json').read_text())['bank'])
        staged = directory / 'coordinator-native-offline'
        packet = directory / 'consent-packet.json'
        # A fully valid old packet cannot resurrect a cancelled source wallet.
        native('regtest-check-consent', staged, packet)
        rejected([NATIVE,'regtest-commit-funding',staged,packet], 'source setup permanently cancelled')
        rejected([NATIVE,'regtest-authorize-funding',bank,staged,packet], 'source setup permanently cancelled')
    if before != status()['tip'] or pool != rpc('getrawmempool'):
        raise RuntimeError('cancellation changed native chain or mempool')
    if (directory / 'source-release.json').exists() or list(directory.glob('**/funding.hex')):
        raise RuntimeError('cancelled setup contains a release')
    result = {'scope':'actual local interrupted setup, no synthetic swap settlement',
        'unfunded_cancelled':True,'repeat_identical':True,'exclusive_os_lock_checked':True,
        'resume_rejected':True,'fully_signed_offer_available':signed,'valid_signed_offer_cannot_reauthorize':True if signed else None,
        'native_tip_and_mempool_unchanged':True,'no_source_release_or_funding_file':True,
        'new_native_transactions':0,'new_evm_transactions':0}
    save(directory / 'cancellation-checks.json', result)
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    print(json.dumps(check(args.directory.resolve()), indent=2))
