#!/usr/bin/env python3
"""An actual signer withholds its bundle receipt; funding must remain unavailable.

The test adapter is only a configured subprocess, not a production signer
bypass. No valid funding transaction is broadcast and no coin is reserved.
The unbroadcastable peer preview is submitted to the isolated node to verify
rejection. Only synthetic regtest participants are created.
"""
import argparse
import fcntl
import json
import os
from pathlib import Path
import subprocess
import sys
from regtest_node import ROOT, rpc
from regtest_wallet import NATIVE, capture, native, save


def withholding_signer(wallet):
    child = subprocess.Popen([str(NATIVE), 'participant', str(wallet), '2'],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    try:
        print(child.stdout.readline().strip(), flush=True)
        for line in sys.stdin:
            packet = json.loads(line)
            if packet.get('command') == 'accept_bundle':
                # A stale receipt must not be accepted as proof of saving this
                # bundle. Do not deliver it to Bob's real signer.
                print(json.dumps({'participant': 2, 'bundle_digest': '00' * 32,
                    'durably_saved': True}), flush=True)
                continue
            child.stdin.write(line)
            child.stdin.flush()
            response = child.stdout.readline()
            if not response:
                break
            print(response.strip(), flush=True)
    finally:
        child.terminate()
        try:
            child.wait(timeout=10)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait()


def run(directory, bank):
    directory.mkdir(mode=0o700)
    swap = directory / 'swap'
    commands = directory / 'commands.json'
    save(commands, {
        'alice': [str(NATIVE), 'participant', str(swap / 'alice'), '1'],
        'bob': [sys.executable, str(Path(__file__).resolve()), 'withhold', str(swap / 'bob')]})
    observed = capture(bank)
    prepared = subprocess.run([str(NATIVE), 'regtest-prepare', str(bank), observed['file'], str(swap)],
        cwd=ROOT, capture_output=True, text=True,
        env=dict(os.environ, LATCH_SIGNER_COMMANDS=str(commands), RAYON_NUM_THREADS='2'))
    if prepared.returncode == 0 or 'participant did not acknowledge exact recovery bundle' not in prepared.stderr:
        raise RuntimeError('did not reject stale bundle receipt')
    if (swap / 'funding.hex').exists() or (swap / 'participant-receipts.json').exists():
        raise RuntimeError('funding escaped before both exact receipts')
    if not (swap / 'alice/recovery-receipt.json').exists() or (swap / 'bob/recovery-bundle.json').exists():
        raise RuntimeError('test did not withhold the intended participant bundle')
    preview = json.loads((swap / 'alice/agreement.json').read_text())['funding']
    path = directory / 'preview.hex'
    path.write_text(preview)
    inspected = native('regtest-inspect', path)
    try:
        rpc('sendrawtransaction', [preview], timeout=180)
    except RuntimeError as error:
        if 'Halo2 proof verification failed' not in str(error):
            raise RuntimeError('preview rejected for an unexpected reason') from None
    else:
        raise RuntimeError('peer preview could be broadcast before bundle delivery')
    if inspected['txid'] in rpc('getrawmempool'):
        raise RuntimeError('failed funding remains in mempool')
    return {'scope': 'real two-party preparation and isolated node rejection; no funding',
        'stale_receipt_rejected': True, 'alice_bundle_durable': True,
        'bob_bundle_withheld': True, 'broadcastable_funding_file_absent': True,
        'peer_preview_rejected_by_node': True, 'no_funding_in_mempool': True}


if __name__ == '__main__':
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['run', 'withhold'])
    parser.add_argument('directory', type=Path)
    parser.add_argument('--bank', type=Path)
    args = parser.parse_args()
    if args.action == 'withhold':
        withholding_signer(args.directory.resolve())
    else:
        if not args.bank:
            parser.error('--bank is required for run')
        with (ROOT / '.local/chain-driver.lock').open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            print(json.dumps(run(args.directory.resolve(), args.bank.resolve()), indent=2))
