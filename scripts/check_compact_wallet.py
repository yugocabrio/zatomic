#!/usr/bin/env python3
"""Compare compact incremental scans with real full-transaction scanning.

Reads an already settled fixture only. Copies keys to a fresh ignored private
test root; never broadcasts, mines, edits the original wallet or invents notes.
"""
import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from testnet_wallet import NATIVE, invoke, read


def save(path, value):
    with open(path, 'x') as stream:
        json.dump(value, stream)


def rejected(*args):
    result = subprocess.run([str(NATIVE), *map(str, args)], capture_output=True, text=True)
    if result.returncode == 0:
        raise RuntimeError('invalid scanner input accepted')
    return result.stderr.strip()


def check(root, full, wallets):
    root.mkdir(mode=0o700)
    exported = invoke(NATIVE, 'regtest-export-compact', full, root / 'captures')
    reports = []
    for index, source in enumerate(wallets):
        wallet = root / f'wallet-{index}'
        wallet.mkdir(mode=0o700)
        key = 'joint-fvk.bin' if (source / 'joint-fvk.bin').exists() else 'spending-key.bin'
        shutil.copyfile(source / key, wallet / key)
        os.chmod(wallet / key, 0o600)
        full_result = invoke(NATIVE, 'regtest-scan', wallet, full)
        prior = None
        received = spent = 0
        resumed_with_notes = False
        rejected_reasons = []
        last_args = None
        for file in exported['captures']:
            args = [NATIVE, 'compact-scan', wallet, file]
            if prior:
                args.append(prior)
                if read(prior)['notes']:
                    resumed_with_notes = True
                    if not rejected_reasons:
                        data = read(prior)
                        bad = copy.deepcopy(data)
                        bad['notes'][0]['witness'] = '00'
                        altered = root / f'bad-witness-{index}.json'
                        save(altered, bad)
                        rejected_reasons.append(rejected('compact-scan', wallet, file, altered))
                        bad = copy.deepcopy(data)
                        bad['fvk_fingerprint'] = '00' * 32
                        altered = root / f'bad-identity-{index}.json'
                        save(altered, bad)
                        rejected_reasons.append(rejected('compact-scan', wallet, file, altered))
                        bad_capture = read(Path(file))
                        bad_capture['initial_hash'] = '00' * 32
                        altered = root / f'bad-chain-{index}.json'
                        save(altered, bad_capture)
                        rejected_reasons.append(rejected('compact-scan', wallet, altered, prior))
            result = invoke(*args)
            prior = Path(result['file'])
            received += result['received_notes']
            spent += result['spent_notes']
            last_args = args
        before = prior.read_bytes()
        invoke(*last_args)
        if prior.read_bytes() != before:
            raise RuntimeError('identical scan replay changed checkpoint')
        compact = read(prior)
        reference = read(Path(full_result['file']))
        notes = [{k: v for k, v in n.items() if k != 'witness'} for n in compact['notes']]
        if notes != reference['notes'] or compact['anchor'] != reference['anchor'] or compact['tip'] != reference['tip']:
            raise RuntimeError('compact scan differs from full ciphertext scan')
        reports.append({'wallet': index, 'received': received, 'spent': spent, 'unspent': len(notes),
            'resumed_with_notes': resumed_with_notes, 'same_full_scan_notes_paths_root': True,
            'separate_processes': len(exported['captures']), 'repeat_unchanged': True,
            'rejected_invalid_checkpoint_inputs': len(rejected_reasons)})
    if not any(r['received'] > 0 and r['spent'] > 0 and r['resumed_with_notes'] for r in reports):
        raise RuntimeError('need actual received/spent notes across checkpoint restart')
    return {'scope': 'existing actual isolated-chain ciphertext, no new transactions',
        'height': exported['height'], 'tip': exported['tip'], 'wallets': reports, 'broadcast': False}


if __name__ == '__main__':
    os.umask(0o077)
    print(json.dumps(check(Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(),
        [Path(p).resolve() for p in sys.argv[3:]]), indent=2))
