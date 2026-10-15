#!/usr/bin/env python3
"""Recover from one participant's accepted native bundle with all setup files offline.

This deliberately retains the local EVM fixture journal/checkpoint: it proves
native recovery-data ownership, not two independently operated EVM wallets.
The other signer and original coordinator native workspace are unavailable.
"""
import argparse
import fcntl
import json
import os
from pathlib import Path
from regtest_node import ROOT
from regtest_wallet import native, save
from recover_regtest_swap import recover
from run_tls_swap import run as tls_run


def check_wrong_workspace_role(directory, mode):
    wrong = 'alice' if mode == 'claim' else 'bob'
    output = directory / 'wrong-role-recovery'
    native('regtest-export-recovery', directory / 'swap' / wrong, output)
    before = (directory / 'evm-checkpoint.json').read_bytes()
    intents = sorted(p.name for p in (directory / 'evm-outgoing').glob('*.json'))
    try:
        recover(directory, output)
    except RuntimeError as error:
        if 'workspace does not own the required native exit; no calls replayed' not in str(error):
            raise
    else:
        raise RuntimeError('wrong participant recovery workspace accepted')
    if before != (directory / 'evm-checkpoint.json').read_bytes() or intents != sorted(p.name for p in (directory / 'evm-outgoing').glob('*.json')):
        raise RuntimeError('wrong-role rejection changed EVM state')
    result = {'scope': 'owned local EVM and opposite native recovery workspace',
        'wrong_role_rejected_before_replay': True, 'checkpoint_unchanged': True,
        'no_outgoing_intent_added': True}
    save(directory / '11-wrong-recovery-role.json', result)
    return result


def run(mode, directory, bank):
    # The TLS runner's child holds the global chain lock for setup. Acquire it
    # here only after that child exits, and keep it through both recoveries.
    stop = 'eth-claimed' if mode == 'claim' else 'eth-locked'
    paused = tls_run('success' if mode == 'claim' else 'refund', directory, bank, stop)
    if not paused.get('interrupted'):
        raise RuntimeError('setup was not interrupted')
    with (ROOT / '.local/chain-driver.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        role = 'bob' if mode == 'claim' else 'alice'
        original = directory / 'swap'
        output = directory / 'owned-recovery'
        exported = native('regtest-export-recovery', original / role, output)
        expected = {'joint-fvk.bin', 'pending-note.json', 'terms.json', 'recovery-ready.json',
            f'{role}/joint-fvk.bin', f'{role}/{mode}.pczt'}
        if mode == 'claim':
            expected.add('bob/presignature.json')
        actual = {str(p.relative_to(output)) for p in output.rglob('*') if p.is_file()}
        if actual != expected or exported['spending_keys_exported'] is not False:
            raise RuntimeError('unexpected exported native recovery files')
        offline = directory / 'swap-offline'
        original.rename(offline)
        try:
            first = recover(directory, output)
            repeated = recover(directory, output)
            if repeated['new_native_transactions'] or repeated['new_evm_transactions'] or repeated.get('identical_outgoing_transactions_replayed'):
                raise RuntimeError('recovery replay unexpectedly submitted a transaction')
            if original.exists():
                raise RuntimeError('recovery recreated the original setup workspace')
        finally:
            offline.rename(original)
        result = {'scope': 'one participant native exit bundle; shared local EVM fixture',
            'mode': mode, 'tls_setup': True, 'all_original_native_files_unavailable': True,
            'spending_keys_exported': False, 'independent_hosts': False,
            'exported_file_count': len(actual), 'first': first, 'repeat': repeated}
        save(directory / '10-owned-recovery.json', result)
        check_wrong_workspace_role(directory, mode)
        return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['claim', 'refund'])
    parser.add_argument('directory', type=Path)
    parser.add_argument('--existing-bank', type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    print(json.dumps(run(args.mode, args.directory.resolve(), args.existing_bank.resolve() if args.existing_bank else None), indent=2))
