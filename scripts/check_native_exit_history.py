#!/usr/bin/env python3
"""Reject changed native exit histories before a node mutation.

Copies only already-broadcast transaction bytes, never keys or recovery bundles.
Requires the completed success replacement-branch gate.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import owner_swap as flow
from regtest_node import rpc, status
from regtest_wallet import native, save
from recover_regtest_swap import native_exit


def check(fixture, directory):
    with flow.chain_lock():
        workspace = fixture / 'owners/bob/recovery'
        originals = sorted(workspace.glob('claim-*.hex'))
        if len(originals) != 2:
            raise RuntimeError('requires two retained authorization variants')
        txid = native('regtest-inspect', originals[0])['txid']
        if not flow.confirmed(txid):
            raise RuntimeError('expected currently confirmed payment')
        directory.mkdir(mode=0o700)
        before, pool = status()['tip'], rpc('getrawmempool')
        cases = []
        for case in ('valid_variants', 'mixed_payment', 'truncated_authorization', 'wrong_mode'):
            root = directory / case
            root.mkdir(mode=0o700)
            for index, original in enumerate(originals):
                shutil.copyfile(original, root / f'claim-{index}.hex')
            if case == 'mixed_payment':
                # The same fixture's published funding has different effects.
                shutil.copyfile(fixture / 'coordinator-native-offline/funding.hex', root / 'claim-z-foreign.hex')
            if case == 'truncated_authorization':
                (root / 'claim-z-truncated.hex').write_text('00')
            try:
                result = native_exit(root, 'unknown' if case == 'wrong_mode' else 'claim')
            except (RuntimeError, subprocess.CalledProcessError):
                if case == 'valid_variants':
                    raise
                cases.append(case)
            else:
                if case != 'valid_variants' or result != (txid, False):
                    raise RuntimeError('changed history did not reject before payment')
        if status()['tip'] != before or rpc('getrawmempool') != pool:
            raise RuntimeError('history checks changed node state')
        result = {'scope': 'published transaction copies; real current-node reconciliation',
            'two_valid_versions_reconciled_without_resend': True,
            'rejected': cases, 'native_tip_and_mempool_unchanged': True,
            'spending_keys_or_private_bundles_copied': False}
        save(directory / 'checks.json', result)
        return result


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('fixture', type=Path)
    p.add_argument('directory', type=Path)
    a = p.parse_args()
    os.umask(0o077)
    print(json.dumps(check(a.fixture.resolve(), a.directory.resolve()), indent=2))
