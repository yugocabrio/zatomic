#!/usr/bin/env python3
"""Validate retained public F observations against changed domains and bytes.

No key, pre-signature, note witness or owner recovery bundle is copied. Mutations
remain in ignored private test directories; the native parser checks real bytes.
"""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import native_funding
import owner_swap as flow
from regtest_node import rpc, status
from regtest_wallet import save


def check(fixture, foreign, directory):
    with flow.chain_lock():
        terms = flow.read(fixture / 'agreement.json')['native']
        original = list((fixture / 'owners/bob/native-funding-observed').glob('*.json'))
        if len(original) != 1:
            raise RuntimeError('expected one original published funding observation')
        data = flow.read(original[0])
        foreign_raw = (foreign / 'coordinator-native-offline/funding.hex').read_text().strip()
        directory.mkdir(mode=0o700)
        before, pool = status()['tip'], rpc('getrawmempool')
        mutations = ['valid', 'genesis', 'branch', 'txid', 'version', 'digest',
            'filename', 'truncated_raw', 'foreign_payment', 'missing', 'symlink', 'excessive']
        rejected = []
        for case in mutations:
            owner = directory / case
            folder = owner / 'native-funding-observed'
            folder.mkdir(mode=0o700, parents=True)
            value = copy.deepcopy(data)
            name = original[0].name
            if case in ('genesis', 'branch', 'txid'):
                value[case] = '00' * (4 if case == 'branch' else 32)
            if case == 'version':
                value['version'] = 2
            if case == 'digest':
                value['bytes_sha256'] = '00' * 32
            if case == 'filename':
                name = '00' * 32 + '.json'
            if case == 'truncated_raw':
                value['raw'] = '00'
            if case == 'foreign_payment':
                value['raw'] = foreign_raw
                value['bytes_sha256'] = hashlib.sha256(bytes.fromhex(foreign_raw)).hexdigest()
                name = value['bytes_sha256'] + '.json'
            if case == 'symlink':
                (folder / name).symlink_to(original[0])
            elif case != 'missing':
                save(folder / name, value)
            if case == 'excessive':
                for index in range(32):
                    shutil.copyfile(original[0], folder / f'extra-{index}.json')
            try:
                values = native_funding.history(owner, terms)
            except (RuntimeError, OSError, ValueError, subprocess.CalledProcessError):
                if case == 'valid':
                    raise
                rejected.append(case)
            else:
                if case != 'valid' or values != [data]:
                    raise RuntimeError('changed public funding history was accepted')
        invalid_driver = directory / 'unsupported_driver'
        invalid_driver.mkdir(mode=0o700)
        save(invalid_driver / 'agreement.json', flow.read(fixture / 'agreement.json'))
        saved_flow = flow.read(fixture / 'owner-flow.json')
        saved_flow['version'] = 'unsupported-driver'
        save(invalid_driver / 'owner-flow.json', saved_flow)
        try:
            flow.validate_recovery(invalid_driver, funding_required=False)
        except RuntimeError as exc:
            if str(exc) != 'owner lifecycle agreement changed':
                raise
        else:
            raise RuntimeError('unsupported driver passed pre-restoration validation')
        if status()['tip'] != before or rpc('getrawmempool') != pool:
            raise RuntimeError('history validation mutated the native chain')
        result = {'scope': 'public funding observations parsed by the native implementation',
            'valid_observation_accepted': True, 'rejected': rejected,
            'unsupported_driver_rejected_before_restoration': True,
            'keys_or_private_bundles_copied': False, 'native_tip_and_mempool_unchanged': True}
        save(directory / 'checks.json', result)
        return result


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('fixture', type=Path)
    p.add_argument('foreign_fixture', type=Path)
    p.add_argument('directory', type=Path)
    a = p.parse_args()
    os.umask(0o077)
    print(json.dumps(check(a.fixture.resolve(), a.foreign_fixture.resolve(), a.directory.resolve()), indent=2))
