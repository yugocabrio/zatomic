#!/usr/bin/env python3
"""Check older witnesses against CURRENT spentness on the owned regtest.

Requires a completed recent bank spend: the old note existed six blocks ago,
but only its newer change remains unspent. Never copies spending keys.
"""
import argparse
import copy
import json
import os
from pathlib import Path
import subprocess
from owner_swap import chain_lock
from regtest_node import rpc, status
from regtest_wallet import capture, save, native, NATIVE, FUNDING_ANCHOR_LAG, require_capacity


def check(bank, directory):
    with chain_lock():
        directory.mkdir(mode=0o700)
        tip = status()
        current = capture(bank)
        older = capture(bank, FUNDING_ANCHOR_LAG)
        source = json.loads(Path(current['file']).read_text())
        lagged = json.loads(Path(older['file']).read_text())
        if current['unspent_notes'] != 1 or older['unspent_notes'] != 0:
            raise RuntimeError('requires a completed spend with change newer than the old anchor')
        raw = json.loads(Path(older['capture_file']).read_text())
        historical = copy.deepcopy(raw)
        height = historical.pop('anchor_height')
        historical['height'] = height
        historical['blocks'] = [b for b in historical['blocks'] if b['height'] <= height]
        historical['tip'] = rpc('getblockhash', [height])
        historical['final_tree'] = rpc('z_gettreestate', [historical['tip']])['ironwood']['commitments']['finalState']
        historical_path = directory / 'historical.json'
        save(historical_path, historical)
        old = native('regtest-scan', bank, historical_path)
        old_notes = json.loads(Path(old['file']).read_text())['notes']
        if old['unspent_notes'] != 1 or old_notes[0]['cmx'] == source['notes'][0]['cmx']:
            raise RuntimeError('test did not isolate a spent old note and newer change')
        rejected = []
        for name, value in [('below_activation', 1), ('future', tip['blocks'] + 1),
                            ('current_tip', tip['blocks']), ('malformed', 'old')]:
            changed = dict(raw, anchor_height=value)
            path = directory / f'{name}.json'
            save(path, changed)
            checked = subprocess.run([str(NATIVE), 'regtest-scan', str(bank), str(path)],
                text=True, capture_output=True, env=dict(os.environ, RAYON_NUM_THREADS='2'))
            if checked.returncode == 0 or checked.stdout:
                raise RuntimeError('invalid funding anchor was accepted')
            rejected.append(name)
        if status()['tip'] != tip['tip']:
            raise RuntimeError('scan validation unexpectedly changed the chain')
        require_capacity(FUNDING_ANCHOR_LAG)
        rpc('generate', [FUNDING_ANCHOR_LAG], timeout=300)
        ready = capture(bank, FUNDING_ANCHOR_LAG)
        ready_data = json.loads(Path(ready['file']).read_text())
        if (ready['unspent_notes'] != 1 or ready_data['height'] != tip['blocks'] + FUNDING_ANCHOR_LAG
                or ready_data['anchor_height'] != tip['blocks']
                or ready_data['anchor_tip'] != tip['tip']
                or ready_data['notes'][0]['cmx'] != source['notes'][0]['cmx']
                or ready_data['anchor'] != source['anchor']
                or lagged['height'] != tip['blocks']):
            raise RuntimeError('historical witness lost the current clock or live note')
        result = {'scope': 'actual owned chain scans with native nullifier filtering',
            'anchor_lag_blocks': FUNDING_ANCHOR_LAG, 'spent_old_note_excluded': True,
            'newer_change_excluded_until_anchor_contains_it': True,
            'clock_remains_current_height': True, 'old_and_current_scans_retained': True,
            'invalid_anchors_rejected': rejected, 'keys_copied': False,
            'height_before': tip['blocks'], 'height_after': ready_data['height']}
        save(directory / 'checks.json', result)
        return result


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('bank', type=Path)
    p.add_argument('directory', type=Path)
    a = p.parse_args()
    os.umask(0o077)
    print(json.dumps(check(a.bank.resolve(), a.directory.resolve()), indent=2))
