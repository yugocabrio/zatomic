#!/usr/bin/env python3
"""Obtain actual matured local notes and trusted node captures; no public RPC."""
import argparse
import json
import os
from pathlib import Path
import subprocess
from regtest_node import ROOT, GENESIS, BRANCH, rpc, status

NATIVE = ROOT / 'target/release/shielded-swap-native'


def native(*args):
    return json.loads(subprocess.check_output([str(NATIVE), *map(str, args)], cwd=ROOT,
        text=True, env=dict(os.environ, RAYON_NUM_THREADS='2')))


def save(path, value):
    # Immutable snapshot: a reorg is an error, never silent replacement.
    encoded = json.dumps(value, sort_keys=True)
    if path.exists():
        if json.loads(path.read_text()) != value:
            raise RuntimeError('existing private snapshot differs')
        return
    with path.open('x') as f:
        f.write(encoded)
        f.flush()
        os.fsync(f.fileno())


def capture(directory):
    os.umask(0o077)
    tip = status()
    if not 2 <= tip['blocks'] <= 2002:
        raise RuntimeError('bounded NU7 history required')
    initial = rpc('getblockhash', [2])
    blocks = []
    for height in range(3, tip['blocks'] + 1):
        h = rpc('getblockhash', [height])
        b = rpc('getblock', [h, 2])
        blocks.append({'height': height, 'hash': h,
            'previousblockhash': b['previousblockhash'],
            'tree_size': b['trees']['ironwood']['size'],
            'transactions': [tx['hex'] for tx in b['tx']]})
    value = {'genesis': GENESIS, 'branch': BRANCH, 'initial_height': 2,
        'initial_hash': initial,
        'initial_tree': rpc('z_gettreestate', [initial])['ironwood']['commitments']['finalState'],
        'tip': tip['tip'], 'height': tip['blocks'], 'blocks': blocks,
        'final_tree': rpc('z_gettreestate', [tip['tip']])['ironwood']['commitments']['finalState']}
    if status()['tip'] != tip['tip']:
        raise RuntimeError('chain changed during capture')
    path = directory / f'capture-{tip["blocks"]}.json'
    save(path, value)
    return native('regtest-scan', directory, path)


def fund(directory):
    os.umask(0o077)
    if status()['blocks'] < 2:
        raise RuntimeError('activate isolated NU7 first')
    initialized = native('regtest-init', directory)
    rpc('generatetoaddress', [1, initialized['address']], timeout=300)
    aux = rpc('generatetoaddress', [1, initialized['aux_address']], timeout=300)[0]
    block = rpc('getblock', [aux, 2])
    save(directory / 'aux-source.json', {'height': block['height'],
         'tx': block['tx'][0]['hex'], 'address': initialized['aux_address']})
    rpc('generate', [100], timeout=300)
    result = capture(directory)
    if result['unspent_notes'] != 1:
        raise RuntimeError('expected one mined shielded source note')
    compact = native('regtest-compact-aux', directory, result['file'])
    tx_hex = Path(compact['file']).read_text().strip()
    if rpc('sendrawtransaction', [tx_hex], timeout=180) != compact['txid']:
        raise RuntimeError('auxiliary split transaction mismatch')
    rpc('generate', [2], timeout=300)
    accepted = rpc('getrawtransaction', [compact['txid'], 1])
    if not accepted['in_active_chain'] or accepted['confirmations'] < 2:
        raise RuntimeError('auxiliary split not confirmed')
    mined = rpc('getblock', [accepted['blockhash'], 1])['height']
    save(directory / 'aux-source-compact.json', {'height': mined, 'tx': tx_hex,
        'index': compact['index'], 'value_zatoshi': compact['value_zatoshi']})
    result = capture(directory)
    save(directory / 'funded.json', result)
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['fund', 'scan'])
    parser.add_argument('directory', type=Path)
    args = parser.parse_args()
    result = (fund if args.action == 'fund' else capture)(args.directory.resolve())
    print(json.dumps(result, indent=2))
