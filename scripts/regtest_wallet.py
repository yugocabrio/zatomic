#!/usr/bin/env python3
"""Obtain actual matured local notes and trusted node captures; no public RPC."""
import argparse
from decimal import Decimal, ROUND_DOWN
import json
import os
from pathlib import Path
import subprocess
import tempfile
import owned_process
from regtest_node import ROOT, GENESIS, BRANCH, rpc, status

NATIVE = ROOT / 'target/release/shielded-swap-native'
INITIAL_HEIGHT = 2
MAX_CAPTURE_HEIGHT = INITIAL_HEIGHT + 10_000  # Matches native wallet.rs; JSON remains capped at 50 MB.
FUNDING_ANCHOR_LAG = 6  # Local fixture policy, not a public-network finality guarantee.


# Demo amounts: 0.015 ZEC for 0.0293 ETH. The faucet funds Alice with one
# coinbase note, and the regtest block reward halves every 864 blocks (0.0163 ZEC
# from height 6,041, 0.0081 from 6,905), so the payout shrinks to fit that note:
# the stage needs one note above payout + 55,000 zatoshi (two fees, the refund
# coin and its fee).
DEMO_PAYOUT_ZATOSHI, DEMO_ETH = 1_500_000, Decimal('0.0293')
FUNDING_OVERHEAD = 60_000


def demo_amounts(margin_blocks=20):
    """(zec, eth) decimal strings for a demo quote funded within margin_blocks."""
    height = status()['blocks'] + margin_blocks  # The reward never grows with height.
    reward = round(rpc('getblocksubsidy', [height])['miner'] * 100_000_000)
    payout = min(DEMO_PAYOUT_ZATOSHI, (reward - FUNDING_OVERHEAD) // 10_000 * 10_000)
    if payout <= 0:
        raise RuntimeError('the regtest block reward is too small to fund a demo trade')
    eth = (DEMO_ETH * payout / DEMO_PAYOUT_ZATOSHI).quantize(Decimal('0.0001'), ROUND_DOWN)
    return str(Decimal(payout) / 100_000_000).rstrip('0'), str(eth)


def require_capacity(additional_blocks):
    if status()['blocks'] + additional_blocks > MAX_CAPTURE_HEIGHT:
        raise RuntimeError('isolated history budget would be exceeded; no new funding started')


def native(*args):
    return json.loads(owned_process.run([str(NATIVE), *map(str, args)], cwd=ROOT,
        text=True, capture_output=True, check=True, env=dict(os.environ, RAYON_NUM_THREADS='2')).stdout)


def save(path, value):
    # Immutable snapshot: callers must give distinct observations distinct names.
    encoded = json.dumps(value, sort_keys=True)
    if path.exists():
        if json.loads(path.read_text()) != value:
            raise RuntimeError('existing private snapshot differs')
        return
    # Publish only complete bytes. Killing a writer cannot leave a truncated
    # destination that a recovering client mistakes for a durable decision.
    fd, temporary = tempfile.mkstemp(prefix='.pending-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as f:
            f.write(encoded)
            f.flush()
            os.fsync(f.fileno())
        try:
            os.link(temporary, path)  # create-once; never overwrite a journal
        except FileExistsError:
            if json.loads(path.read_text()) != value:
                raise RuntimeError('concurrent private snapshot differs')
        parent = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(parent)
            os.unlink(temporary)
            os.fsync(parent)
        finally:
            os.close(parent)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def capture(directory, funding_anchor_lag=0):
    os.umask(0o077)
    tip = status()
    if not INITIAL_HEIGHT <= tip['blocks'] <= MAX_CAPTURE_HEIGHT:
        raise RuntimeError('bounded NU7 history required')
    if not 0 <= funding_anchor_lag <= tip['blocks'] - INITIAL_HEIGHT:
        raise RuntimeError('funding anchor outside available history')
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
    suffix = ''
    if funding_anchor_lag:
        value['anchor_height'] = tip['blocks'] - funding_anchor_lag
        suffix = f'-anchor-{value["anchor_height"]}'
    path = directory / f'capture-{tip["blocks"]}-{tip["tip"]}{suffix}.json'
    save(path, value)
    return dict(native('regtest-scan', directory, path), capture_file=str(path))


def funding_capture(directory):
    observed = capture(directory, FUNDING_ANCHOR_LAG)
    if not observed['unspent_notes']:
        # The owned regtest has no autonomous miner. Give recent change time to
        # enter the older anchor. This is harness mining, never mainnet policy.
        require_capacity(FUNDING_ANCHOR_LAG)
        rpc('generate', [FUNDING_ANCHOR_LAG], timeout=300)
        observed = capture(directory, FUNDING_ANCHOR_LAG)
    if not observed['unspent_notes']:
        raise RuntimeError('no current unspent source note at the funding anchor')
    return observed


def fund(directory):
    """One mined shielded source note. No transparent coin: a swap's refund
    auxiliary is created from its own funding change, only if refunded."""
    os.umask(0o077)
    require_capacity(101)  # Reject before creating a wallet or mining anything.
    if status()['blocks'] < 2:
        raise RuntimeError('activate isolated NU7 first')
    initialized = native('regtest-init', directory)
    rpc('generatetoaddress', [1, initialized['address']], timeout=300)
    rpc('generate', [100], timeout=300)
    result = capture(directory)
    if result['unspent_notes'] != 1:
        raise RuntimeError('expected one mined shielded source note')
    save(directory / 'funded.json', result)
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['fund', 'scan'])
    parser.add_argument('directory', type=Path)
    args = parser.parse_args()
    result = (fund if args.action == 'fund' else capture)(args.directory.resolve())
    print(json.dumps(result, indent=2))
