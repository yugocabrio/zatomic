#!/usr/bin/env python3
"""Watch-only public native recovery preparation, never broadcasting.

Initialize from a portable owner export, sync the joint FVK locally, then
obtain the exact still-unspent funding note at a confirmed historical anchor.
Offline reproof is a separate native command. No original wallet/signing key,
secret opening, ETH RPC, first-reveal decision or cross-chain sender is used.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import time
from regtest_wallet import save
from testnet_wallet import ROOT, NATIVE, GENESIS, checkpoint, invoke, read, sync
from public_source import locked
from source_inputs import fresh
from public_preflight import native_funding


def checked(wallet):
    report = invoke(NATIVE, 'testnet-inspect-recovery', wallet)
    if report['synthetic_inputs'] is not False:
        raise RuntimeError('synthetic recovery is offline only; no public observer queries')
    binding = read(wallet/'watch-binding.json')
    if (binding['format'] != 'latch-public-recovery-watch-v1'
            or binding['bundle_digest'] != report['bundle_digest']
            or binding['role'] != report['role'] or binding['genesis'] != GENESIS):
        raise RuntimeError('watch-only recovery identity changed')
    return report


def observe(wallet, directory, batches):
    """Hold sync.lock through acquisition. Old checkpoints never get overwritten.

    No refund/reveal cutoff is used here: recovery may be needed AFTER expiry.
    This is not the first-reveal preflight and grants no execution permission.
    """
    with locked(wallet):
        return observe_locked(wallet, directory, batches)


def snapshot_for_anchor(wallet, directory, exact_anchor=None):
    """Offline exact-anchor selection; native verifier checks every witness/root.

    This does not query a provider or establish canonicality/unspentness now.
    """
    info, current = checkpoint(wallet)
    anchors = []
    for file in wallet.glob('compact-*.json'):
        value = read(file)
        if (value['genesis'] == GENESIS and value['birthday_height'] == info['birthday']
                and type(value['height']) is int and value['height'] <= current['height']-11
                and (exact_anchor is None or value['anchor'] == exact_anchor)):
            anchors.append((value['height'], value))
    if not anchors:
        raise RuntimeError('no twelve-confirmed checkpoint for the required anchor; retain state and reprove if necessary')
    _, anchor = max(anchors, key=lambda a: a[0])
    save(directory/'anchor.json', anchor)
    save(directory/'current.json', current)
    invoke(NATIVE, 'testnet-recovery-snapshot', wallet, directory/'anchor.json',
        directory/'current.json', directory/'snapshot.json')
    selected = read(directory/'snapshot.json')
    if exact_anchor is not None and selected['anchor'] != exact_anchor:
        raise RuntimeError('recovery snapshot differs from prepared transaction anchor')
    return selected


def observe_locked(wallet, directory, batches, exact_anchor=None):
    """Caller holds sync.lock; optionally require a prepared raw tx's anchor.

    A newer usable anchor cannot silently validate already-proved bytes.
    Reproof is a separate operation retaining every old outgoing version.
    """
    report = checked(wallet)  # Full offline bundle/receipt validation before RPC.
    directory.mkdir(mode=0o700)
    scanned = sync(wallet, batches)
    if scanned['caught_up_to_observed_tip'] is not True:
        raise RuntimeError('watch wallet behind provider; continue explicit sync')
    selected = snapshot_for_anchor(wallet, directory, exact_anchor)
    invoke('node', ROOT/'scripts/observe_testnet_transaction.mjs', report['funding_txid'], directory/'funding')
    funding = read(directory/'funding/observation.json')
    bundle = read(wallet/'native-recovery.json')
    # Same fixed native clock/confirmation rules as consent/preflight, without
    # pretending that this partial descriptor is a signed cross-chain agreement.
    descriptor = {'execution_plan': bundle['review']['plan'], 'native_genesis': GENESIS,
        'native_branch': '77190ad9', 'native': {'funding_txid': report['funding_txid']},
        'observation_policy': {'native_min_confirmations': 12}}
    native_funding(descriptor, funding, int(time.time()))
    if funding['mined_block']['height'] != selected['notes'][0]['height']:
        raise RuntimeError('raw funding observation differs from scanned note origin')
    # LAST provider operation rechecks the old tree and current nullifier tip.
    # A tip advance/reorg refuses; no blind rewind, snapshot reuse or auto-retry.
    invoke('node', ROOT/'scripts/observe_testnet_source.mjs', directory/'snapshot.json', directory/'canonical.json')
    canonical = read(directory/'canonical.json')
    fresh(canonical, int(time.time()))
    native_funding(descriptor, funding, int(time.time()))
    result = {'format': 'latch-public-recovery-observation-v1',
        'bundle_digest': report['bundle_digest'], 'role': report['role'],
        'funding_txid': report['funding_txid'], 'height': selected['height'],
        'anchor_height': selected['anchor_height'], 'anchor': selected['anchor'],
        'exact_funding_note_unspent_in_scan': True,
        'canonical_trees_rechecked': True, 'provider_trusted': True,
        'spending_keys_read': False, 'secret_opening_read': False, 'broadcast': False,
        'execution_enabled': False, 'refund_auxiliary_checked': False,
        'scope': 'fresh trusted-provider native witness acquisition only; not outgoing recovery authorization'}
    save(directory/'observation.json', result)
    return result


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='operation', required=True)
    init = sub.add_parser('init')
    init.add_argument('portable', type=Path); init.add_argument('wallet', type=Path)
    init.add_argument('--birthday', type=int, required=True, help='exclusive post-NU7 height BEFORE F')
    for name in ('sync', 'observe'):
        p = sub.add_parser(name); p.add_argument('wallet', type=Path)
        p.add_argument('--batches', type=int, default=4)
        if name == 'observe': p.add_argument('directory', type=Path)
    args = parser.parse_args()
    if args.operation == 'init':
        return invoke(NATIVE, 'testnet-recovery-watch', args.portable, args.wallet, args.birthday)
    if not 1 <= args.batches <= 32: raise RuntimeError('batch count must be 1..32')
    if args.operation == 'sync':
        with locked(args.wallet):
            checked(args.wallet)
            return sync(args.wallet, args.batches)
    return observe(args.wallet, args.directory, args.batches)


if __name__ == '__main__':
    try:
        print(json.dumps(main(), indent=2))
    except (RuntimeError, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        raise SystemExit('Recovery observation failed; private checkpoints retained, no transaction sent.') from None
