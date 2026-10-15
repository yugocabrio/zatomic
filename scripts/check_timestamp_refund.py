#!/usr/bin/env python3
"""Real native timestamp refund gate on the existing OWNED isolated Zebra.

No ETH transfer or public RPC. The regtest clock is deliberately historical;
this tests nLockTime mechanics, not a deployable cross-chain timing profile.
Retains all private state and can resume after funding/proof/confirmation.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import native_funding
from owner_swap import chain_lock
from regtest_node import rpc, status
from regtest_wallet import fund, capture, native, save, require_capacity
from run_regtest_swap import reject_native, require_aux_unspent


def read(path):
    return json.loads(path.read_text())


def clock():
    tip = status()
    blocks = [rpc('getblock', [rpc('getblockhash', [h]), 1])
        for h in range(tip['blocks'] - 10, tip['blocks'] + 1)]
    if status()['tip'] != tip['tip']:
        raise RuntimeError('owned chain changed while reading clock')
    return {'height': tip['blocks'], 'tip': tip['tip'], 'header_time': blocks[-1]['time'],
        'median_time_past': sorted(b['time'] for b in blocks)[5]}


def reject_locked(file):
    error = reject_native(file)
    if not any(s in error.lower() for s in ('nonfinal', 'non-final', 'locktime', 'lock time', 'locked until')):
        raise RuntimeError('timestamp refund rejected for a different reason: ' + error)
    return error


def confirm(file, txid):
    found = native_funding.current(txid)
    sent = False
    if not found:
        if rpc('sendrawtransaction', [file.read_text().strip()], timeout=180) != txid:
            raise RuntimeError('broadcast identity mismatch')
        sent = True
    depth = found.get('confirmations', 0) if found.get('in_active_chain') else 0
    if depth < 2:
        rpc('generate', [2 - depth], timeout=300)
    found = native_funding.current(txid)
    if not found.get('in_active_chain') or found.get('confirmations', 0) < 2:
        raise RuntimeError('native timestamp gate requires two controlled confirmations')
    return sent


def check(root, resume, existing_bank=None):
    with chain_lock():
        status()
        if not resume:
            require_capacity(240)
            root.mkdir(mode=0o700)
        elif not root.is_dir():
            raise RuntimeError('resume requires an existing retained fixture')
        if existing_bank is not None and (resume or not (existing_bank / 'funded.json').exists()):
            raise RuntimeError('bank option requires a completed own source fixture on a fresh run')
        if not (root / 'source.json').exists():
            save(root / 'source.json', {'bank': str(existing_bank or root / 'bank')})
        bank = Path(read(root / 'source.json')['bank'])
        swap, recovery = root / 'swap', root / 'recovery'
        offline = root / 'native-setup-offline'
        if offline.exists():
            if swap.exists():
                raise RuntimeError('ambiguous offline native setup')
            offline.rename(swap)
        if (root / 'complete.json').exists():
            result = read(root / 'complete.json')
            tx = native_funding.current(result['refund_txid'])
            if not tx.get('in_active_chain') or tx.get('confirmations', 0) < 2:
                raise RuntimeError('completed timestamp refund lost confirmation; retain state')
            return dict(result, repeated=True, new_transactions=0)
        if not (bank / 'funded.json').exists():
            if bank.exists():
                raise RuntimeError('incomplete source preparation retained; inspect before funding again')
            fund(bank)
        if not (root / 'clock-request.json').exists():
            observed = clock()
            save(root / 'clock-request.json', dict(observed, refund_timestamp=observed['header_time'] + 6))
        request = read(root / 'clock-request.json')
        deadline = request['refund_timestamp']
        if not (swap / 'terms.json').exists():
            if swap.exists():
                raise RuntimeError('partial native preparation retained; do not recreate signer nonces')
            try:
                native('regtest-prepare-timestamp', bank, read(bank / 'funded.json')['file'], swap, deadline)
            except subprocess.CalledProcessError as error:
                # stderr can contain private diagnostics: retain only locally.
                (root / 'native-prepare-error.log').write_text(error.stderr or '')
                raise RuntimeError('native preparation failed; private diagnostic retained') from None
        terms = read(swap / 'terms.json')
        if terms.get('refund_lock') != {'kind': 'timestamp', 'value': deadline} or 'refund_height' in terms:
            raise RuntimeError('timestamp terms ambiguous or changed')
        try:
            native_funding.controlled_refund_height(terms)
        except RuntimeError:
            pass
        else:
            raise RuntimeError('timestamp primitive entered height-based cross-chain client')
        if not recovery.exists():
            native('regtest-export-recovery', swap / 'alice', recovery)
        funding = native_funding.current(terms['funding_txid'])
        if not funding:
            require_aux_unspent(terms)
            if clock()['median_time_past'] >= deadline:
                raise RuntimeError('test clock advanced during preparation; refuse funding')
        funding_sent = confirm(swap / 'funding.hex', terms['funding_txid'])
        save(root / 'funded.json', {'txid': terms['funding_txid']})
        # The exported watch-only bundle has all necessary authority. The entire
        # source/signer setup becomes unavailable during proof and settlement.
        save(root / 'offline-intent.json', {'directory': str(swap)})
        swap.rename(offline)
        try:
            prepared_path = root / 'prepared-refund.json'
            if not prepared_path.exists():
                scan = capture(recovery)
                prepared = native('regtest-finish', recovery, scan['file'], 'refund')
                if prepared['lock_time'] != deadline or prepared['transparent_inputs'] != 1:
                    raise RuntimeError('wrong native refund lock/layout')
                save(prepared_path, prepared)
            prepared = read(prepared_path)
            file = Path(prepared['file'])
            if not (root / 'before.json').exists():
                now = clock()
                if now['median_time_past'] >= deadline:
                    raise RuntimeError('missed pre-lock test observation; retain recovery')
                save(root / 'before.json', dict(now, rejected=reject_locked(file)))
            for _ in range(120):
                now = clock()
                if now['median_time_past'] >= deadline:
                    break
                rpc('generate', [1], timeout=300)
            else:
                raise RuntimeError('timestamp test mining bound reached')
            if not (root / 'equal.json').exists():
                if now['median_time_past'] != deadline:
                    raise RuntimeError('missed equality test boundary; retain recovery')
                save(root / 'equal.json', dict(now, rejected=reject_locked(file)))
            for _ in range(12):
                if clock()['median_time_past'] > deadline:
                    break
                rpc('generate', [1], timeout=300)
            else:
                raise RuntimeError('timestamp equality did not advance within bound')
            sent = confirm(file, prepared['txid'])
            scanned = capture(recovery / 'alice')
            notes = read(Path(scanned['file']))['notes']
            if not any(n['txid'] == prepared['txid'] and n['value'] == terms['payout_zatoshi'] for n in notes):
                raise RuntimeError('Alice did not decrypt the exact refund')
            tx = native_funding.current(prepared['txid'])
            mined = rpc('getblock', [tx['blockhash'], 1])
            if mined['time'] <= deadline:
                raise RuntimeError('refund block violates strict timestamp lock')
            result = {'scope': 'native timestamp mechanics on isolated Zebra, no ETH/public execution',
                'funding_txid': terms['funding_txid'], 'refund_txid': prepared['txid'], 'refund_timestamp': deadline,
                'refund_block_time': mined['time'], 'refund_height': mined['height'],
                'received_zatoshi': terms['payout_zatoshi'], 'confirmations': tx['confirmations'],
                'rejected_before_mtp': read(root / 'before.json')['median_time_past'],
                'rejected_at_equal_mtp': read(root / 'equal.json')['median_time_past'],
                'whole_original_setup_absent_during_exit': True, 'exit_uses_watch_only_export': True,
                'controlled_height_client_refuses_timestamp_profile': True,
                'public_safety_window_demonstrated': False, 'new_transactions': int(funding_sent) + int(sent)}
            save(root / 'complete.json', result)
            return result
        finally:
            offline.rename(swap)


if __name__ == '__main__':
    os.umask(0o077)
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('directory', type=Path)
    p.add_argument('--resume', action='store_true')
    p.add_argument('--bank', type=Path, help='reuse a mature own source fixture with an unspent auxiliary')
    args = p.parse_args()
    print(json.dumps(check(args.directory.resolve(), args.resume, args.bank.resolve() if args.bank else None), indent=2))
