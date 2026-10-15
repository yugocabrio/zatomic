#!/usr/bin/env python3
"""Exercise source binding with retained real isolated-chain history, no sends.

No fixture keys are copied, public network calls made or new proofs generated.
This is not a positive funded public reservation/graph/preflight demonstration.
"""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import public_source
from regtest_wallet import ROOT, NATIVE, native, save
import testnet_wallet


def check(root):
    root.mkdir(mode=0o700)
    # The original source bank and swap have already settled. Inspecting their
    # private files must never regenerate, replace or publish an old transaction.
    coordinator = ROOT/'.local/otc-success-001/coordinator'
    pczt = coordinator/'swap/unsigned-funding.pczt'
    original_scan = coordinator/'bank/scan-3563-4937266231b0aa44a9ce9c0396cb17c816b3b667a326a03587c3752499a70aaf-anchor-3557.json'
    before_spend = ROOT/'.local/source-history-001/wallet/compact-2-3563-4937266231b0aa44a9ce9c0396cb17c816b3b667a326a03587c3752499a70aaf.json'
    scan, checkpoint = testnet_wallet.read(original_scan), testnet_wallet.read(before_spend)
    chosen = None
    for index, note in enumerate(scan['notes']):
        value = dict(scan, notes=[note], fvk_fingerprint=checkpoint['fvk_fingerprint'])
        path = root/f'original-note-{index}.json'; save(path, value)
        p = subprocess.run([str(NATIVE), 'check-source-spend', str(pczt), str(path)],
            capture_output=True, text=True, timeout=30)
        if p.returncode == 0:
            if chosen is not None: raise RuntimeError('multiple source notes match the funding input')
            chosen = value
            assert json.loads(p.stdout)['source_note_nullifier_fvk_and_anchor_bound'] is True
    if chosen is None: raise RuntimeError('retained real funding PCZT failed source binding')
    for field in ('anchor', 'fvk_fingerprint'):
        changed = copy.deepcopy(chosen); changed[field] = '00'*32
        path = root/f'changed-{field}.json'; save(path, changed)
        result = subprocess.run([str(NATIVE), 'check-source-spend', str(pczt), str(path)],
            capture_output=True, text=True, timeout=30)
        if result.returncode == 0: raise RuntimeError('wrong source binding accepted')
    # Refresh the exact note from real compact checkpoints. The old source note
    # was actually consumed; the currently usable note is a different commitment.
    reference = testnet_wallet.read(ROOT/'.local/source-input-check-001/selected.json')
    wallet = ROOT/'.local/compact-wallet-002/wallet-0'
    key_wallet = ROOT/'.local/source-input-check-001/wallet' # Existing retained network/key wrapper.
    files = [(testnet_wallet.read(p), p) for p in wallet.glob('compact-*.json')]
    anchor = next(p for v, p in files if v['height'] == reference['anchor_height'])
    current = next(p for v, p in files if v['height'] == reference['height'])
    native('compact-source-snapshot', key_wallet, anchor, current, reference['principal_zatoshi'], root/'fresh.json')
    fresh = testnet_wallet.read(root/'fresh.json')
    public_source.exact_note(reference, fresh)
    changed = copy.deepcopy(fresh); changed['notes'] = chosen['notes']
    try: public_source.exact_note(reference, changed)
    except RuntimeError: pass
    else: raise RuntimeError('another real historical note replaced the reservation')
    result = subprocess.run([str(NATIVE), 'compact-source-snapshot', str(key_wallet), str(before_spend),
        str(current), str(reference['principal_zatoshi']), str(root/'spent-must-not-exist.json')],
        capture_output=True, text=True, timeout=30)
    if result.returncode == 0 or 'no mature unspent note' not in result.stderr:
        raise RuntimeError('actually spent historical source note not refused')
    # The lock test has no wallet keys, inputs or graph. A second process must
    # not sync/recheck while the source preflight owns the wallet lock.
    lock_wallet = root/'lock-only-fixture'; lock_wallet.mkdir(mode=0o700)
    save(lock_wallet/'network.json', {'genesis': testnet_wallet.GENESIS})
    marker = {'test_only': True, 'must_not_expire': True}
    save(lock_wallet/'source-reservation.json', marker)
    with public_source.locked(lock_wallet):
        probe = subprocess.run([sys.executable, '-c',
            'import pathlib,sys; import public_source\ntry:\n with public_source.locked(pathlib.Path(sys.argv[1])): pass\nexcept BlockingIOError: sys.exit(0)\nelse: sys.exit(9)',
            str(lock_wallet)], env=dict(os.environ, PYTHONPATH=str(ROOT/'scripts')),
            capture_output=True, timeout=10)
        if probe.returncode: raise RuntimeError('source lock did not exclude another process')
    assert testnet_wallet.read(lock_wallet/'source-reservation.json') == marker
    return {'scope': 'retained real regtest source PCZT and compact receive/spend history; no new chain work',
        'real_unsigned_f_bound_to_source_note_fvk_nullifier_and_anchor': True,
        'changed_anchor_and_fvk_refused': True, 'fresh_same_note_and_old_witness_preserved': True,
        'different_real_note_substitution_refused': True, 'actually_spent_historical_note_refused': True,
        'source_lock_excludes_second_process_and_preserves_reservation': True,
        'public_funded_package_graph_preflight': False, 'new_transactions': 0, 'new_proofs': 0,
        'funding_authorized': False, 'broadcast': False}


if __name__ == '__main__':
    os.umask(0o077)
    print(json.dumps(check(Path(sys.argv[1]).resolve()), indent=2))
