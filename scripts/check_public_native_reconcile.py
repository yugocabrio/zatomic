#!/usr/bin/env python3
"""Real native verification with explicit offline provider transcripts.

Retained proofs/checkpoints have synthetic public-profile inputs and block
hashes. No RPC, new proof, source/owner signing key or exposed opening is used.
"""
import copy
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import sys
import time
from check_public_authority import OWNER_FILES, refuses
from check_public_outgoing import copy_private, hashes
import public_authority as authority
import public_native_reconcile as reconcile
import public_outgoing as outgoing
import public_recovery_watch as recovery
from public_evm_observation import digest
from regtest_wallet import ROOT, native, save
from testnet_wallet import head, read


def transcript(journal, expected, raw, status='mined', confirmations=12):
    """Invented provider status, actual raw tx decoder and actual exit verifier."""
    def query(txid, directory):
        assert txid == expected['txid']
        directory.mkdir(mode=0o700)
        now = int(time.time())
        parsed = None
        if status != 'not_found':
            copy_private(raw, directory/'transaction.hex')
            parsed = native('inspect-transaction', directory/'transaction.hex')
        report = {'format': 'latch-testnet-transaction-observation-v1',
            'genesis': expected['genesis'], 'branch': '77190ad9', 'requested_txid': txid,
            'observed_at': datetime.now(timezone.utc).isoformat(),
            'observed_tip': {'height': 4_505_000, 'hash': 'aa'*32, 'timestamp': now},
            'announced_upgrade': {'height': 0}, 'status': status, 'transaction': parsed,
            'mined_block': {'height': 4_505_001-confirmations, 'hash': 'bb'*32} if status == 'mined' else None,
            'confirmations_by_provider': confirmations if status == 'mined' else 0,
            'transaction_index': 1 if status == 'mined' else None}
        save(directory/'observation.json', report)
        return report
    return query


def run(root, fixture, witness, alternate):
    root.mkdir(mode=0o700)
    original = hashes(fixture)
    journals = {}
    for role in ('alice', 'bob'):
        owner = root/role; owner.mkdir(mode=0o700)
        for name in OWNER_FILES: copy_private(fixture/role/name, owner/name)
        shutil.copytree(fixture/role/outgoing.JOURNAL, owner/outgoing.JOURNAL)
        with authority.owner_locked(owner):
            journal = outgoing.verified_journal_locked(owner)
        expected = journal['versions'][0]['checked']
        assert expected['proof_and_signatures_verified'] and expected['synthetic_inputs']
        journals[role] = journal
        # Full public entry must stop before a provider request or observation intent.
        refuses(lambda: reconcile.observe(owner, expected['bytes_sha256']), 'synthetic outgoing')
        assert not (owner/outgoing.JOURNAL/'native-observations').exists()
        directory = root/(role+'-observed'); directory.mkdir(mode=0o700)
        raw = journal['directory']/'versions'/(expected['bytes_sha256']+'.hex')
        observed, actual, state = reconcile.run_observation(journal, expected, directory,
            transcript(journal, expected, raw))
        assert state == 'confirmed-by-provider' and actual['bytes_sha256'] == expected['bytes_sha256']
        agreement = journal['files']['proposal']['agreement']
        for status, required in (('mempool', 'pending-by-provider'), ('orphaned', 'orphaned-by-provider'),
                ('not_found', 'unobserved-by-provider')):
            value = copy.deepcopy(observed)
            value.update(status=status, mined_block=None, transaction_index=None, confirmations_by_provider=0)
            checked = actual
            if status == 'not_found': value['transaction'] = None; checked = None
            assert reconcile.classify(agreement, expected, value, checked, int(time.time())) == required
        shallow = copy.deepcopy(observed); shallow['mined_block']['height'] += 1; shallow['confirmations_by_provider'] = 11
        assert reconcile.classify(agreement, expected, shallow, actual, int(time.time())) == 'confirming-by-provider'
        for label in ('wrong-id', 'stale', 'invalid-confirmations'):
            bad = copy.deepcopy(observed)
            if label == 'wrong-id': bad['requested_txid'] = '00'*32
            if label == 'stale': bad['observed_at'] = '2026-01-01T00:00:00Z'
            if label == 'invalid-confirmations': bad['confirmations_by_provider'] = 13
            refuses(lambda: reconcile.classify(agreement, expected, bad, actual, int(time.time())),
                'count' if label == 'invalid-confirmations' else 'domain')
    alice = journals['alice']; expected = alice['versions'][0]['checked']
    alternate_dir = root/'alternate-proof'; alternate_dir.mkdir(mode=0o700)
    alternate_result = reconcile.run_observation(alice, expected, alternate_dir,
        transcript(alice, expected, alternate))
    assert alternate_result[2] == 'confirmed-by-provider'
    assert alternate_result[1]['bytes_sha256'] != expected['bytes_sha256']
    # The exact same effects can settle using another valid randomized proof.
    # Invalid bytes with that txid must still fail the REAL verifier.
    corrupt = root/'invalid-proof.hex'; changed = bytearray(outgoing.raw_bytes(alternate)); changed[-1] ^= 1
    corrupt.write_text(changed.hex()); os.chmod(corrupt, 0o600)
    invalid_dir = root/'invalid-observed'; invalid_dir.mkdir(mode=0o700)
    try: reconcile.run_observation(alice, expected, invalid_dir, transcript(alice, expected, corrupt))
    except Exception as error:
        if 'proof or signature invalid' not in str(error) and 'returned non-zero exit status' not in str(error): raise
    else: raise RuntimeError('unverified provider authorization accepted')

    wallet = root/'watch'; wallet.mkdir(mode=0o700)
    for name in ('watch-binding.json', 'network.json', 'native-recovery.json', 'owner-receipt.json', 'joint-fvk.bin', 'head.json'):
        copy_private(witness/name, wallet/name)
    for path in witness.glob('compact-*.json'): copy_private(path, wallet/path.name)
    info = read(wallet/'head.json')
    checkpoints = {read(p)['height']: p.name for p in wallet.glob('compact-*.json')}
    head(wallet, dict(info, checkpoint=checkpoints[4_500_012]))
    exact = root/'exact-anchor'; exact.mkdir(mode=0o700)
    snapshot = recovery.snapshot_for_anchor(wallet, exact, expected['anchor'])
    assert snapshot['anchor'] == expected['anchor']
    wrong = root/'missing-anchor'; wrong.mkdir(mode=0o700)
    refuses(lambda: recovery.snapshot_for_anchor(wallet, wrong, '00'*32), 'no twelve-confirmed')
    # Only this copied watch head advances to the retained spent checkpoint.
    head(wallet, dict(info, checkpoint=checkpoints[4_500_013]))
    scans = 0
    def scan_spent():
        nonlocal scans
        scans += 1
        directory = root/('spent-scan-'+str(scans)); directory.mkdir(mode=0o700)
        return recovery.snapshot_for_anchor(wallet, directory, expected['anchor'])
    def canonical_must_not_run(): raise RuntimeError('spent snapshot must not be declared canonical/unspent')
    # Actual native spent-note rejection is superseded by a cryptographically
    # verified exit observed during the scan, never by an invented success flag.
    result = reconcile.recheck_after_scan(scan_spent, lambda: alternate_result, canonical_must_not_run)
    assert result[2] == 'confirmed-by-provider' and result[3] is None
    negative_dir = root/'negative'; negative_dir.mkdir(mode=0o700)
    negative = reconcile.run_observation(alice, expected, negative_dir,
        transcript(alice, expected, None, 'not_found'))
    refuses(lambda: reconcile.recheck_after_scan(scan_spent, lambda: negative, canonical_must_not_run), 'exact funding note absent/spent')
    def offline(): raise RuntimeError('provider unavailable')
    refuses(lambda: reconcile.recheck_after_scan(lambda: snapshot, offline, canonical_must_not_run), 'provider unavailable')

    parent = alice['directory']/'native-observations'; parent.mkdir(mode=0o700)
    confirmed = parent/('01'*16); confirmed.mkdir(mode=0o700)
    save(confirmed/'intent.json', {'binding_digest': digest(alice['binding'])})
    save(confirmed/'report.json', {'format': 'latch-public-native-reconciliation-v1',
        'agreement_digest': alice['binding']['agreement_digest'], 'native_state': 'confirmed-by-provider'})
    later = parent/('02'*16); later.mkdir(mode=0o700)
    save(later/'intent.json', {'binding_digest': digest(alice['binding'])})
    save(later/'report.json', {'format': 'latch-public-native-reconciliation-v1',
        'agreement_digest': alice['binding']['agreement_digest'], 'native_state': 'unobserved-by-provider'})
    interrupted = parent/('03'*16); interrupted.mkdir(mode=0o700); (interrupted/'exit').mkdir(mode=0o700)
    copy_private(alternate, interrupted/'exit/transaction.hex')
    before = hashes(parent)
    past = reconcile.history(alice['directory'], alice['binding'])
    assert past == {'runs': 3, 'raw_seen': True, 'confirmed_before': True, 'incomplete': 1}
    assert hashes(parent) == before and hashes(fixture) == original
    return {'scope': 'real native proofs/signatures/witness checks; explicitly synthetic provider status and inputs',
        'both_roles_retained_journal_and_raw_verified': True,
        'different_valid_proof_same_txid_recognized': True,
        'invalid_provider_authorization_refused': True,
        'exact_anchor_and_current_unspent_native_checked': True,
        'settlement_during_spent_note_scan_reconciled': True,
        'absence_does_not_override_spent_note_or_rpc_failure': True,
        'prior_confirmation_and_incomplete_raw_history_retained': True,
        'synthetic_public_entry_refused_before_query_or_intent': True,
        'original_journals_unchanged': True, 'rpc_calls': 0, 'new_proofs': 0,
        'public_funded_execution': False, 'broadcast': False}


if __name__ == '__main__':
    os.umask(0o077)
    print(json.dumps(run(*(Path(p).resolve() for p in sys.argv[1:5])), indent=2))
