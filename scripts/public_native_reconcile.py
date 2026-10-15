#!/usr/bin/env python3
"""Read-only post-proof native reconciliation of one retained outgoing version.

Observe settlement BEFORE asking whether its input note is still unspent. Every
query has durable local context; a negative index result never clears exposure
history or permits another spend. Public broadcasting remains disabled.
"""
import argparse
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time
import uuid
import public_authority as authority
from public_evm_observation import digest
import public_outgoing as outgoing
import public_recovery_watch as recovery
from public_source import locked
from regtest_wallet import ROOT
from source_inputs import publish, fresh
from testnet_wallet import read, invoke

HISTORY_LIMIT = 128


def classify(agreement, expected, observation, actual, now):
    """Validate a freshly decoded/cryptographically checked observation.

    `actual` must come from check_exit on the raw bytes returned in this invocation,
    not a report supplied by a caller. Negative results cannot establish non-exposure.
    """
    p = agreement['execution_plan']['policy']
    tip = observation['observed_tip']
    stamp = datetime.fromisoformat(observation['observed_at'].replace('Z', '+00:00'))
    if (observation['format'] != 'latch-testnet-transaction-observation-v1'
            or observation['genesis'] != agreement['native_genesis']
            or observation['branch'] != agreement['native_branch']
            or observation['requested_txid'] != expected['txid']
            or stamp.utcoffset() is None
            or not -p['clock_error_seconds'] <= now-stamp.timestamp() <= p['observation_max_age_seconds']
            or type(tip['height']) is not int or not 4_465_026 <= tip['height'] <= 0xffffffff
            or not re.fullmatch('[0-9a-f]{64}', tip['hash'])
            or not -(p['native_early_header_seconds']+p['clock_error_seconds']) <= now-tip['timestamp'] <= p['native_tip_max_age_seconds']
            or observation['announced_upgrade']['height'] != 0):
        raise RuntimeError('native reconciliation domain/clock/upgrade mismatch')
    status, tx, mined = observation['status'], observation['transaction'], observation['mined_block']
    if status == 'not_found':
        if tx is not None or actual is not None or mined is not None or observation['confirmations_by_provider'] != 0:
            raise RuntimeError('inconsistent negative native observation')
        return 'unobserved-by-provider'
    if status not in ('mined', 'mempool', 'orphaned') or actual is None:
        raise RuntimeError('unrecognized native transaction observation')
    if (tx['format'] != 'latch-observed-transaction-v1' or tx['version'] != 6
            or tx['branch'] != agreement['native_branch'] or tx['txid'] != expected['txid']
            or tx['bytes_sha256'] != actual['bytes_sha256']
            or any(actual[k] != expected[k] for k in ('txid', 'bundle_digest', 'mode', 'role', 'genesis'))
            or actual['proof_and_signatures_verified'] is not True):
        raise RuntimeError('observed raw exit differs from the accepted transaction')
    # A different valid authorization/proof for the SAME effects can settle it.
    # Do not require provider raw bytes to match our selected proof version.
    if status in ('mempool', 'orphaned'):
        if mined is not None or observation['confirmations_by_provider'] != 0:
            raise RuntimeError('unmined observation has confirmations')
        return 'pending-by-provider' if status == 'mempool' else 'orphaned-by-provider'
    if (mined is None or type(mined['height']) is not int
            or not 4_465_026 <= mined['height'] <= tip['height']
            or not re.fullmatch('[0-9a-f]{64}', mined['hash'])
            or type(observation['transaction_index']) is not int or observation['transaction_index'] < 1):
        raise RuntimeError('native mined block/index mismatch')
    count = tip['height']-mined['height']+1
    if observation['confirmations_by_provider'] != count:
        raise RuntimeError('native confirmation count mismatch')
    return ('confirmed-by-provider' if count >= agreement['observation_policy']['native_min_confirmations']
        else 'confirming-by-provider')


def history(journal, binding):
    directory = journal/'native-observations'
    if not directory.exists() and not directory.is_symlink(): return {'runs': 0, 'raw_seen': False, 'confirmed_before': False, 'incomplete': 0}
    outgoing.private_directory(directory)
    entries = list(directory.iterdir())
    if len(entries) >= HISTORY_LIMIT: raise RuntimeError('native observation history full; preserve for reconciliation')
    result = {'runs': len(entries), 'raw_seen': False, 'confirmed_before': False, 'incomplete': 0}
    for entry in entries:
        if not re.fullmatch('[0-9a-f]{32}', entry.name): raise RuntimeError('unexpected native observation history entry')
        outgoing.private_directory(entry)
        for name in ('exit/transaction.hex', 'after-sync/exit/transaction.hex'):
            if (entry/name).exists() or (entry/name).is_symlink(): result['raw_seen'] = True
        # A process can die just after creating the private directory. Such an
        # entry is unresolved; do not erase it or infer that no query happened.
        if not (entry/'intent.json').exists() and not (entry/'intent.json').is_symlink():
            result['incomplete'] += 1; continue
        intent = read(entry/'intent.json')
        if intent['binding_digest'] != digest(binding): raise RuntimeError('native observation history binding changed')
        if (entry/'report.json').exists() or (entry/'report.json').is_symlink():
            report = read(entry/'report.json')
            if (report['format'] != 'latch-public-native-reconciliation-v1'
                    or report['agreement_digest'] != binding['agreement_digest']
                    or report['native_state'] not in ('unobserved-by-provider', 'pending-by-provider',
                        'orphaned-by-provider', 'confirming-by-provider', 'confirmed-by-provider')):
                raise RuntimeError('native observation report binding changed')
            result['confirmed_before'] |= report['native_state'] == 'confirmed-by-provider'
        else: result['incomplete'] += 1
    return result


def live_query(txid, directory):
    invoke('node', ROOT/'scripts/observe_testnet_transaction.mjs', txid, directory)
    return read(directory/'observation.json')


def run_observation(journal, expected, directory, query=live_query):
    """Chain-reader boundary, also testable with explicit provider transcripts.

    Cryptography is never injected: every positive raw response passes the real
    native verifier, including when this boundary is checked offline.
    """
    observation = query(expected['txid'], directory/'exit')
    actual = None
    if observation['status'] != 'not_found':
        actual, _ = outgoing.check_exit(journal['directory'], directory/'exit/transaction.hex', journal['binding'])
    state = classify(journal['files']['proposal']['agreement'], expected, observation, actual, int(time.time()))
    return observation, actual, state


def recheck_after_scan(scan, observe_again, canonical):
    """Keep the caller's watch lock; settlement may consume the note during sync.

    This only orders existing readers. It never converts a scan/RPC failure to
    absence, or approves a transaction for transmission.
    """
    failed, witness = None, None
    try:
        witness = scan()
    except (RuntimeError, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        failed = error
    observed, actual, state = observe_again()
    if state in ('unobserved-by-provider', 'orphaned-by-provider'):
        if failed is not None: raise failed
        canonical()
    else:
        witness = None
    return observed, actual, state, witness


def observe(owner, fingerprint, wallet=None, batches=4):
    if not re.fullmatch('[0-9a-f]{64}', fingerprint) or not 1 <= batches <= 32:
        raise RuntimeError('exact retained version fingerprint and bounded sync required')
    with authority.owner_locked(owner):
        journal = outgoing.verified_journal_locked(owner)
        binding, files = journal['binding'], journal['files']
        agreement = files['proposal']['agreement']
        if binding['synthetic_inputs'] is not False:
            raise RuntimeError('synthetic outgoing transactions cannot enter public reconciliation')
        selected = [v for v in journal['versions'] if v['bytes_sha256'] == fingerprint]
        if len(selected) != 1 or selected[0]['checked'] is None:
            raise RuntimeError('complete retained raw version required')
        expected = selected[0]['checked']
        previous = history(journal['directory'], binding)
        parent = journal['directory']/'native-observations'; outgoing.private_directory(parent)
        directory = parent/uuid.uuid4().hex; outgoing.private_directory(directory)
        publish(directory/'intent.json', {'format': 'latch-public-native-observation-intent-v1',
            'binding_digest': digest(binding), 'txid': expected['txid'], 'version': fingerprint,
            'prior': previous, 'broadcast': False, 'send_authorized': False})
        observed, actual, state = run_observation(journal, expected, directory)
        witness = None
        # Settlement/pending are reconciled before unspentness. A completed exit
        # has spent the joint note, so requiring that note here would reject success.
        if state in ('unobserved-by-provider', 'orphaned-by-provider') and wallet is not None:
            with locked(wallet):
                if (read(wallet/'native-recovery.json') != files['bundle']
                        or read(wallet/'owner-receipt.json') != files['proposal']['receipts'][binding['role']]):
                    raise RuntimeError('watch wallet differs from this owner outgoing journal')
                refreshed = directory/'after-sync'; outgoing.private_directory(refreshed)
                def canonical():
                    invoke('node', ROOT/'scripts/observe_testnet_source.mjs', directory/'witness/snapshot.json', directory/'post-proof-canonical.json')
                    fresh(read(directory/'post-proof-canonical.json'), int(time.time()))
                observed, actual, state, witness = recheck_after_scan(
                    lambda: recovery.observe_locked(wallet, directory/'witness', batches, expected['anchor']),
                    lambda: run_observation(journal, expected, refreshed), canonical)
        # These are still native observations only; never a refund/claim send gate.
        classify(agreement, expected, observed, actual, int(time.time()))
        if authority.bind_owner(owner, files, {'agreement_digest': binding['agreement_digest'],
                'bundle_digest': binding['bundle_digest']}, 'native_'+binding['mode']) != journal['caller']:
            raise RuntimeError('caller acceptance changed during native reconciliation')
        retained = journal['directory']/'versions'/(fingerprint+'.hex')
        if hashlib.sha256(outgoing.raw_bytes(retained)).hexdigest() != fingerprint:
            raise RuntimeError('retained raw version changed during reconciliation')
        result = {'format': 'latch-public-native-reconciliation-v1', 'agreement_digest': binding['agreement_digest'],
            'role': binding['role'], 'mode': binding['mode'], 'version': fingerprint, 'txid': expected['txid'],
            'native_state': state, 'confirmations_by_provider': observed['confirmations_by_provider'],
            'observed_bytes_sha256': None if actual is None else actual['bytes_sha256'],
            'provider_version_matches_selected': None if actual is None else actual['bytes_sha256'] == fingerprint,
            'current_unspent_witness_check': witness, 'prior': previous,
            'lost_prior_confirmation': previous['confirmed_before'] and state != 'confirmed-by-provider',
            'provider_trusted': True, 'send_authorized': False, 'broadcast': False,
            'network_exposure_excluded': False, 'reservation_released': False,
            'remaining_gates': ['counter-chain-and-secret-exposure-reconciliation', 'refund-clock-and-auxiliary-if-needed',
                'durable-send-attempt-and-transport', 'public-transfer-authorization']}
        if state in ('unobserved-by-provider', 'orphaned-by-provider') and witness is None:
            result['remaining_gates'].insert(0, 'native-exact-anchor-current-unspent-check')
        publish(directory/'report.json', result)
        return dict(result, observation_directory=str(directory))


def main():
    os.umask(0o077)
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('owner', type=Path); p.add_argument('version')
    p.add_argument('--watch-wallet', type=Path, help='same owner watch wallet; needed only if exit unobserved/orphaned')
    p.add_argument('--batches', type=int, default=4)
    a = p.parse_args()
    print(json.dumps(observe(a.owner, a.version, a.watch_wallet, a.batches), indent=2))
    return 2 # Native state is not a cross-chain sending authorization.


if __name__ == '__main__':
    try: raise SystemExit(main())
    except (RuntimeError, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        raise SystemExit('Native reconciliation refused; all private history retained, no transaction sent.') from None
