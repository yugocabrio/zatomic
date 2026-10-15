#!/usr/bin/env python3
"""Owner-locked native delivery from retained valid bytes and fresh recovery policy.

Check is read-only on the networks. Explicit --broadcast-testnet submits only
the exact retained version, after persisting possible delivery. No public funded
positive run has been demonstrated. RPC and timing assumptions remain explicit.
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
import public_outgoing as out
import public_recovery_decision as recovery
import public_evm_observation as eth
import probe_sepolia
from regtest_wallet import ROOT
from source_inputs import publish
from testnet_wallet import read


def retain(journal, fingerprint):
    if not re.fullmatch('[0-9a-f]{64}', fingerprint): raise RuntimeError('exact native version required')
    selected = [v for v in journal['versions'] if v['bytes_sha256'] == fingerprint and v['checked'] is not None]
    if len(selected) != 1: raise RuntimeError('complete native version required')
    checked = selected[0]['checked']; path = journal['directory']/'versions'/(fingerprint+'.hex')
    raw = out.raw_bytes(path)
    if hashlib.sha256(raw).hexdigest() != checked['bytes_sha256']: raise RuntimeError('native bytes changed')
    return raw, checked


def send_once(directory, identity, raw, fresh_guard, transport):
    """Write-ahead primitive. Callers retain owner/source locks throughout.

    Fresh guard returns a short absolute transport validity, never a cached
    report loaded by a CLI. A negative response is still possible delivery.
    """
    if hashlib.sha256(raw).hexdigest() != identity['bytes_sha256']: raise RuntimeError('native retained bytes changed')
    validity = fresh_guard()
    if not time.time() < validity <= time.time()+120: raise RuntimeError('fresh native send validity required')
    out.private_directory(directory)
    out.immutable(directory/'binding.json', identity)
    entries = [p for p in directory.iterdir() if p.name != 'binding.json']
    if len(entries) >= 128 or any(not re.fullmatch('[0-9a-f]{32}', p.name) for p in entries):
        raise RuntimeError('native delivery history bound/shape; preserve all attempts')
    for entry in entries: out.private_directory(entry)
    attempt = directory/uuid.uuid4().hex; out.private_directory(attempt)
    publish(attempt/'intent.json', dict(identity, format='latch-native-send-attempt-v1',
        valid_until=validity, may_have_reached_network=True))
    try:
        result = transport(raw, validity)
        if (result['txid'] != identity['txid'] or result['bytes_sha256'] != identity['bytes_sha256']
                or result['submitted_to_provider'] is not True or result['confirmed'] is not False):
            raise RuntimeError('native submit response mismatch')
    except Exception:
        publish(attempt/'result.json', {'status': 'uncertain', 'may_have_reached_network': True})
        return {'status': 'uncertain', 'txid': identity['txid'], 'attempt': attempt.name,
            'confirmation_required': True, 'broadcast_may_have_occurred': True}
    publish(attempt/'result.json', {'status': 'submitted', 'txid': identity['txid'], 'confirmation_required': True})
    return {'status': 'submitted', 'txid': identity['txid'], 'attempt': attempt.name,
        'confirmation_required': True, 'broadcast_may_have_occurred': True}


def transport(raw, validity, txid, lock_fds):
    locks = []
    for fd in lock_fds:
        meta = os.fstat(fd); locks.append({'fd': fd, 'dev': meta.st_dev, 'ino': meta.st_ino})
    request = {'raw_hex': raw.hex(), 'sha256': hashlib.sha256(raw).hexdigest(), 'txid': txid,
        'valid_until': validity, 'lock_fds': locks}
    result = subprocess.run(['node', str(ROOT/'scripts/send_testnet_transaction.mjs'), '--broadcast-testnet'],
        input=json.dumps(request), pass_fds=tuple(lock_fds), capture_output=True, text=True, timeout=150, check=True)
    return json.loads(result.stdout)


def require_decision(decision, agreement, expected, now=None):
    now = int(time.time()) if now is None else now
    if (decision['agreement_digest'] != eth.digest(agreement) or decision['mode'] != expected['mode']
            or decision['native']['txid'] != expected['txid']
            or decision['native']['version'] != expected['bytes_sha256']):
        raise RuntimeError('native recovery decision differs from retained bytes')
    if decision['blockers'] or decision['reader_errors']:
        raise RuntimeError('native recovery prerequisites unresolved')
    allowed = {'claim': ('prepare-native-claim-send', 'urgent-native-claim-outside-timing-assumption'),
        'refund': ('prepare-native-refund-send',)}[expected['mode']]
    if decision['action'] not in allowed: raise RuntimeError('native exit already observed or not executable')
    if decision['native']['current_unspent_witness_check'] is None:
        raise RuntimeError('exact current unspent witness required')
    if expected['mode'] == 'refund' and (decision['local_claim_history'] is None
            or decision['local_claim_history']['local_claim_may_be_exposed']):
        raise RuntimeError('native refund forbidden after possible exposure')
    # Re-evaluate freshness/timing using the same actual observations; this is
    # not a token parser. The caller obtains decision under its owner lock.
    again = recovery.decide(agreement, expected['mode'], decision['native'],
        decision['local_claim_history'], decision['eth_observation'], decision['auxiliary'], now)
    if again['blockers'] or again['action'] != decision['action']:
        raise RuntimeError('native recovery decision became stale')
    observed = datetime.fromisoformat(decision['native']['native_clock']['observed_at'].replace('Z', '+00:00')).timestamp()
    expiry = int(observed+agreement['execution_plan']['policy']['observation_max_age_seconds'])
    if expected['mode'] == 'refund':
        eth_time = datetime.fromisoformat(decision['eth_observation']['clock']['observed_at'].replace('Z', '+00:00')).timestamp()
        aux_time = datetime.fromisoformat(decision['auxiliary']['observed_at'].replace('Z', '+00:00')).timestamp()
        p = agreement['execution_plan']['policy']
        if not -p['clock_error_seconds'] <= now-aux_time <= p['observation_max_age_seconds']:
            raise RuntimeError('refund auxiliary observation became stale')
        expiry = min(expiry, int(min(eth_time, aux_time)+p['observation_max_age_seconds']))
    return min(now+60, expiry)


def execute(owner, version, consents, wallet, batches=4, endpoint=probe_sepolia.ENDPOINT, broadcast=False):
    with authority.owner_locked(owner) as owner_fd:
        journal = out.verified_journal_locked(owner)
        if read(consents) != journal['files']['consents']: raise RuntimeError('exact accepted consents required')
        if journal['binding']['synthetic_inputs'] is not False:
            raise RuntimeError('synthetic inputs cannot enter public native execution')
        raw, checked = retain(journal, version)
        agreement = journal['files']['proposal']['agreement']
        decision = recovery.reconcile_locked(owner, version, consents, wallet, batches, endpoint)
        if decision['action'] in ('native-exit-confirmed-check-counter-asset', 'monitor-native-exit'):
            return {'action': decision['action'], 'decision': decision, 'new_submission': False, 'send_authorized': False}
        result = {}
        def fresh_guard():
            validity = require_decision(decision, agreement, checked)
            if (authority.bind_owner(owner, journal['files'], journal['binding'], 'native_'+checked['mode']) != journal['caller']
                    or read(consents) != journal['files']['consents'] or retain(journal, version)[0] != raw):
                raise RuntimeError('owner acceptance or native raw changed before send')
            result.update(action='ready-for-explicit-testnet-send', txid=checked['txid'],
                decision_digest=eth.digest(decision), provider_trusted=True, new_submission=False,
                send_authorized=False, broadcast=False)
            return validity
        if not broadcast:
            fresh_guard(); return result
        directory = journal['directory']/'delivery'; out.private_directory(directory)
        identity = {'agreement_digest': journal['binding']['agreement_digest'], 'mode': checked['mode'],
            'txid': checked['txid'], 'bytes_sha256': version}
        submitted = send_once(directory/version, identity, raw, fresh_guard,
            lambda data, validity: transport(data, validity, checked['txid'], [owner_fd]))
        return dict(result, submission=submitted, new_submission=True, action='reconcile-exact-native-exit')


def main():
    os.umask(0o077)
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('owner', type=Path); p.add_argument('version'); p.add_argument('consents', type=Path)
    p.add_argument('--watch-wallet', type=Path, required=True); p.add_argument('--batches', type=int, default=4)
    p.add_argument('--eth-rpc', default=probe_sepolia.ENDPOINT)
    p.add_argument('--broadcast-testnet', action='store_true', help='explicit network side effect; user authorization required')
    a = p.parse_args()
    print(json.dumps(execute(a.owner, a.version, a.consents, a.watch_wallet, a.batches, a.eth_rpc, a.broadcast_testnet), indent=2))
    return 2


if __name__ == '__main__':
    try: raise SystemExit(main())
    except (RuntimeError, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        raise SystemExit('Native execution stopped; retain all private attempts and reconcile the exact exit before retrying.') from None
