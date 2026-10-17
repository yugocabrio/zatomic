#!/usr/bin/env python3
"""Fresh native recovery decision under one owner lock; transport still disabled.

Alice's no-reveal refund requires local non-exposure history, terminal/empty ETH
state, the exact auxiliary and a mature native timestamp. Bob's already signed
claim must not wait for an ETH provider to rediscover a known opening.
"""
import argparse
from datetime import datetime
import json
import os
from pathlib import Path
import subprocess
import time
import uuid
import public_authority as authority
import public_eth_outgoing as eth_outgoing
import public_eth_reconcile as eth_reconcile
import public_native_reconcile as native_reconcile
import public_outgoing as outgoing
import public_preflight as preflight
import probe_sepolia
import timestamp_policy
from regtest_wallet import ROOT
from source_inputs import publish
from testnet_wallet import read


def decide(agreement, mode, native, local, ethereum=None, auxiliary=None, now=None):
    """Pure policy over this invocation's verified readers, not a report loader.

    Tests can model provider states explicitly. No caller-supplied bool becomes
    signature/chain evidence in the live entry below, and no result permits send.
    """
    now = int(time.time()) if now is None else now
    timestamp_policy.require_agreement_binding(agreement['execution_plan'], agreement)
    if mode not in ('claim', 'refund') or native['mode'] != mode:
        raise RuntimeError('recovery decision role/mode mismatch')
    from public_evm_observation import digest
    if native['agreement_digest'] != digest(agreement): raise RuntimeError('recovery agreement changed')
    p = agreement['execution_plan']['policy']; lock = agreement['native']['refund_lock']['value']
    result = {'format': 'latch-public-recovery-decision-v1', 'mode': mode, 'agreement_digest': digest(agreement),
        'action': 'hold', 'blockers': [], 'send_authorized': False, 'broadcast': False,
        'provider_trusted': True, 'external_exposure_excluded': False, 'reservation_released': False,
        'remaining_gates': ['durable-send-attempt-and-transport', 'public-transfer-authorization']}
    blockers = result['blockers']; state = native['native_state']
    clock = native['native_clock']
    stamp = datetime.fromisoformat(clock['observed_at'].replace('Z', '+00:00'))
    if (clock['genesis'] != agreement['native_genesis'] or clock['branch_id'] != agreement['native_branch']
            or stamp.utcoffset() is None
            or not -p['clock_error_seconds'] <= now-stamp.timestamp() <= p['observation_max_age_seconds']
            or not -(p['native_early_header_seconds']+p['clock_error_seconds']) <= now-clock['provider_header_timestamp'] <= p['native_tip_max_age_seconds']
            or clock['announced_upgrade']['height'] != 0):
        blockers.append('native-clock-stale-or-domain-unresolved')
        return result
    if state == 'confirmed-by-provider':
        result['action'] = 'native-exit-confirmed-check-counter-asset'
        return result
    if state in ('pending-by-provider', 'confirming-by-provider'):
        result['action'] = 'monitor-native-exit'
        return result
    if state not in ('unobserved-by-provider', 'orphaned-by-provider'):
        raise RuntimeError('unknown native recovery state')
    witness = native['current_unspent_witness_check']
    if (witness is None or witness['exact_funding_note_unspent_in_scan'] is not True
            or witness['canonical_trees_rechecked'] is not True):
        blockers.append('exact-anchor-current-unspent-check-required')
    if mode == 'claim':
        # The actual full native claim signature/proof was already checked by
        # observe_locked. Neither ETH getter failure nor refund state revokes it.
        result['counter_chain_read_required_for_native_claim'] = False
        earliest_refund = lock-p['native_early_header_seconds']-p['clock_error_seconds']
        required = p['native_inclusion_seconds']+p['native_confirmation_seconds']+p['native_reorg_recovery_seconds']
        result['within_assumed_claim_window'] = now+required < earliest_refund
        result['action'] = 'prepare-native-claim-send' if not blockers else 'restore-native-claim-witness'
        if not result['within_assumed_claim_window']:
            result['action'] = 'urgent-native-claim-outside-timing-assumption'
        return result
    if local is None or not local['local_history_initialized'] or local['local_claim_may_be_exposed']:
        blockers.append('missing-or-possibly-exposed-local-claim-history')
    if ethereum is None:
        blockers.append('fresh-eth-recovery-observation-required')
    else:
        if ethereum['agreement_digest'] != digest(agreement): raise RuntimeError('counter-chain agreement changed')
        blockers.extend(timestamp_policy.clock_blockers(agreement['execution_plan'], clock, ethereum['clock'], now))
        states = ethereum['escrow']['states']
        final, latest = states['provider_finalized']['state'], states['latest']['state']
        if ethereum['claim_seen_ever'] or final == 2 or latest == 2:
            blockers.append('eth-claim-seen-no-original-asset-fallback')
        if final not in (0, 3) or latest != final:
            blockers.append('eth-not-stably-empty-or-refunded')
    if now <= lock+p['clock_error_seconds'] or clock['provider_header_timestamp'] <= lock:
        blockers.append('native-refund-timestamp-not-mature')
    if auxiliary is None:
        blockers.append('exact-refund-auxiliary-check-required')
    elif any(auxiliary['observed_tip'][k] != native['native_observed_tip'][k] for k in ('height', 'hash')):
        blockers.append('auxiliary-and-native-tips-differ')
    if not blockers: result['action'] = 'prepare-native-refund-send'
    return result


def observe_auxiliary(agreement, checked, directory):
    publish(directory/'auxiliary-target.json', checked['native_auxiliary'])
    subprocess.run(['node', str(ROOT/'scripts/observe_testnet_auxiliary.mjs'), '--receiver',
        str(directory/'auxiliary-target.json'), str(directory/'auxiliary')],
        capture_output=True, text=True, timeout=150, check=True)
    observation = read(directory/'auxiliary/observation.json')
    preflight.native_auxiliary(agreement, checked['native_auxiliary'], observation, int(time.time()))
    return observation


def reconcile(owner, fingerprint, consents, wallet=None, batches=4, endpoint=probe_sepolia.ENDPOINT):
    with authority.owner_locked(owner):
        return reconcile_locked(owner, fingerprint, consents, wallet, batches, endpoint)


def reconcile_locked(owner, fingerprint, consents, wallet=None, batches=4, endpoint=probe_sepolia.ENDPOINT):
    """Caller retains operator.lock through any subsequent delivery decision."""
    files, checked, caller, kind = eth_outgoing.context(owner, consents)
    if checked['synthetic_inputs'] is not False:
        raise RuntimeError('synthetic inputs cannot enter public recovery decision')
    mode = {'claim': 'refund', 'lock': 'claim'}[kind]
    agreement = files['proposal']['agreement']
    parent = owner/'public-recovery-decisions'; outgoing.private_directory(parent)
    if len(list(parent.iterdir())) >= 128: raise RuntimeError('recovery decision history full; preserve all state')
    directory = parent/uuid.uuid4().hex; outgoing.private_directory(directory)
    publish(directory/'intent.json', {'agreement_digest': checked['agreement_digest'], 'mode': mode,
        'version': fingerprint, 'broadcast': False})
    native = native_reconcile.observe_locked(owner, fingerprint, wallet, batches)
    local = eth_outgoing.exposure(owner, files, checked) if mode == 'refund' else None
    ethereum = auxiliary = auxiliary_raw = None
    errors = []
    if mode == 'refund' and native['native_state'] in ('unobserved-by-provider', 'orphaned-by-provider'):
        try:
            ethereum = eth_reconcile.observe_locked(owner, consents, endpoint)
        except (RuntimeError, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
            errors.append('eth-reader-failed-private-history-retained')
        try:
            auxiliary_raw = observe_auxiliary(agreement, checked, directory)
        except (RuntimeError, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
            # A deferred coin exists only after Alice sends her auxiliary A
            # (public_auxiliary_execute.py) and it gains the agreed confirmations.
            errors.append('deferred-refund-auxiliary-not-yet-confirmed'
                if checked['native_auxiliary'].get('deferred') else 'auxiliary-reader-failed-private-response-retained')
        # A just-mined refund consumed its own auxiliary. Reconcile again
        # before treating that disappearance as loss of the recovery path.
        native = native_reconcile.observe_locked(owner, fingerprint, wallet, batches)
        if auxiliary_raw is not None:
            try:
                auxiliary = preflight.native_auxiliary(agreement, checked['native_auxiliary'], auxiliary_raw, int(time.time()))
            except (RuntimeError, ValueError, KeyError, TypeError):
                errors.append('auxiliary-stale-or-changed-after-native-recheck')
    decision = decide(agreement, mode, native, local, ethereum, auxiliary)
    if authority.bind_owner(owner, files, checked, eth_outgoing.PHASE[kind]) != caller or read(consents) != files['consents']:
        raise RuntimeError('owner acceptance changed during recovery decision')
    decision.update(native=native, eth_observation=ethereum, local_claim_history=local,
        auxiliary=auxiliary, reader_errors=errors)
    publish(directory/'report.json', decision)
    return dict(decision, observation_directory=str(directory))


def main():
    os.umask(0o077)
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('owner', type=Path); p.add_argument('version'); p.add_argument('consents', type=Path)
    p.add_argument('--watch-wallet', type=Path); p.add_argument('--batches', type=int, default=4)
    p.add_argument('--eth-rpc', default=probe_sepolia.ENDPOINT)
    a = p.parse_args()
    print(json.dumps(reconcile(a.owner, a.version, a.consents, a.watch_wallet, a.batches, a.eth_rpc), indent=2))
    return 2


if __name__ == '__main__':
    try: raise SystemExit(main())
    except (RuntimeError, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        raise SystemExit('Recovery decision refused; preserve all state. No transaction sent.') from None
