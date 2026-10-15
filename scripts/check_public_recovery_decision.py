#!/usr/bin/env python3
"""Changed cross-chain decision policy with actual native authorization checks.

Chain states/timestamps are explicit transcripts. No RPC, new proof, signing key
or opening; copied accepted packets and already prepared native exits only.
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
from check_public_outgoing import copy_private
from check_public_native_reconcile import transcript
import public_authority as authority
import public_eth_outgoing as eth_outgoing
import public_outgoing as outgoing
import public_native_reconcile as native_reconcile
import public_recovery_decision as decision
from public_evm_observation import digest
from regtest_wallet import save
import timestamp_policy


def check(root, fixture):
    root.mkdir(mode=0o700)
    reports = {}
    for role in ('alice', 'bob'):
        owner = root/role; owner.mkdir(mode=0o700)
        for name in OWNER_FILES: copy_private(fixture/role/name, owner/name)
        shutil.copytree(fixture/role/outgoing.JOURNAL, owner/outgoing.JOURNAL)
        with authority.owner_locked(owner): journal = outgoing.verified_journal_locked(owner)
        binding = journal['binding']; expected = journal['versions'][0]['checked']
        assert binding['synthetic_inputs'] and expected['proof_and_signatures_verified']
        consents = journal['directory']/'consents.json'
        refuses(lambda: decision.reconcile(owner, expected['bytes_sha256'], consents), 'synthetic inputs')
        assert not (owner/'public-recovery-decisions').exists()
        mode = binding['mode']; agreement = journal['files']['proposal']['agreement']
        raw = journal['directory']/'versions'/(expected['bytes_sha256']+'.hex')
        observed_dir = root/(role+'-native-observed'); observed_dir.mkdir(mode=0o700)
        observed, actual, state = native_reconcile.run_observation(journal, expected, observed_dir,
            transcript(journal, expected, raw))
        assert state == 'confirmed-by-provider' and actual['proof_and_signatures_verified']
        clock = {'genesis': observed['genesis'], 'branch_id': observed['branch'], 'observed_at': observed['observed_at'],
            'provider_header_timestamp': observed['observed_tip']['timestamp'], 'announced_upgrade': observed['announced_upgrade']}
        native = {'agreement_digest': digest(agreement), 'mode': mode, 'native_state': state,
            'native_clock': clock, 'native_observed_tip': observed['observed_tip'], 'current_unspent_witness_check': None}
        result = decision.decide(agreement, mode, native, None)
        assert result['action'] == 'native-exit-confirmed-check-counter-asset'
        # A mined R consumed the auxiliary: success must precede an unspent check.
        assert not result['blockers'] and not result['send_authorized']
        native['native_state'] = 'pending-by-provider'
        assert decision.decide(agreement, mode, native, None)['action'] == 'monitor-native-exit'
        native['native_state'] = 'unobserved-by-provider'
        native['current_unspent_witness_check'] = {'exact_funding_note_unspent_in_scan': True, 'canonical_trees_rechecked': True}
        if role == 'bob':
            # Once a real native claim is prepared, ETH absence/refund/RPC
            # failure cannot revoke its authorization or trigger an ETH fallback.
            claim = decision.decide(agreement, mode, native, None, None, None)
            assert claim['action'] == 'prepare-native-claim-send' and not claim['counter_chain_read_required_for_native_claim']
            native['current_unspent_witness_check'] = None
            assert 'exact-anchor-current-unspent-check-required' in decision.decide(agreement, mode, native, None)['blockers']
            reports[role] = {'actual_native_bytes_verified': actual['bytes_sha256'], 'eth_unavailable_does_not_delay_known_claim': True}
            continue
        files, checked = authority.verified_files(journal['directory']/'native-recovery.json',
            journal['directory']/'proposal.json', consents)
        with authority.owner_locked(owner):
            local = eth_outgoing.exposure(owner, files, checked)
            assert not local['local_history_initialized'] and local['local_claim_may_be_exposed']
            eth_outgoing.workspace(owner, files, checked, role)
            local = eth_outgoing.require_no_local_claim(owner, files, checked)
        # Explicit future-time model, not a live observation or altered consent.
        now = agreement['native']['refund_lock']['value']+61
        stamp = datetime.fromtimestamp(now, timezone.utc).isoformat()
        native['native_clock'].update(observed_at=stamp, provider_header_timestamp=now)
        native['native_observed_tip']['timestamp'] = now
        eth = {'agreement_digest': digest(agreement), 'claim_seen_ever': False,
            'clock': {'observed_at': stamp, 'chain_id': 11155111, 'expected_genesis': timestamp_policy.ETH_GENESIS,
                'rpc_genesis_verified': True, 'status': 'observed', 'latest': {'timestamp': now}},
            'escrow': {'states': {k: {'state': 3} for k in ('provider_finalized', 'latest')}}}
        aux = {'observed_tip': copy.deepcopy(native['native_observed_tip'])}
        evaluate = lambda n=native, l=local, e=eth, a=aux, t=now: decision.decide(agreement, 'refund', n, l, e, a, t)
        good = evaluate(); assert good['action'] == 'prepare-native-refund-send' and not good['send_authorized']
        assert 'fresh-eth-recovery-observation-required' in evaluate(e=None)['blockers']
        assert 'exact-refund-auxiliary-check-required' in evaluate(a=None)['blockers']
        exposed = dict(local, local_claim_may_be_exposed=True)
        assert 'missing-or-possibly-exposed-local-claim-history' in evaluate(l=exposed)['blockers']
        for final, latest in ((1, 1), (0, 1), (0, 3), (2, 2)):
            changed = copy.deepcopy(eth)
            changed['escrow']['states']['provider_finalized']['state'] = final
            changed['escrow']['states']['latest']['state'] = latest
            assert evaluate(e=changed)['action'] == 'hold'
        changed = copy.deepcopy(eth); changed['claim_seen_ever'] = True
        assert 'eth-claim-seen-no-original-asset-fallback' in evaluate(e=changed)['blockers']
        changed = copy.deepcopy(eth); changed['clock']['observed_at'] = datetime.fromtimestamp(now-121, timezone.utc).isoformat()
        assert 'eth-observation-stale-or-future' in evaluate(e=changed)['blockers']
        changed = copy.deepcopy(aux); changed['observed_tip']['hash'] = 'ff'*32
        assert 'auxiliary-and-native-tips-differ' in evaluate(a=changed)['blockers']
        early = copy.deepcopy(native); early['native_clock']['provider_header_timestamp'] = agreement['native']['refund_lock']['value']
        assert 'native-refund-timestamp-not-mature' in evaluate(n=early)['blockers']
        # Partial claim directory means possible exposure even without raw bytes.
        (owner/eth_outgoing.JOURNAL/'claim').mkdir(mode=0o700)
        with authority.owner_locked(owner): sticky = eth_outgoing.exposure(owner, files, checked)
        assert evaluate(l=sticky)['action'] == 'hold'
        reports[role] = {'actual_native_bytes_verified': actual['bytes_sha256'],
            'refund_requires_unexposed_history_terminal_eth_mature_clock_and_exact_auxiliary': True,
            'claimed_history_survives_later_refund': True, 'settlement_precedes_spent_auxiliary_refusal': True}
    result = {'scope': 'actual native bytes/consents plus explicitly modeled chain/clock states',
        'roles': reports, 'synthetic_public_entry_refused_before_observation': True,
        'rpc_calls': 0, 'new_proofs': 0, 'public_funded_execution': False, 'send_authorized': False, 'broadcast': False}
    save(root/'report.json', result)
    return result


if __name__ == '__main__':
    os.umask(0o077)
    print(json.dumps(check(*(Path(p).resolve() for p in sys.argv[1:3])), indent=2))
