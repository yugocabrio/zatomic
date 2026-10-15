#!/usr/bin/env python3
"""Owner-bound read-only ETH recovery status; never first reveal or send authority."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import uuid
import public_authority as authority
import public_evm_observation as eth
import public_opening
import public_eth_outgoing
from public_outgoing import private_directory
from probe_sepolia import ReadOnlyRpc, ENDPOINT
from source_inputs import publish
from testnet_wallet import read


def history(parent, agreement_digest):
    if not parent.exists() and not parent.is_symlink():
        return {'runs': 0, 'claim_seen_before': False, 'incomplete': 0}
    private_directory(parent)
    entries = list(parent.iterdir())
    if len(entries) >= 128: raise RuntimeError('ETH recovery history full; retain for reconciliation')
    prior = {'runs': len(entries), 'claim_seen_before': False, 'incomplete': 0}
    for entry in entries:
        if not re.fullmatch('[0-9a-f]{32}', entry.name): raise RuntimeError('unexpected ETH recovery history entry')
        private_directory(entry)
        intent = entry/'intent.json'
        if not intent.exists() and not intent.is_symlink():
            prior['incomplete'] += 1; continue
        if read(intent)['agreement_digest'] != agreement_digest: raise RuntimeError('ETH history agreement mismatch')
        for label in ('provider_finalized', 'latest'):
            path = entry/(label+'.json')
            if not path.exists() and not path.is_symlink(): continue
            state = read(path)
            if (state['agreement_digest'] != agreement_digest or state['state']['exact_order_matched'] is not True
                    or state['state']['state'] not in (0, 1, 2, 3)):
                raise RuntimeError('ETH saved order state mismatch')
            prior['claim_seen_before'] |= state['state']['state'] == 2
        if not (entry/'report.json').exists(): prior['incomplete'] += 1
    return prior


def observe(owner, consents, endpoint=ENDPOINT):
    with authority.owner_locked(owner):
        return observe_locked(owner, consents, endpoint)


def observe_locked(owner, consents, endpoint=ENDPOINT):
    """Caller holds the owner's operator.lock across both chain readers."""
    files, checked = authority.verified_files(owner/'public-native-recovery.json',
        owner/'public-consent-proposal.json', consents)
    role = read(owner/'identity.json')['role']
    phase = {'alice': 'native_refund', 'bob': 'native_claim'}[role]
    caller = authority.bind_owner(owner, files, checked, phase)
    if checked['synthetic_inputs'] is not False:
        raise RuntimeError('synthetic inputs cannot enter public ETH recovery')
    agreement = files['proposal']['agreement']
    local_exposure = public_eth_outgoing.exposure(owner, files, checked) if role == 'alice' else None
    observed_opening = None
    opening_path = owner/'public-observed-opening'
    if role == 'bob' and (opening_path.exists() or opening_path.is_symlink()):
        observed_opening = public_opening.accepted(public_opening.workspace(owner, files, checked), checked)
    rpc = ReadOnlyRpc(endpoint) # Validate configuration before any directory/query.
    parent = owner/'public-eth-observations'
    prior = history(parent, checked['agreement_digest'])
    private_directory(parent)
    directory = parent/uuid.uuid4().hex; private_directory(directory)
    publish(directory/'intent.json', {'format': 'latch-public-eth-recovery-intent-v1',
        'agreement_digest': checked['agreement_digest'], 'bundle_digest': checked['bundle_digest'],
        'role': role, 'endpoint': endpoint, 'prior': prior, 'local_claim_history': local_exposure, 'broadcast': False})
    def record(label, state):
        publish(directory/(label+'.json'), {'agreement_digest': checked['agreement_digest'], 'state': state})
    result = eth.observe_recovery(agreement, rpc, endpoint, record)
    if authority.bind_owner(owner, files, checked, phase) != caller or read(consents) != files['consents']:
        raise RuntimeError('owner acceptance/consents changed during ETH observation')
    result.update(prior=prior, claim_seen_ever=prior['claim_seen_before'] or result['claim_observed_by_provider'],
        local_claim_history=local_exposure,
        verified_native_opening_available=observed_opening is not None,
        scope='ETH order status plus locally reverified opening if already captured; no mempool completeness, withdrawal or send authorization')
    publish(directory/'report.json', result)
    return dict(result, observation_directory=str(directory))


def main():
    os.umask(0o077)
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('owner', type=Path); p.add_argument('consents', type=Path)
    p.add_argument('--endpoint', default=ENDPOINT)
    a = p.parse_args()
    print(json.dumps(observe(a.owner, a.consents, a.endpoint), indent=2))
    return 2 # Partial recovery observation, never send authorization.


if __name__ == '__main__':
    try: raise SystemExit(main())
    except (RuntimeError, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        raise SystemExit('ETH recovery observation refused; private history retained, no transaction sent.') from None
