#!/usr/bin/env python3
"""Read-only checks of an exact signed public agreement; this command never sends.

Successful observations are private diagnostic snapshots, never reusable release
tokens. This does not read owner keys or adaptor witnesses. No deploy/send RPC
exists here. It rejects synthetic provenance before any network disclosure.
"""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from otc_offer import read
import public_authority
import public_evm_observation as eth
import probe_sepolia
import public_source
from regtest_wallet import ROOT, save
import timestamp_policy


def agreement_from_files(bundle, proposal, consents):
    files, verified = public_authority.verified_files(bundle, proposal, consents)
    agreement = files['proposal']['agreement']
    if verified['synthetic_inputs'] is not False or agreement['synthetic_inputs'] is not False:
        raise RuntimeError('synthetic inputs cannot enter public execution observations')
    timestamp_policy.require_agreement_binding(agreement['execution_plan'], agreement)
    return agreement, verified, files


def native_funding(agreement, observation, now):
    """Validate fresh output from our local raw-tx/compact-effect observer.

    A caller-created JSON report is not a proof. The CLI obtains the raw bytes
    and checks them locally in this invocation, using its pinned TLS provider.
    """
    p = agreement['execution_plan']['policy']
    tx, mined, tip = observation['transaction'], observation['mined_block'], observation['observed_tip']
    if (observation['format'] != 'latch-testnet-transaction-observation-v1'
            or observation['genesis'] != agreement['native_genesis']
            or observation['branch'] != agreement['native_branch']
            or tx is None
            or tx['txid'] != agreement['native']['funding_txid']
            or tx['version'] != 6 or tx['branch'] != agreement['native_branch']
            or observation['status'] != 'mined' or mined is None):
        raise RuntimeError('exact native funding transaction is not confirmed on this network')
    confirmations = tip['height'] - mined['height'] + 1
    if (type(confirmations) is not int or confirmations < agreement['observation_policy']['native_min_confirmations']
            or observation['confirmations_by_provider'] != confirmations):
        raise RuntimeError('native funding lacks the agreed confirmations')
    stamp = datetime.fromisoformat(observation['observed_at'].replace('Z', '+00:00'))
    if (stamp.utcoffset() is None or not -p['clock_error_seconds'] <= now-stamp.timestamp() <= p['observation_max_age_seconds']
            or not -(p['native_early_header_seconds']+p['clock_error_seconds']) <= now-tip['timestamp'] <= p['native_tip_max_age_seconds']
            or observation['announced_upgrade']['height'] != 0):
        raise RuntimeError('native funding observation outside clock/upgrade bounds')
    return {'txid': tx['txid'], 'mined_block': mined, 'observed_tip': tip,
        'confirmations_by_provider': confirmations, 'provider_trusted': True}


def native_auxiliary(agreement, expected, observation, now):
    """Require the exact signed R input, never any same-valued replacement coin."""
    p = agreement['execution_plan']['policy']
    tip = observation['observed_tip']
    stamp = datetime.fromisoformat(observation['observed_at'].replace('Z', '+00:00'))
    if (observation['format'] != 'latch-testnet-auxiliary-observation-v1'
            or observation['genesis'] != agreement['native_genesis']
            or expected['genesis'] != agreement['native_genesis']
            or observation['auxiliary_address'] != expected['aux_address']
            or observation['auxiliary_script'] != expected['aux_script']
            or stamp.utcoffset() is None
            or not -p['clock_error_seconds'] <= now-stamp.timestamp() <= p['observation_max_age_seconds']
            or not -(p['native_early_header_seconds']+p['clock_error_seconds']) <= now-tip['timestamp'] <= p['native_tip_max_age_seconds']):
        raise RuntimeError('refund auxiliary observation domain/clock changed')
    coins = [c for c in observation['utxos'] if c['txid'] == expected['txid'] and c['index'] == expected['index']]
    if len(coins) != 1:
        raise RuntimeError('exact signed refund auxiliary is unavailable')
    coin = coins[0]
    confirmations = tip['height']-coin['height']+1
    if (coin['script'] != expected['aux_script'] or coin['value_zatoshi'] != expected['value_zatoshi']
            or expected['value_zatoshi'] != 20_000
            or confirmations < agreement['observation_policy']['native_min_confirmations']
            or coin['confirmations_by_provider'] != confirmations):
        raise RuntimeError('refund auxiliary effects/confirmations differ from agreement')
    return {'txid': coin['txid'], 'index': coin['index'], 'value_zatoshi': coin['value_zatoshi'],
        'confirmations_by_provider': confirmations, 'observed_tip': tip, 'provider_trusted': True,
        'observed_at': observation['observed_at'], 'mempool_conflicts_excluded': False}


def deferred_auxiliary(expected, now):
    """Before the refund path there is nothing to observe: Alice's auxiliary
    transaction A creates the coin only then. Skipping the query also keeps the
    transparent address away from the provider until a refund."""
    if expected.get('deferred') is not True or expected['value_zatoshi'] != 20_000:
        raise RuntimeError('deferred refund auxiliary target mismatch')
    return {'txid': expected['txid'], 'index': expected['index'], 'value_zatoshi': 20_000,
        'deferred': True, 'observed': False, 'provider_trusted': False,
        'observed_at': datetime.fromtimestamp(now, timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}


def preflight(bundle, proposal, consents, phase, directory, endpoint, source_wallet=None, owner=None):
    agreement, verified, files = agreement_from_files(bundle, proposal, consents)
    if owner is None:
        raise RuntimeError('public preflight requires the calling owner local state')
    # Fixed lock ordering: owner operator.lock, then source sync.lock if funding.
    with public_authority.owner_locked(owner):
        caller = public_authority.bind_owner(owner, files, verified, phase)
        if phase == 'funding':
            if source_wallet is None:
                raise RuntimeError('funding preflight requires the reserved source wallet')
            with public_source.locked(source_wallet):
                result = observe_verified(bundle, agreement, verified, phase, directory, endpoint, source_wallet)
        else:
            if source_wallet is not None:
                raise RuntimeError('source wallet is used only before native funding')
            result = observe_verified(bundle, agreement, verified, phase, directory, endpoint, None)
        if public_authority.bind_owner(owner, files, verified, phase) != caller:
            raise RuntimeError('caller acceptance changed during observations')
        result['caller'] = caller
        save(directory/'report.json', result)
        return result


def observe_verified(bundle, agreement, verified, phase, directory, endpoint, source_wallet, source_released=False,
        rebroadcast=False):
    plan = agreement['execution_plan']
    window = 'first_reveal' if phase == 'first_reveal' else 'funding'
    if rebroadcast:
        if phase != 'first_reveal': raise RuntimeError('only a claim may be rebroadcast past its window')
        window = 'claim_rebroadcast'
    timestamp_policy.require_window(plan, window, int(time.time()))
    directory.mkdir(mode=0o700)
    save(directory/'verified-consents.json', verified)
    source_context = (public_source.prepare(source_wallet, bundle, agreement, verified, directory/'source', released=source_released)
        if source_wallet is not None else None)
    # No fallback endpoint and no cached success. A failed identity/finality/code
    # observation terminates this invocation before native observer queries.
    observation = eth.observe(agreement, phase, probe_sepolia.ReadOnlyRpc(endpoint), endpoint)
    save(directory/'eth.json', observation)
    deferred = verified['native_auxiliary'].get('deferred') is True
    if not deferred:
        save(directory/'auxiliary-target.json', verified['native_auxiliary'])
        auxiliary_dir = directory/'native-auxiliary'
        subprocess.run(['node', str(ROOT/'scripts/observe_testnet_auxiliary.mjs'), '--receiver',
            str(directory/'auxiliary-target.json'), str(auxiliary_dir)],
            capture_output=True, text=True, timeout=150, check=True)
        auxiliary_observation = read(auxiliary_dir/'observation.json')
        native_auxiliary(agreement, verified['native_auxiliary'], auxiliary_observation, int(time.time()))
    source_check = None
    if phase == 'funding':
        zcash, source_check = public_source.observe(source_context, agreement)
        funding = None
    else:
        folder = directory/'native-funding'
        subprocess.run(['node', str(ROOT/'scripts/observe_testnet_transaction.mjs'),
            agreement['native']['funding_txid'], str(folder)],
            capture_output=True, text=True, timeout=150, check=True)
        raw = read(folder/'observation.json')
        funding = native_funding(agreement, raw, int(time.time()))
        zcash = {'genesis': raw['genesis'], 'branch_id': raw['branch'],
            'observed_at': raw['observed_at'], 'provider_header_timestamp': raw['observed_tip']['timestamp'],
            'announced_upgrade': raw['announced_upgrade']}
    save(directory/'native-clock.json', zcash)
    now = int(time.time())
    timestamp_policy.require_window(plan, window, now)
    blockers = timestamp_policy.clock_blockers(plan, zcash, observation['clock'], now)
    if blockers:
        raise RuntimeError('cross-chain clock observations stale/incomplete: ' + ','.join(blockers))
    auxiliary = (deferred_auxiliary(verified['native_auxiliary'], now) if deferred
        else native_auxiliary(agreement, verified['native_auxiliary'], auxiliary_observation, now))
    result = {'format': 'latch-public-preflight-v1', 'agreement_digest': verified['agreement_digest'],
        'phase': phase, 'both_conditional_consents_verified': True,
        'eth_exact_code_state_reserves_checked': True, 'native_funding': funding,
        'native_auxiliary': auxiliary, 'native_source': source_check,
        'remaining_gates': ['fresh-explicit-sender-reconciliation',
            'funded-public-positive-execution-and-recovery-validation',
            'public-deployment-and-transfer-authorization'],
        'execution_enabled': False, 'funding_authorized': False, 'reveal_authorized': False,
        'broadcast': False, 'deployment': False, 'provider_trusted': True}
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('bundle', 'proposal', 'consents'):
        p.add_argument(name, type=Path)
    p.add_argument('phase', choices=('funding', 'eth_lock', 'first_reveal'))
    p.add_argument('directory', type=Path, help='new private observation directory')
    p.add_argument('--eth-rpc', default=probe_sepolia.ENDPOINT, help='explicit trusted HTTPS Sepolia provider; never auto-fallback')
    p.add_argument('--source-wallet', type=Path, help='reserved source wallet; required only for funding preflight')
    p.add_argument('--owner', type=Path, required=True, help='caller local owner state: Alice for funding/reveal, Bob for ETH lock')
    a = p.parse_args()
    os.umask(0o077)
    result = preflight(a.bundle, a.proposal, a.consents, a.phase, a.directory.resolve(), a.eth_rpc,
        a.source_wallet.absolute() if a.source_wallet is not None else None, a.owner.absolute())
    print(json.dumps(result, indent=2))
    return 2  # Partial preparation, including when every implemented check passes.


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, RuntimeError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        sys.exit('Public preflight refused; private observations retained if created. No funds released or secret disclosed.')
