#!/usr/bin/env python3
"""Read-only checks of an exact signed public agreement; all senders stay disabled.

Successful observations are private diagnostic snapshots, never reusable release
tokens. This does not read owner keys or adaptor witnesses. No deploy/send RPC
exists here. It rejects synthetic provenance before any network disclosure.
"""
import argparse
from datetime import datetime
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from otc_offer import read
from public_agreement import validate_policy
import public_evm_observation as eth
import probe_sepolia
from regtest_wallet import ROOT, native, save
import timestamp_policy


def agreement_from_files(bundle, proposal, consents):
    validate_policy()
    agreement = read(proposal)['agreement']
    verified = native('testnet-check-consents', bundle, proposal, consents)
    if (verified['agreement_digest'] != eth.digest(agreement)
            or verified['bundle_digest'] != agreement['bundle_digest']
            or verified['both_owner_signatures_verified'] is not True):
        raise RuntimeError('conditional agreement changed during validation')
    if verified['synthetic_inputs'] is not False or agreement['synthetic_inputs'] is not False:
        raise RuntimeError('synthetic inputs cannot enter public execution observations')
    timestamp_policy.require_agreement_binding(agreement['execution_plan'], agreement)
    return agreement, verified


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
        'mempool_conflicts_excluded': False}


def preflight(bundle, proposal, consents, phase, directory, endpoint):
    agreement, verified = agreement_from_files(bundle, proposal, consents)
    plan = agreement['execution_plan']
    window = 'first_reveal' if phase == 'first_reveal' else 'funding'
    timestamp_policy.require_window(plan, window, int(time.time()))
    directory.mkdir(mode=0o700)
    save(directory/'verified-consents.json', verified)
    # No fallback endpoint and no cached success. A failed identity/finality/code
    # observation terminates this invocation before native observer queries.
    observation = eth.observe(agreement, phase, probe_sepolia.ReadOnlyRpc(endpoint), endpoint)
    save(directory/'eth.json', observation)
    save(directory/'auxiliary-target.json', verified['native_auxiliary'])
    auxiliary_dir = directory/'native-auxiliary'
    subprocess.run(['node', str(ROOT/'scripts/observe_testnet_auxiliary.mjs'), '--receiver',
        str(directory/'auxiliary-target.json'), str(auxiliary_dir)],
        capture_output=True, text=True, timeout=150, check=True)
    auxiliary_observation = read(auxiliary_dir/'observation.json')
    native_auxiliary(agreement, verified['native_auxiliary'], auxiliary_observation, int(time.time()))
    if phase == 'funding':
        result = subprocess.run(['node', str(ROOT/'scripts/probe_testnet.mjs')],
            capture_output=True, text=True, timeout=60, check=True)
        zcash = json.loads(result.stdout)
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
    auxiliary = native_auxiliary(agreement, verified['native_auxiliary'], auxiliary_observation, now)
    result = {'format': 'latch-public-preflight-v1', 'agreement_digest': verified['agreement_digest'],
        'phase': phase, 'both_conditional_consents_verified': True,
        'eth_exact_code_state_reserves_checked': True, 'native_funding': funding,
        'native_auxiliary': auxiliary,
        'remaining_gates': ['live-native-source-reservation-recheck',
            'public-sender-intent-and-reconciliation', 'mined-witness-public-recovery',
            'public-deployment-and-transfer-authorization'],
        'execution_enabled': False, 'funding_authorized': False, 'reveal_authorized': False,
        'broadcast': False, 'deployment': False, 'provider_trusted': True}
    save(directory/'report.json', result)
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('bundle', 'proposal', 'consents'):
        p.add_argument(name, type=Path)
    p.add_argument('phase', choices=('funding', 'eth_lock', 'first_reveal'))
    p.add_argument('directory', type=Path, help='new private observation directory')
    p.add_argument('--eth-rpc', default=probe_sepolia.ENDPOINT, help='explicit trusted HTTPS Sepolia provider; never auto-fallback')
    a = p.parse_args()
    os.umask(0o077)
    result = preflight(a.bundle, a.proposal, a.consents, a.phase, a.directory.resolve(), a.eth_rpc)
    print(json.dumps(result, indent=2))
    return 2  # Partial preparation, including when every implemented check passes.


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, RuntimeError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        sys.exit('Public preflight refused; private observations retained if created. No funds released or secret disclosed.')
