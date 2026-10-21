#!/usr/bin/env python3
"""Owner-locked public ETH check/send; explicit testnet broadcast switch required.

No key or opening is read: prepare the exact private action first. Every send
reconciles its hash and repeats live policy under the same owner lock. No public
execution of this entry point has been demonstrated; RPC providers are trusted.
"""
import argparse
from datetime import datetime
import json
import os
from pathlib import Path
import re
import subprocess
import time
import urllib.request
import uuid
import fee_policy
import public_authority as authority
import public_eth_delivery as delivery
import public_eth_outgoing as out
import public_eth_reconcile as recovery
import public_evm_observation as eth
import public_preflight as preflight
import probe_sepolia as sepolia
import timestamp_policy
from source_inputs import publish
from testnet_wallet import read


def send_raw(endpoint, raw):
    # Separate from the immutable read-only RPC allowlist. The complete caller
    # has already identified this exact endpoint and holds operator.lock.
    sepolia.ReadOnlyRpc(endpoint)
    if not re.fullmatch(r'0x(?:[0-9a-f]{2}){1,65536}', raw): raise RuntimeError('bounded raw ETH required')
    req = urllib.request.Request(endpoint, json.dumps({'jsonrpc': '2.0', 'id': 1,
        'method': 'eth_sendRawTransaction', 'params': [raw]}).encode(),
        {'Content-Type': 'application/json', 'User-Agent': 'Latch-explicit-testnet/1'})
    with urllib.request.build_opener(sepolia.NoRedirect).open(req, timeout=15) as response:
        data = response.read(100001)
        if len(data) > 100000: raise RuntimeError('bounded submission response required')
        value = json.loads(data)
    if (not isinstance(value, dict) or value.get('jsonrpc') != '2.0' or type(value.get('id')) is not int
            or value['id'] != 1 or 'error' in value or not re.fullmatch('0x[0-9a-f]{64}', value.get('result', ''))):
        raise RuntimeError('uncertain ETH submission; reconcile exact hash')
    return value['result']


def require_fee_nonce(value, reserve, agreement):
    tx = value['transaction_base']; policy = fee_policy.policy(agreement)
    if (reserve['address'] != tx['from'] or reserve['action'] != value['kind']
            or reserve['nonce'] != int(tx['nonce'], 16)
            or int(tx['gasPrice'], 16) != policy['max_gas_price_wei']
            or reserve['gas_price_wei'] > int(tx['gasPrice'], 16)
            or min(reserve['confirmed_balance_wei'], reserve['pending_balance_wei']) < reserve['required_balance_wei']):
        raise RuntimeError('retained ETH nonce/ceiling fee/reserve not executable; preserve existing bytes')


def observed_state(report):
    state = report['state']
    if state not in ('unobserved-by-provider', 'pending-by-provider', 'confirming-by-provider',
            'confirmed-by-provider', 'reverted-by-provider'):
        raise RuntimeError('unknown ETH receipt state')
    return state


def execute(owner, consents, kind, endpoint=sepolia.ENDPOINT, broadcast=False):
    with authority.owner_locked(owner):
        files, checked, caller, _ = out.context(owner, consents, kind)
        if checked['synthetic_inputs'] is not False:
            raise RuntimeError('synthetic inputs cannot enter public ETH execution')
        role = caller['role']; agreement = files['proposal']['agreement']
        directory, binding = out.workspace(owner, files, checked, role)
        action, value = out.decision(directory, binding, agreement, kind)
        _, verified, _ = delivery.retained(action, value, files, checked)
        receipt = delivery.observe_locked(owner, consents, kind, endpoint)
        state = observed_state(receipt)
        if state != 'unobserved-by-provider':
            return {'action': 'retain-and-monitor' if state != 'confirmed-by-provider' else 'confirmed',
                'receipt': receipt, 'new_submission': False, 'send_authorized': False,
                'next': 'preserve-exposure-and-recover-native' if kind == 'claim' else 'reconcile-next-action'}
        result = {}
        # A recorded attempt may have exposed t: the same bytes may be resent
        # within the retry time the policy reserves after the reveal cutoff.
        attempts = action/'send-attempts'
        rebroadcast = kind == 'claim' and attempts.is_dir() and any(
            (p/'intent.json').is_file() for p in attempts.iterdir() if p.is_dir())
        def fresh_guard(saved, actual):
            if saved != value or actual != verified: raise RuntimeError('retained ETH action changed')
            observed = action/('send-check-'+uuid.uuid4().hex)
            if kind in out.PHASE:
                report = preflight.observe_verified(directory/'bundle.json', agreement, checked,
                    out.PHASE[kind], observed, endpoint, None, rebroadcast=rebroadcast)
                publish(observed/'report.json', report)
                ethereum = read(observed/'eth.json')
                reserve = ethereum['reserves'][role]
            else:
                report = recovery.observe_locked(owner, consents, endpoint, action=kind)
                out.require_recovery_action(kind, report)
                ethereum = report; reserve = report['action_checks']['reserve']
            require_fee_nonce(saved, reserve, agreement)
            if authority.bind_owner(owner, files, checked, out.action_phase(kind, role)) != caller or read(consents) != files['consents']:
                raise RuntimeError('caller acceptance changed before ETH send')
            now = int(time.time()); p = agreement['execution_plan']['policy']
            stamp = datetime.fromisoformat(ethereum['observed_at'].replace('Z', '+00:00')).timestamp()
            if not -p['clock_error_seconds'] <= now-stamp <= p['observation_max_age_seconds']:
                raise RuntimeError('ETH send observation became stale')
            if kind in out.PHASE:
                timestamp_policy.require_window(agreement['execution_plan'],
                    ('claim_rebroadcast' if rebroadcast else 'first_reveal') if kind == 'claim' else 'funding', now)
            result.update(txid=verified['txid'], kind=kind, checked_in_this_invocation=True,
                observation_digest=eth.digest(report), native_recovery_required_if_claim_exposed=kind == 'claim',
                provider_trusted=True, broadcast=False, send_authorized=False)
        if not broadcast:
            fresh_guard(value, verified)
            return dict(result, action='ready-for-explicit-testnet-send', new_submission=False)
        submitted = delivery.send_once(action, value, files, checked,
            lambda raw: send_raw(endpoint, raw), fresh_guard)
        return dict(result, submission=submitted, new_submission=True,
            action='reconcile-exact-hash', broadcast_may_have_occurred=True)


def main():
    os.umask(0o077)
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('owner', type=Path); p.add_argument('consents', type=Path)
    p.add_argument('action', choices=('lock', 'claim', 'refund', 'withdraw'))
    p.add_argument('--eth-rpc', default=sepolia.ENDPOINT)
    p.add_argument('--broadcast-testnet', action='store_true', help='explicit network side effect; user authorization required')
    a = p.parse_args()
    print(json.dumps(execute(a.owner, a.consents, a.action, a.eth_rpc, a.broadcast_testnet), indent=2))
    return 2 # Submission is not completed cross-chain settlement.


if __name__ == '__main__':
    try: raise SystemExit(main())
    except (RuntimeError, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        raise SystemExit('ETH execution stopped; retain all private attempts and reconcile exact hashes before retrying.') from None
