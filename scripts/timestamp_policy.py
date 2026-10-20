"""Executable candidate public-clock policy; no signer or network operations.

These numeric latency/clock/reorg bounds are assumptions to be accepted by both
operators, not properties proved by this module or by RPC labels. This is NOT
connected to the current height-only sender. Never use first-reveal checks to
erase exposure history or to authorize a no-reveal refund.
"""
import copy
import os
from datetime import datetime
import hashlib
import json
import fee_policy

GENESIS = '05a60a92d99d85997cce3b87616c089f6124d7342af37106edc76126334a2c38'
ETH_GENESIS = '0x25a5cc106eea7138acab33231d7160d69cb777ee0c2c553fcddf5138993e6dd9'
POLICY = {'version': 1, 'profile': 'candidate-testnet-timestamp-v1',
    'native_genesis': GENESIS, 'native_branch': '77190ad9', 'eth_chain_id': 11155111,
    'clock_error_seconds': 60, 'native_early_header_seconds': 7200,
    'secret_observation_seconds': 300, 'native_proof_seconds': 600,
    'native_inclusion_seconds': 1800, 'native_confirmation_seconds': 3600,
    'native_reorg_recovery_seconds': 3600,
    'eth_inclusion_seconds': 600, 'eth_settlement_seconds': 1800, 'eth_retry_seconds': 600,
    'observation_max_age_seconds': 120, 'native_tip_max_age_seconds': 600,
    'eth_tip_max_age_seconds': 120, 'eth_expiry_after_creation_seconds': 21600,
    'funding_cutoff_before_expiry_seconds': 7200, 'reveal_cutoff_before_expiry_seconds': 3600,
    'native_refund_after_eth_expiry_seconds': 86400}
# A shorter reviewed profile for public-testnet demonstrations: the same latency,
# clock and reorg bounds, an ETH deadline 3 hours after creation and a native
# refund 6 hours after that (slack about 73 minutes over the strict gap check).
# Selected only by LATCH_TIMING_PROFILE=short; the default stays POLICY.
SHORT = dict(POLICY, profile='candidate-testnet-timestamp-short-v1',
    eth_expiry_after_creation_seconds=10800, native_refund_after_eth_expiry_seconds=21600)
PROFILES = {POLICY['profile']: POLICY, SHORT['profile']: SHORT}


def selected():
    value = os.environ.get('LATCH_TIMING_PROFILE', 'default')
    if value not in ('default', 'short'):
        raise RuntimeError('LATCH_TIMING_PROFILE must be default or short')
    return SHORT if value == 'short' else POLICY


def uint(value):
    if type(value) is not int or not 0 <= value <= 0xffffffff:
        raise RuntimeError('explicit uint32 time/height required')
    return value


def digest(plan):
    return hashlib.sha256(b'Latch candidate execution plan v1\0' +
        json.dumps(plan, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def native_work(p):
    return sum(p[k] for k in ('secret_observation_seconds', 'native_proof_seconds',
        'native_inclusion_seconds', 'native_confirmation_seconds', 'native_reorg_recovery_seconds'))


def build(now, policy=None):
    now = uint(now); policy = selected() if policy is None else policy
    expiry = uint(now + policy['eth_expiry_after_creation_seconds'])
    plan = {'policy': copy.deepcopy(policy), 'created_at': now, 'eth_expiry': expiry,
        'fund_before': expiry-policy['funding_cutoff_before_expiry_seconds'],
        'first_reveal_before': expiry-policy['reveal_cutoff_before_expiry_seconds'],
        'native_refund_lock': {'kind': 'timestamp', 'value': uint(expiry+policy['native_refund_after_eth_expiry_seconds'])},
        'fee_policy': fee_policy.default()}
    validate(plan)
    return plan


def validate(plan):
    if set(plan) != {'policy','created_at','eth_expiry','fund_before','first_reveal_before','native_refund_lock','fee_policy'}:
        raise RuntimeError('unknown/missing execution plan fields')
    p = plan['policy']
    # A changed profile needs a new reviewed version, not caller-selected bounds.
    expected = PROFILES.get(p.get('profile')) if isinstance(p, dict) else None
    if expected is None or p != expected or any(type(p[k]) is not int for k,v in expected.items() if type(v) is int):
        raise RuntimeError('unsupported candidate timestamp policy')
    now, expiry = uint(plan['created_at']), uint(plan['eth_expiry'])
    lock = plan['native_refund_lock']
    if (set(lock) != {'kind','value'} or lock['kind'] != 'timestamp' or uint(lock['value']) < 500_000_000
            or expiry != now+p['eth_expiry_after_creation_seconds']
            or uint(plan['fund_before']) != expiry-p['funding_cutoff_before_expiry_seconds']
            or uint(plan['first_reveal_before']) != expiry-p['reveal_cutoff_before_expiry_seconds']
            or lock['value'] != expiry+p['native_refund_after_eth_expiry_seconds']):
        raise RuntimeError('timestamp units or derived deadlines changed')
    fee_policy.policy({'fee_policy':plan['fee_policy']})
    earliest_native = lock['value']-p['native_early_header_seconds']-p['clock_error_seconds']
    latest_required = expiry+p['clock_error_seconds']+native_work(p)
    required_reveal = 2*p['clock_error_seconds']+p['eth_inclusion_seconds']+p['eth_settlement_seconds']+p['eth_retry_seconds']
    if earliest_native <= latest_required or p['reveal_cutoff_before_expiry_seconds'] <= required_reveal:
        raise RuntimeError('unsafe strict cross-chain time gap')
    return {'earliest_native_refund_under_bounds':earliest_native,
        'native_completion_bound_after_eth_expiry':latest_required,
        'native_gap_slack_seconds':earliest_native-latest_required,
        'first_reveal_slack_seconds':p['reveal_cutoff_before_expiry_seconds']-required_reveal}


def require_window(plan, phase, now):
    validate(plan); now=uint(now)
    field={'funding':'fund_before','first_reveal':'first_reveal_before'}.get(phase)
    if field is None or now < plan['created_at'] or now >= plan[field]:
        raise RuntimeError('candidate phase outside strict clock window')


def require_agreement_binding(plan, agreement):
    validate(plan)
    if (agreement.get('execution_plan_digest') != digest(plan)
            or agreement.get('eth_chain_id') != POLICY['eth_chain_id']
            or agreement.get('native_genesis') != POLICY['native_genesis']
            or agreement.get('native_branch') != POLICY['native_branch']
            or uint(agreement.get('eth_expiry')) != plan['eth_expiry']
            or agreement.get('fee_policy') != plan['fee_policy']
            or agreement['native'].get('refund_lock') != plan['native_refund_lock']
            or 'refund_height' in agreement['native']):
        raise RuntimeError('agreement does not bind the exact candidate execution plan')
    uint(agreement['native']['refund_lock']['value'])


def clock_blockers(plan, zcash, eth, now):
    validate(plan); now=uint(now); p=plan['policy']; reasons=[]
    if (zcash['genesis'] != GENESIS or zcash['branch_id'] != p['native_branch']
            or eth['chain_id'] != p['eth_chain_id'] or eth['expected_genesis'] != ETH_GENESIS):
        raise RuntimeError('candidate clock observation network mismatch')
    for name, observation in [('native',zcash),('eth',eth)]:
        stamp=datetime.fromisoformat(observation['observed_at'].replace('Z','+00:00'))
        if stamp.utcoffset() is None:
            raise RuntimeError('clock observation must have a timezone')
        age=now-stamp.timestamp()
        if not -p['clock_error_seconds'] <= age <= p['observation_max_age_seconds']:
            reasons.append(name+'-observation-stale-or-future')
    zage=now-uint(zcash['provider_header_timestamp'])
    eage=now-uint(eth['latest']['timestamp'])
    if not -(p['native_early_header_seconds']+p['clock_error_seconds']) <= zage <= p['native_tip_max_age_seconds']:
        reasons.append('native-tip-outside-clock-bounds')
    if not -p['clock_error_seconds'] <= eage <= p['eth_tip_max_age_seconds']:
        reasons.append('eth-tip-outside-clock-bounds')
    if zcash.get('announced_upgrade') is None or uint(zcash['announced_upgrade']['height']) != 0:
        reasons.append('native-upgrade-cutoff-unresolved')
    if eth.get('rpc_genesis_verified') is not True or eth.get('status') != 'observed':
        reasons.append('eth-provider-identity-incomplete')
    return reasons
