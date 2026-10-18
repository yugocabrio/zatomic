"""Owner gas reserves checked BEFORE any first claim-witness disclosure.

No method here sends calldata, estimates a secret claim remotely, signs or sends.
Balances/nonces/fees are trusted RPC observations, not reservations.
"""
import copy
import re

# v1: limits measured under the earlier gas schedule. Agreements signed with
# it (or without a fee policy) keep verifying with exactly these limits.
LEGACY = {'profile': 'bounded-legacy-eth-v1', 'max_gas_price_wei': 100 * 10**9,
    'gas_limits': {'lock': 700_000, 'claim': 1_000_000, 'refund': 200_000, 'withdraw': 200_000},
    'withdrawal_attempt_limit': 33}
# v2 (2026-10-18): Sepolia now charges heavily for new state. Simulated on its
# current rules (scripts/measure_sepolia_gas.py): lock 799,447, worst-case
# claim 768,210, refund 143,831, withdraw 31,216. New agreements use v2.
DEFAULT = {'profile': 'bounded-legacy-eth-v2', 'max_gas_price_wei': 100 * 10**9,
    'gas_limits': {'lock': 1_000_000, 'claim': 1_000_000, 'refund': 200_000, 'withdraw': 200_000},
    'withdrawal_attempt_limit': 33}
PROFILES = {p['profile']: p for p in (LEGACY, DEFAULT)}


def default():
    return copy.deepcopy(DEFAULT)


def policy(agreement):
    # Historical agreements retain their signed digests and original limits.
    value = agreement.get('fee_policy', LEGACY)
    known = PROFILES.get(value.get('profile')) if isinstance(value, dict) else None
    if (known is None or set(value) != set(known)
            or type(value['max_gas_price_wei']) is not int
            or not 0 < value['max_gas_price_wei'] <= known['max_gas_price_wei']
            or value['gas_limits'] != known['gas_limits']
            or any(type(n) is not int for n in value['gas_limits'].values())
            or type(value['withdrawal_attempt_limit']) is not int
            or value['withdrawal_attempt_limit'] != known['withdrawal_attempt_limit']):
        raise RuntimeError('unsupported signed gas policy')
    return value


def quantity(value):
    if not isinstance(value, str) or not re.fullmatch(r'0x(?:0|[1-9a-f][0-9a-f]{0,63})', value):
        raise RuntimeError('noncanonical gas/account observation')
    return int(value, 16)


def required_balance(agreement, action):
    selected = policy(agreement)
    remaining = {'lock': ('lock', 'refund', 'withdraw'), 'claim': ('claim', 'withdraw'),
        'refund': ('refund', 'withdraw'), 'withdraw': ('withdraw',)}
    if action not in remaining:
        raise RuntimeError('unsupported gas reserve action')
    amount = agreement['amount_wei']
    if type(amount) is not int or not 0 < amount < 2**256:
        raise RuntimeError('invalid escrow amount')
    gas = sum(selected['gas_limits'][kind] for kind in remaining[action])
    return gas * selected['max_gas_price_wei'] + (amount if action == 'lock' else 0)


def require_action_budget(agreement, address, action, rpc):
    selected = policy(agreement)
    price = quantity(rpc('eth_gasPrice'))
    block = rpc('eth_getBlockByNumber', ['latest', False])
    base = quantity(block['baseFeePerGas'])
    latest = quantity(rpc('eth_getTransactionCount', [address, 'latest']))
    pending = quantity(rpc('eth_getTransactionCount', [address, 'pending']))
    balance = quantity(rpc('eth_getBalance', [address, 'pending']))
    required = required_balance(agreement, action)
    if not 0 < price <= selected['max_gas_price_wei'] or price < base:
        raise RuntimeError('gas price outside accepted cap or below current base fee')
    if latest != pending:
        raise RuntimeError('unrelated pending nonce before new owner action')
    if balance < required:
        raise RuntimeError('owner lacks accepted gas reserve before first exposure/funding')
    return {'gas_price': hex(price), 'nonce': hex(latest),
        'gas': selected['gas_limits'][action], 'required_balance_wei': required,
        'observed_balance_wei': balance}


def require_prefunding_reserves(agreement, rpc):
    return {role: require_action_budget(agreement, agreement[field], action, rpc)
        for role, field, action in [('alice', 'recipient', 'claim'), ('bob', 'maker', 'lock')]}
