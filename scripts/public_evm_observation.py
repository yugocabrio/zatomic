"""Exact agreed escrow and gas observations, with no transaction capability.

Caller must verify both conditional consents before disclosing the order or owner
addresses. Hash-pinned EIP-1898 queries and canonical rechecks still trust RPC;
they are not consensus proofs or durable authorization tokens.
"""
from datetime import datetime, timezone
import hashlib
import json
import re
import time
import fee_policy
from evm_wallet import keccak
import probe_sepolia as sepolia
import timestamp_policy


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def data(value, size):
    if not isinstance(value, str) or not re.fullmatch(r'0x[0-9a-f]{' + str(size * 2) + '}', value):
        raise RuntimeError('noncanonical escrow data')
    return bytes.fromhex(value[2:])


def order_id(agreement):
    # ABI encode four static words locally; no orderId call or witness is needed.
    return '0x' + keccak(agreement['eth_chain_id'].to_bytes(32, 'big')
        + data(agreement['escrow']['contract'], 20).rjust(32, b'\0')
        + data(agreement['maker'], 20).rjust(32, b'\0')
        + data(agreement['escrow']['salt'], 32)).hex()


def expected_order(agreement):
    return [int(agreement['maker'], 16), int(agreement['recipient'], 16),
        agreement['amount_wei'], agreement['eth_expiry'], 1,
        int(agreement['point_x'], 16), int(agreement['point_y'], 16), int(digest(agreement), 16)]


def inspect_escrow(agreement, call, blocks, phase):
    """Lower-level state reader, also exercised against a real isolated EVM.

    It does not establish the RPC network, signatures, input state or wall clock.
    The public entry point must do those checks separately.
    """
    if phase not in ('funding', 'eth_lock', 'first_reveal'):
        raise RuntimeError('unsupported public preflight phase')
    target, identifier = agreement['escrow']['contract'], order_id(agreement)
    states = {}
    for label in ('provider_finalized', 'latest'):
        at = {'blockHash': blocks[label]['hash'], 'requireCanonical': True}
        code = call('eth_getCode', [target, at])
        if not isinstance(code, str) or not re.fullmatch(r'0x(?:[0-9a-f]{2}){1,24576}', code):
            raise RuntimeError('escrow code absent or malformed at pinned block')
        code_hash = '0x' + keccak(bytes.fromhex(code[2:])).hex()
        if code_hash != agreement['escrow']['runtime_code_hash']:
            raise RuntimeError('escrow code differs from signed runtime hash')
        encoded = data(call('eth_call', [{'to': target, 'data': '0x9c3f1e90' + identifier[2:]}, at]), 256)
        words = [int.from_bytes(encoded[i:i+32], 'big') for i in range(0, 256, 32)]
        expected = expected_order(agreement) if phase == 'first_reveal' else [0]*8
        if words != expected:
            raise RuntimeError('escrow order/state differs from signed phase conditions')
        states[label] = {'block': blocks[label], 'runtime_code_hash': code_hash,
            'state': words[4], 'exact_order_matched': True}
    return {'order_id': identifier, 'states': states}


def balances(agreement, call, latest, phase):
    """Pin confirmed balances/nonces to the same block as code and order state.

    Also check pending state. This detects observed contention, not simultaneous
    use of the key elsewhere or private pending transactions unknown to this RPC.
    """
    p = fee_policy.policy(agreement)
    price = sepolia.quantity(call('eth_gasPrice', []))
    if not 0 < price <= p['max_gas_price_wei'] or price < latest['base_fee_wei']:
        raise RuntimeError('gas price outside signed cap or below pinned base fee')
    at = {'blockHash': latest['hash'], 'requireCanonical': True}
    roles = [('alice', 'recipient', 'claim')]
    if phase != 'first_reveal':
        roles.append(('bob', 'maker', 'lock'))
    result = {}
    for role, field, action in roles:
        address = agreement[field]
        confirmed_nonce = sepolia.quantity(call('eth_getTransactionCount', [address, at]))
        pending_nonce = sepolia.quantity(call('eth_getTransactionCount', [address, 'pending']))
        confirmed_balance = sepolia.quantity(call('eth_getBalance', [address, at]))
        pending_balance = sepolia.quantity(call('eth_getBalance', [address, 'pending']))
        required = fee_policy.required_balance(agreement, action)
        if confirmed_nonce != pending_nonce:
            raise RuntimeError('owner nonce changed or pending before first action')
        if min(confirmed_balance, pending_balance) < required:
            raise RuntimeError('owner lacks signed reserve in confirmed or pending state')
        result[role] = {'address': address, 'action': action, 'nonce': confirmed_nonce,
            'gas_price_wei': price, 'gas_limit': p['gas_limits'][action],
            'required_balance_wei': required, 'confirmed_balance_wei': confirmed_balance,
            'pending_balance_wei': pending_balance}
    return result


def recheck(blocks, call):
    for label in ('provider_finalized', 'provider_safe', 'latest'):
        b = blocks[label]
        if sepolia.block(hex(b['height']), call) != b:
            raise RuntimeError('pinned ETH observation was reorganized/inconsistent')
    # Forward growth is acceptable. A finality-label rollback is not.
    final = sepolia.block('finalized', call)
    if final['height'] < blocks['provider_finalized']['height']:
        raise RuntimeError('provider finality label rolled back')
    if final['height'] == blocks['provider_finalized']['height'] and final != blocks['provider_finalized']:
        raise RuntimeError('provider finalized block changed')


def observe(agreement, phase, call, endpoint):
    plan = agreement['execution_plan']
    timestamp_policy.require_agreement_binding(plan, agreement)
    window = 'first_reveal' if phase == 'first_reveal' else 'funding'
    timestamp_policy.require_window(plan, window, int(time.time()))
    start = time.monotonic()
    blocks = sepolia.observe(call, endpoint)
    if not blocks['rpc_genesis_verified'] or blocks['status'] != 'observed':
        raise RuntimeError('ETH provider identity incomplete; no escrow/address request made')
    escrow = inspect_escrow(agreement, call, blocks, phase)
    reserves = balances(agreement, call, blocks['latest'], phase)
    recheck(blocks, call)
    now = int(time.time())
    timestamp_policy.require_window(plan, window, now)
    age = now - blocks['latest']['timestamp']
    if (time.monotonic() - start > plan['policy']['observation_max_age_seconds']
            or not -plan['policy']['clock_error_seconds'] <= age <= plan['policy']['eth_tip_max_age_seconds']):
        raise RuntimeError('ETH observation exceeded signed duration/clock bounds')
    return {'format': 'latch-public-escrow-observation-v1', 'agreement_digest': digest(agreement),
        'phase': phase, 'clock': blocks, 'escrow': escrow, 'reserves': reserves,
        'observed_at': datetime.fromtimestamp(now, timezone.utc).isoformat(),
        'provider_trusted': True, 'owner_addresses_and_order_disclosed_to_provider': True,
        'keys_or_witness_sent': False, 'broadcast': False, 'funding_authorized': False,
        'reveal_authorized': False}
