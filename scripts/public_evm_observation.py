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
import escrow_abi
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


def public_order(agreement):
    """abi.encode(Order) exactly as lock() commits it (v2 calls carry it)."""
    return escrow_abi.order(agreement['maker'], agreement['recipient'], agreement['amount_wei'],
        agreement['eth_expiry'], agreement['point_x'], agreement['point_y'], '0x'+digest(agreement))


def claim_prefix(agreement):
    """Exact claim calldata before the 32-byte witness, for the agreed version."""
    v = escrow_abi.version(agreement)
    return ('0x' + escrow_abi.selector(escrow_abi.SIGNATURES[v]['claim']) + order_id(agreement)[2:]
            + (public_order(agreement) if v == 2 else ''))


def expected_order(agreement):
    return [int(agreement['maker'], 16), int(agreement['recipient'], 16),
        agreement['amount_wei'], agreement['eth_expiry'], 1,
        int(agreement['point_x'], 16), int(agreement['point_y'], 16), int(digest(agreement), 16)]


def inspect_escrow(agreement, call, blocks, phase, record=None):
    """Lower-level state reader, also exercised against a real isolated EVM.

    It does not establish the RPC network, signatures, input state or wall clock.
    The public entry point must do those checks separately.
    """
    if phase not in ('funding', 'eth_lock', 'first_reveal', 'recovery'):
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
        if escrow_abi.version(agreement) == 2:
            states[label] = inspect_v2(agreement, call, at, phase, target, identifier, code_hash, blocks[label])
            if record is not None: record(label, states[label])
            continue
        encoded = data(call('eth_call', [{'to': target, 'data': '0x9c3f1e90' + identifier[2:]}, at]), 256)
        words = [int.from_bytes(encoded[i:i+32], 'big') for i in range(0, 256, 32)]
        expected = expected_order(agreement) if phase in ('first_reveal', 'recovery') else [0]*8
        if phase == 'recovery':
            if words[4] == 0: expected = [0]*8
            elif words[4] in (1, 2, 3): expected[4] = words[4]
            else: raise RuntimeError('unknown escrow state')
        if words != expected:
            raise RuntimeError('escrow order/state differs from signed phase conditions')
        states[label] = {'block': blocks[label], 'runtime_code_hash': code_hash,
            'state': words[4], 'exact_order_matched': True}
        if record is not None: record(label, states[label])
    if phase == 'recovery':
        final, latest = states['provider_finalized']['state'], states['latest']['state']
        if latest not in {0: (0, 1, 2, 3), 1: (1, 2, 3), 2: (2,), 3: (3,)}[final]:
            raise RuntimeError('escrow finalized/latest states contradict immutable lifecycle')
        if states['provider_finalized'].get('paid') and not states['latest'].get('paid'):
            raise RuntimeError('escrow finalized/latest states contradict immutable lifecycle')
    return {'order_id': identifier, 'states': states}


def inspect_v2(agreement, call, at, phase, target, identifier, code_hash, block):
    """One v2 slot: commitment(order) | state, and the escrow's own comb table."""
    table = escrow_abi.table_address(target)
    code = call('eth_getCode', [table, at])
    if not isinstance(code, str) or not re.fullmatch(r'0x(?:[0-9a-f]{2}){1,24576}', code):
        raise RuntimeError('comb table code absent or malformed at pinned block')
    table_hash = '0x' + keccak(bytes.fromhex(code[2:])).hex()
    if table_hash != agreement['escrow']['table_code_hash'] or table_hash != escrow_abi.table_codehash():
        raise RuntimeError('comb table differs from signed code hash')
    slot = '0x' + data(call('eth_call', [{'to': target, 'data': '0x9c3f1e90' + identifier[2:]}, at]), 32).hex()
    state, paid = escrow_abi.slot_state(2, slot, public_order(agreement))
    allowed = {'funding': ((0, False),), 'eth_lock': ((0, False),), 'first_reveal': ((1, False),),
        'recovery': ((0, False), (1, False), (2, False), (3, False), (2, True), (3, True))}[phase]
    if (state, paid) not in allowed:
        raise RuntimeError('escrow order/state differs from signed phase conditions')
    return {'block': block, 'runtime_code_hash': code_hash, 'table_code_hash': table_hash,
        'state': state, 'paid': paid, 'exact_order_matched': True}


def market_price(call, latest, p):
    """Owner transactions pay the signed ceiling, so the ceiling must cover the
    pinned block's base fee and the provider's suggested price. A suggestion
    that lags just below the base fee (common at near-zero Sepolia fees) is
    raised to the base fee instead of refused."""
    price = max(sepolia.quantity(call('eth_gasPrice', [])), latest['base_fee_wei'])
    if not 0 < price <= p['max_gas_price_wei']:
        raise RuntimeError('gas price or base fee outside the signed cap')
    return price


def balances(agreement, call, latest, phase):
    """Pin confirmed balances/nonces to the same block as code and order state.

    Also check pending state. This detects observed contention, not simultaneous
    use of the key elsewhere or private pending transactions unknown to this RPC.
    """
    p = fee_policy.policy(agreement)
    price = market_price(call, latest, p)
    roles = [('alice', 'claim')]
    if phase != 'first_reveal':
        roles.append(('bob', 'lock'))
    result = {}
    for role, action in roles:
        result[role] = action_reserve(agreement, call, latest, role, action, price)
    return result


def action_reserve(agreement, call, latest, role, action, price=None):
    if role not in ('alice', 'bob') or action not in ('lock', 'claim', 'refund', 'withdraw'):
        raise RuntimeError('unsupported owner reserve')
    p = fee_policy.policy(agreement)
    if price is None: price = market_price(call, latest, p)
    address = agreement['owners'][role]['address']
    at = {'blockHash': latest['hash'], 'requireCanonical': True}
    confirmed_nonce = sepolia.quantity(call('eth_getTransactionCount', [address, at]))
    pending_nonce = sepolia.quantity(call('eth_getTransactionCount', [address, 'pending']))
    confirmed_balance = sepolia.quantity(call('eth_getBalance', [address, at]))
    pending_balance = sepolia.quantity(call('eth_getBalance', [address, 'pending']))
    required = fee_policy.required_balance(agreement, action)
    if confirmed_nonce != pending_nonce or confirmed_nonce >= 2**64:
        raise RuntimeError('owner nonce changed or pending before first action')
    if min(confirmed_balance, pending_balance) < required:
        raise RuntimeError('owner lacks signed reserve in confirmed or pending state')
    return {'address': address, 'action': action, 'nonce': confirmed_nonce,
        'gas_price_wei': price, 'gas_limit': p['gas_limits'][action],
        'required_balance_wei': required, 'confirmed_balance_wei': confirmed_balance,
        'pending_balance_wei': pending_balance}


CREDIT_SELECTOR = '0x'+keccak(b'credits(address)')[:4].hex()


def recovery_action(agreement, call, blocks, escrow, role, action, now=None):
    """Exact terminal credit or matured lock, before signing a recovery action.

    Does not exclude historical exposure. The owner wrapper must also consult
    sticky local history. Credits aggregate by owner: require a dedicated owner
    and the exact agreed amount rather than silently withdrawing other orders.
    """
    now = int(time.time()) if now is None else now
    if action not in ('refund', 'withdraw') or role not in ('alice', 'bob'):
        raise RuntimeError('unsupported recovery action')
    if action == 'refund' and role != 'bob': raise RuntimeError('only maker prepares ETH refund')
    expected = 1 if action == 'refund' else {'alice': 2, 'bob': 3}[role]
    if any(s['state'] != expected for s in escrow['states'].values()):
        raise RuntimeError('recovery requires matching finalized/latest order state')
    if action == 'refund' and (now < agreement['eth_expiry']+agreement['execution_plan']['policy']['clock_error_seconds']
            or any(blocks[k]['timestamp'] < agreement['eth_expiry'] for k in ('provider_finalized', 'latest'))):
        raise RuntimeError('ETH refund timestamp not mature')
    address = agreement['owners'][role]['address']
    credits = {}
    if escrow_abi.version(agreement) == 2:
        # v2 credits the order itself: a terminal state without the PAID bit
        # is exactly this order's unwithdrawn amount, never another order's.
        if action == 'withdraw' and any(s['paid'] for s in escrow['states'].values()):
            raise RuntimeError('exact dedicated owner credit required; reconcile prior withdrawal or other orders')
        expected_credit = agreement['amount_wei'] if action == 'withdraw' else 0
        credits = {label: expected_credit for label in ('provider_finalized', 'latest')}
        return {'action': action, 'role': role, 'credit_wei': expected_credit, 'credits': credits,
            'reserve': action_reserve(agreement, call, blocks['latest'], role, action),
            'withdrawal_verified': False, 'send_authorized': False}
    for label in ('provider_finalized', 'latest'):
        at = {'blockHash': blocks[label]['hash'], 'requireCanonical': True}
        credits[label] = int.from_bytes(data(call('eth_call', [{'to': agreement['escrow']['contract'],
            'data': CREDIT_SELECTOR+data(address, 20).hex().rjust(64, '0')}, at]), 32), 'big')
    expected_credit = agreement['amount_wei'] if action == 'withdraw' else 0
    if any(n != expected_credit for n in credits.values()):
        raise RuntimeError('exact dedicated owner credit required; reconcile prior withdrawal or other orders')
    return {'action': action, 'role': role, 'credit_wei': expected_credit, 'credits': credits,
        'reserve': action_reserve(agreement, call, blocks['latest'], role, action),
        'withdrawal_verified': False, 'send_authorized': False}


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


def observe_recovery(agreement, call, endpoint, record=None, action=None, role=None):
    """Read the exact order after expiry too; no first-reveal or sending decision.

    Persist each checked state before later RPCs can fail. A claimed order means
    a witness was exposed on the provider's branch, but the getter doesn't return
    that witness. Empty/locked/refunded never exclude earlier mempool exposure.
    """
    plan = agreement['execution_plan']
    timestamp_policy.require_agreement_binding(plan, agreement)
    start = time.monotonic()
    blocks = sepolia.observe(call, endpoint)
    if not blocks['rpc_genesis_verified'] or blocks['status'] != 'observed':
        raise RuntimeError('ETH provider identity incomplete; no escrow/address request made')
    escrow = inspect_escrow(agreement, call, blocks, 'recovery', record)
    action_checks = recovery_action(agreement, call, blocks, escrow, role, action) if action is not None else None
    recheck(blocks, call)
    now = int(time.time())
    if (time.monotonic()-start > plan['policy']['observation_max_age_seconds']
            or not -plan['policy']['clock_error_seconds'] <= now-blocks['latest']['timestamp'] <= plan['policy']['eth_tip_max_age_seconds']):
        raise RuntimeError('ETH recovery observation exceeded signed duration/clock bounds')
    return {'format': 'latch-public-escrow-recovery-observation-v1', 'agreement_digest': digest(agreement),
        'clock': blocks, 'escrow': escrow, 'action_checks': action_checks,
        'observed_at': datetime.fromtimestamp(now, timezone.utc).isoformat(),
        'claim_observed_by_provider': any(v['state'] == 2 for v in escrow['states'].values()),
        'opening_obtained': False, 'prior_exposure_excluded': False, 'withdrawal_verified': False,
        'provider_trusted': True, 'owner_addresses_and_order_disclosed_to_provider': True,
        'keys_or_witness_sent': False, 'broadcast': False, 'send_authorized': False}
