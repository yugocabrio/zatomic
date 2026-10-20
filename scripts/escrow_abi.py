"""Escrow ABI by version for every client: calldata, order state, events, code pins.

v1 is contracts/src/PointEscrow.sol (seven-slot order, credits per address).
v2 is contracts/src/PointEscrowV2.sol (one slot: commitment(order) | state;
claim, refund and withdraw carry the order; per-order withdrawal).
An agreement without `escrow_version` is a v1 agreement and keeps v1 rules.

Calldata is built here in Python, never through argv, so an unrevealed claim
witness never appears in a process argument list. Nothing here calls an RPC.
"""
import json
import os
from pathlib import Path
import re
import evm_wallet

ROOT = Path(__file__).resolve().parents[1]
VERSIONS = (1, 2)
ARTIFACT = {1: 'PointEscrow.sol/PointEscrow.json', 2: 'PointEscrowV2.sol/PointEscrowV2.json'}
ORDER = '(address,address,uint256,uint64,(uint256,uint256),bytes32)'
LOCK = 'lock(bytes32,address,uint64,(uint256,uint256),bytes32)'
SIGNATURES = {
    1: {'lock': LOCK, 'claim': 'claim(bytes32,uint256)', 'refund': 'refund(bytes32)',
        'withdraw': 'withdraw(address)'},
    2: {'lock': LOCK, 'claim': f'claim(bytes32,{ORDER},uint256)', 'refund': f'refund(bytes32,{ORDER})',
        'withdraw': f'withdraw(bytes32,{ORDER},address)'},
}
# Static 32-byte words after the selector.
WORDS = {1: {'lock': 6, 'claim': 2, 'refund': 1, 'withdraw': 1},
         2: {'lock': 6, 'claim': 9, 'refund': 8, 'withdraw': 9}}
LOCKED = 'Locked(bytes32,address,address,uint256,uint64,uint256,uint256,bytes32)'
CLAIMED = 'Claimed(bytes32,uint256)'
REFUNDED = 'Refunded(bytes32)'
WITHDRAWN = {1: 'Withdrawn(address,address,uint256)', 2: 'Withdrawn(bytes32,address,address,uint256)'}
ORDERS_SELECTOR = '0x9c3f1e90'  # orders(bytes32), the same getter name in both versions
STATE_BITS, PAID = 7, 4
V2_STATES = {1: (1, False), 2: (2, False), 3: (3, False), 6: (2, True), 7: (3, True)}


def local_default():
    """Escrow version for NEW agreements on the isolated local chains."""
    value = os.environ.get('LATCH_ESCROW_VERSION', '2')
    if value not in ('1', '2'):
        raise RuntimeError('LATCH_ESCROW_VERSION must be 1 or 2')
    return int(value)


def version(agreement):
    value = agreement.get('escrow_version', 1)
    if type(value) is not int or value not in VERSIONS:
        raise RuntimeError('unsupported escrow version')
    return value


def artifact(v):
    return json.loads((ROOT / '.local/forge-out' / ARTIFACT[v]).read_text())


def creation_code(v):
    code = artifact(v)['bytecode']['object']
    return code if code.startswith('0x') else '0x' + code


def runtime_code(v):
    return artifact(v)['deployedBytecode']['object'].removeprefix('0x')


def selector(signature):
    return evm_wallet.keccak(signature.encode())[:4].hex()


def topic(signature):
    return '0x' + evm_wallet.keccak(signature.encode()).hex()


def word(value):
    if type(value) is not int or not 0 <= value < 2**256:
        raise RuntimeError('invalid ABI word')
    return value.to_bytes(32, 'big').hex()


def address_word(address):
    if not isinstance(address, str) or not re.fullmatch(r'0x[0-9a-fA-F]{40}', address):
        raise RuntimeError('invalid ABI address')
    return address[2:].lower().rjust(64, '0')


def bytes32_word(value):
    if not isinstance(value, str) or not re.fullmatch(r'0x[0-9a-fA-F]{64}', value):
        raise RuntimeError('invalid ABI bytes32')
    return value[2:].lower()


def order(maker, recipient, amount, refund_at, x, y, terms_hash):
    """abi.encode(Order) as 7 words of hex, without 0x."""
    if type(refund_at) is not int or not 0 <= refund_at < 2**64:
        raise RuntimeError('invalid order refund time')
    return (address_word(maker) + address_word(recipient) + word(amount) + word(refund_at)
            + word(int(x, 16) if isinstance(x, str) else x) + word(int(y, 16) if isinstance(y, str) else y)
            + bytes32_word(terms_hash))


def commitment(order_hex):
    if not re.fullmatch(r'[0-9a-f]{448}', order_hex):
        raise RuntimeError('seven-word order encoding required')
    return int.from_bytes(evm_wallet.keccak(bytes.fromhex(order_hex)), 'big') & ~STATE_BITS & (2**256 - 1)


def calldata(v, kind, order_id, order_hex=None, witness=None, to=None):
    """Exact calldata for claim, refund or withdraw of one order."""
    sel = '0x' + selector(SIGNATURES[v][kind])
    if v == 2 and kind in ('claim', 'refund', 'withdraw'):
        if order_hex is None:
            raise RuntimeError('v2 escrow calls carry the order')
        commitment(order_hex)
    if kind == 'claim':
        scalar = int(witness, 0) if isinstance(witness, str) else witness
        body = bytes32_word(order_id) + (order_hex if v == 2 else '') + word(scalar)
    elif kind == 'refund':
        body = bytes32_word(order_id) + (order_hex if v == 2 else '')
    elif kind == 'withdraw':
        body = (bytes32_word(order_id) + order_hex if v == 2 else '') + address_word(to)
    else:
        raise RuntimeError('unsupported escrow call')
    data = sel + body
    if len(data) != 10 + 64 * WORDS[v][kind]:
        raise RuntimeError('escrow calldata length mismatch')
    return data


def shape(data):
    """(version, kind) whose selector and length match `data`, else None."""
    if not isinstance(data, str) or not data.startswith('0x'):
        return None
    for v in VERSIONS:
        for kind, signature in SIGNATURES[v].items():
            if data[2:10] == selector(signature) and len(data) == 10 + 64 * WORDS[v][kind]:
                return v, kind
    return None


def slot_state(v, encoded, order_hex):
    """Decode orders(id) for the agreed order: (state, paid) with v1 numbering.

    state 0 empty, 1 locked, 2 claimed, 3 refunded; `paid` is v2 only (v1
    tracks payment in credits). Raises if the slot holds a different order.
    """
    if v != 2:
        raise RuntimeError('slot_state decodes v2 slots only')
    if not isinstance(encoded, str) or not re.fullmatch(r'0x[0-9a-f]{64}', encoded):
        raise RuntimeError('v2 order slot must be one word')
    slot = int(encoded, 16)
    if slot == 0:
        return 0, False
    if slot & ~STATE_BITS != commitment(order_hex) or slot & STATE_BITS not in V2_STATES:
        raise RuntimeError('escrow order differs from the committed agreement')
    return V2_STATES[slot & STATE_BITS]


def table_address(contract):
    """CREATE address of the escrow's nonce 1, where v2 deploys its comb table."""
    if not re.fullmatch(r'0x[0-9a-fA-F]{40}', contract):
        raise RuntimeError('invalid escrow address')
    return '0x' + evm_wallet.keccak(bytes.fromhex('d694' + contract[2:].lower() + '01'))[12:].hex()


def table_codehash():
    source = (ROOT / 'contracts/src/PallasCombTables.sol').read_text()
    found = re.findall(r'CODEHASH_4 = (0x[0-9a-f]{64});', source)
    if len(found) != 1:
        raise RuntimeError('width-4 table code hash pin missing')
    return found[0]


def verify_code(agreement, get_code):
    """Exact deployed code for the agreement's version, and v2's comb table."""
    v = version(agreement)
    if get_code(agreement['contract']).removeprefix('0x') != runtime_code(v):
        raise RuntimeError('escrow code differs from the pinned version')
    if v == 2:
        table = bytes.fromhex(get_code(table_address(agreement['contract'])).removeprefix('0x'))
        if '0x' + evm_wallet.keccak(table).hex() != table_codehash():
            raise RuntimeError('v2 comb table missing or changed')
    return v


def withdrawn_event(v, log, contract, order_id, owner, to, amount):
    """True for the exact Withdrawn log of `owner` paying `amount` to `to`."""
    if log['address'].lower() != contract.lower() or int(log['data'], 16) != amount:
        return False
    owner_topic, to_topic = '0x' + address_word(owner), '0x' + address_word(to)
    expected = ([topic(WITHDRAWN[1]), owner_topic, to_topic] if v == 1
                else [topic(WITHDRAWN[2]), order_id.lower(), owner_topic, to_topic])
    return [t.lower() for t in log['topics']] == expected
