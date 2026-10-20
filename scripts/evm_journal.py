"""Durable, exactly identified outgoing transactions for the owned local EVM.

Raw signatures are saved BEFORE eth_sendRawTransaction. A restored local node
can replay the identical bytes/hash. This is not public-chain finality; replay
of a potentially exposed claim is bounded by the fixture's timing policy.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
import run_native_evm_gate as evm
import escrow_abi
from regtest_wallet import save
from regtest_node import status


class InjectedStop(RuntimeError):
    pass


METHODS = escrow_abi.SIGNATURES[1]  # v1 names; validate_intent accepts every version's shape.


def validate_intent(intent):
    """Bind replay policy to the signed bytes, including the recovered sender.

    Decode through stdin: a pending claim's witness must not appear in argv or
    decoder errors. Never trust a mutable `kind` label to classify the call.
    """
    raw = intent['raw']
    if not isinstance(raw, str) or not raw.startswith('0x') or len(raw) > 131072:
        raise RuntimeError('invalid outgoing raw encoding')
    decoded = subprocess.run(['cast', 'decode-transaction', '--json'],
        input=raw + '\n', capture_output=True, text=True, timeout=10)
    if decoded.returncode:
        raise RuntimeError('cannot decode signed outgoing transaction')
    actual = json.loads(decoded.stdout)
    tx = intent['transaction']
    if intent['chain_id'] != evm.CHAIN or actual['hash'].lower() != intent['txid'].lower():
        raise RuntimeError('outgoing intent identity/domain mismatch')
    for field in ('chainId', 'type', 'nonce', 'gasPrice', 'gas', 'value'):
        if int(actual[field], 16) != int(tx.get(field, '0x0'), 16):
            raise RuntimeError('outgoing signed quantity differs from journal')
    if int(actual['chainId'], 16) != evm.CHAIN or actual['type'] != '0x0':
        raise RuntimeError('outgoing signed transaction domain mismatch')
    for field, other in [('signer', 'from'), ('to', 'to'), ('input', 'data')]:
        if (actual.get(field) or '').lower() != (tx.get(other) or '').lower():
            raise RuntimeError('outgoing signed destination/data/sender differs from journal')
    kind = intent['kind']
    if kind == 'deploy':
        if actual.get('to') or actual['input'] not in (escrow_abi.creation_code(v) for v in escrow_abi.VERSIONS):
            raise RuntimeError('outgoing deployment differs from pinned escrow')
    elif kind in METHODS:
        found = escrow_abi.shape(actual['input'])
        if found is None or found[1] != kind:
            raise RuntimeError('outgoing kind differs from signed method')
    else:
        raise RuntimeError('unknown outgoing intent; refuse replay')
    return tx


def require_reveal_window(agreement, terms):
    now = int(evm.rpc('eth_getBlockByNumber', ['latest', False])['timestamp'], 16)
    if now + 60 >= agreement['eth_expiry'] or status()['blocks'] + 6 >= terms['refund_height']:
        raise RuntimeError('potentially exposed claim outside recovery window; no refund fallback')


def verify_contract(agreement):
    try:
        escrow_abi.verify_code(agreement, lambda address: evm.rpc('eth_getCode', [address, 'latest']))
    except RuntimeError:
        raise RuntimeError('restored contract code mismatch before any replay') from None


def terms_hash(agreement):
    return '0x' + hashlib.sha256(json.dumps(agreement, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def local_order(agreement, terms):
    """The agreed order exactly as lock() commits it (v2 claim/refund/withdraw carry it)."""
    return escrow_abi.order(agreement['maker'], agreement['recipient'], agreement['amount_wei'],
        agreement['eth_expiry'], terms['point_x'], terms['point_y'], terms_hash(agreement))


def order_slot(agreement, terms, order):
    """(state, paid) of the agreed order: 0 empty, 1 locked, 2 claimed, 3 refunded."""
    encoded = evm.rpc('eth_call', [{'to': agreement['contract'], 'data': evm.calldata('orders(bytes32)', order)}, 'latest'])
    if escrow_abi.version(agreement) == 2:
        return escrow_abi.slot_state(2, encoded, local_order(agreement, terms))
    words = [int(encoded[2+i:2+i+64], 16) for i in range(0, len(encoded)-2, 64)]
    if len(words) == 8 and not any(words):
        return 0, False
    if len(words) != 8 or words[0] != int(agreement['maker'], 16) or words[1] != int(agreement['recipient'], 16) or words[2] != agreement['amount_wei'] or words[3] != agreement['eth_expiry'] or words[5] != int(terms['point_x'], 16) or words[6] != int(terms['point_y'], 16) or words[7] != int(terms_hash(agreement), 16):
        raise RuntimeError('restored order differs from committed agreement')
    return words[4], False


def order_state(agreement, terms, order):
    """State of an existing agreed order; an empty slot is rejected."""
    state, _ = order_slot(agreement, terms, order)
    if state == 0:
        raise RuntimeError('restored order differs from committed agreement')
    return state


def checkpoint(directory):
    value = {'chain_id': evm.CHAIN, 'state': evm.rpc('anvil_dumpState')}
    temporary = directory / 'evm-checkpoint.tmp'
    with temporary.open('w') as handle:
        json.dump(value, handle)
        handle.flush()
        os.fsync(handle.fileno())
    temporary.replace(directory / 'evm-checkpoint.json')
    fd = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def receipt(txid):
    for _ in range(100):
        value = evm.rpc('eth_getTransactionReceipt', [txid])
        if value:
            if value['status'] != '0x1':
                raise RuntimeError(f'outgoing EVM transaction reverted: {txid}')
            return value
        time.sleep(.1)
    raise RuntimeError('outgoing EVM receipt timeout; intent preserved')


def record(directory, value):
    folder = directory / 'evm-receipts'
    folder.mkdir(mode=0o700, exist_ok=True)
    # Replaying an identical transaction on a restored local chain can give it
    # a new block hash. Preserve each receipt observation rather than silently
    # overwriting the old one or treating its old block as canonical forever.
    save(folder / f'{value["transactionHash"]}-{value["blockHash"]}.json', value)
    checkpoint(directory)


def send(directory, transaction, kind='other', fault_after_send=False):
    if int(evm.rpc('eth_chainId'), 16) != evm.CHAIN:
        raise RuntimeError('wrong outgoing EVM chain')
    tx = dict(transaction, chainId=hex(evm.CHAIN), type='0x0',
              nonce=evm.rpc('eth_getTransactionCount', [transaction['from'], 'pending']),
              gasPrice=evm.rpc('eth_gasPrice'))
    raw = evm.rpc('eth_signTransaction', [tx])
    if isinstance(raw, dict):
        raw = raw['raw']
    txid = evm.rpc('web3_sha3', [raw])
    intent = {'chain_id': evm.CHAIN, 'kind': kind, 'transaction': tx, 'raw': raw, 'txid': txid}
    validate_intent(intent)
    # Preserve the immediately preceding node state before exposing a signed
    # transaction to sendRaw. Intent + raw bytes are private artifacts.
    checkpoint(directory)
    folder = directory / 'evm-outgoing'
    folder.mkdir(mode=0o700, exist_ok=True)
    sequence = len(list(folder.glob('*.json')))
    save(folder / f'{sequence:06d}-{txid}.json', intent)
    accepted = evm.rpc('eth_sendRawTransaction', [raw])
    if accepted != txid:
        raise RuntimeError('outgoing transaction identity changed')
    if fault_after_send:
        raise InjectedStop(f'{kind}-broadcast-before-receipt-checkpoint')
    value = receipt(txid)
    record(directory, value)
    return value


def replay(directory, agreement, terms):
    replayed = 0
    for path in sorted((directory / 'evm-outgoing').glob('*.json')):
        intent = json.loads(path.read_text())
        tx = validate_intent(intent)
        if intent['kind'] != 'deploy' and tx.get('to', '').lower() != agreement['contract'].lower():
            raise RuntimeError('outgoing destination differs from agreed escrow')
        current = evm.rpc('eth_getTransactionReceipt', [intent['txid']])
        if current:
            if current['status'] != '0x1':
                raise RuntimeError('recorded outgoing transaction reverted')
            # No resubmission when the exact hash is already confirmed.
            continue
        if evm.rpc('eth_getTransactionCount', [tx['from'], 'pending']) != tx['nonce']:
            raise RuntimeError('outgoing nonce already consumed or changed; refuse replacement')
        now = int(evm.rpc('eth_getBlockByNumber', ['latest', False])['timestamp'], 16)
        if intent['kind'] == 'claim':
            data = tx.get('data', '')
            if tx.get('to', '').lower() != agreement['contract'].lower() or escrow_abi.shape(data) != (escrow_abi.version(agreement), 'claim'):
                raise RuntimeError('outgoing claim destination/encoding mismatch')
            state = order_state(agreement, terms, '0x' + data[10:74])
            if state == 2:
                # A different relayer can complete the same fixed-recipient
                # claim. Reconcile its public event instead of forcing a revert.
                continue
            if state != 1:
                raise RuntimeError('potentially exposed claim no longer claimable; no refund fallback')
            # A signed claim may already have exposed t. Never reinterpret its
            # absent receipt as "no reveal" and refund both sides. Retry the
            # identical call only inside the conservative controlled window.
            require_reveal_window(agreement, terms)
        elif intent['kind'] == 'lock' and now + 300 >= agreement['eth_expiry']:
            raise RuntimeError('original ETH lock window elapsed; refuse new funding')
        elif intent['kind'] not in ('deploy', 'lock', 'refund', 'withdraw'):
            raise RuntimeError('unknown outgoing intent; refuse replay')
        if evm.rpc('eth_sendRawTransaction', [intent['raw']]) != intent['txid']:
            raise RuntimeError('replayed transaction identity changed')
        current = receipt(intent['txid'])
        record(directory, current)
        replayed += 1
    return replayed
