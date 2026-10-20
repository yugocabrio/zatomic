#!/usr/bin/env python3
"""Exact ETH delivery journal and read-only public receipt reconciliation.

The transport primitive is exercised only on an owned isolated EVM. There is no
public sending CLI: a future sender must hold the owner lock, freshly reconcile
both chains and enforce first-exposure/replay policy before invoking it. An old
observation or a saved successful receipt is never authority to send.
"""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import time
import uuid
import evm_wallet
import public_authority as authority
import public_eth_outgoing as out
import public_evm_observation as eth
import public_outgoing as private
import probe_sepolia as sepolia
from source_inputs import publish
from testnet_wallet import read


def retained(action, value, files, checked):
    raw = private.raw_bytes(action/'transaction.hex')
    verified = out.verify_raw(action, value, files, checked, raw)
    expected = {'decision_digest': eth.digest(value), 'checked': verified}
    if read(action/'signed.json') != expected:
        raise RuntimeError('delivery raw/decision/signed journal mismatch')
    # Only local stdin carries calldata. Decoder output remains private.
    decoded = subprocess.run(['cast', 'decode-transaction', '--json'],
        input='0x'+raw.hex()+'\n', text=True, capture_output=True, timeout=15, check=True)
    return raw, verified, json.loads(decoded.stdout)


def folder(action, name, identity):
    parent = action/name; private.private_directory(parent)
    private.immutable(parent/'binding.json', identity)
    entries = [p for p in parent.iterdir() if p.name != 'binding.json']
    if len(entries) >= 128 or any(not re.fullmatch('[0-9a-f]{32}', p.name) for p in entries):
        raise RuntimeError('delivery history bound/shape; retain all attempts')
    for entry in entries: private.private_directory(entry)
    directory = parent/uuid.uuid4().hex; private.private_directory(directory)
    return directory


def identity(value, verified):
    return {'decision_digest': eth.digest(value), 'txid': verified['txid'],
        'bytes_sha256': verified['bytes_sha256']}


def send_once(action, value, files, checked, send, fresh_guard):
    """Lower-level transport, NOT a public safety/authorization entry point.

    Caller holds the owner lock. The callback checks this exact signed decision
    and current chain state in this invocation. Never supply a serialized report
    as a guard. Any attempted transport, even an exception, remains uncertain
    until a new exact receipt observation; there is no automatic retry.
    """
    raw, verified, _ = retained(action, value, files, checked)
    fresh_guard(value, verified)
    attempt = folder(action, 'send-attempts', identity(value, verified))
    publish(attempt/'intent.json', dict(identity(value, verified),
        format='latch-eth-send-intent-v1', may_have_reached_network=True,
        possible_secret_exposure=value['kind'] == 'claim'))
    # The intent is fsynced before the transport callback receives raw bytes.
    try:
        returned = send('0x'+raw.hex())
        if returned != verified['txid']: raise RuntimeError('unexpected returned transaction hash')
    except Exception:
        # Never save/echo a provider exception: it may contain secret calldata.
        publish(attempt/'result.json', {'status': 'uncertain', 'may_have_reached_network': True})
        return {'status': 'uncertain', 'txid': verified['txid'], 'attempt': attempt.name,
            'possible_secret_exposure': value['kind'] == 'claim'}
    publish(attempt/'result.json', {'status': 'submitted', 'txid': returned,
        'receipt_required': True, 'may_have_reached_network': True})
    return {'status': 'submitted', 'txid': returned, 'attempt': attempt.name,
        'possible_secret_exposure': value['kind'] == 'claim'}


def expected_event(agreement, value, decoded):
    kind = value['kind']; identifier = eth.order_id(agreement)
    owner = value['transaction_base']['from']; word = lambda n: f'{n:064x}'
    if kind == 'lock':
        signature = b'Locked(bytes32,address,address,uint256,uint64,uint256,uint256,bytes32)'
        topics = [identifier, '0x'+word(int(owner, 16)), '0x'+word(int(agreement['recipient'], 16))]
        data = '0x'+''.join(word(n) for n in (agreement['amount_wei'], agreement['eth_expiry'],
            int(agreement['point_x'], 16), int(agreement['point_y'], 16), int(eth.digest(agreement), 16)))
    elif kind == 'claim':
        signature = b'Claimed(bytes32,uint256)'; topics = [identifier]; data = '0x'+decoded['input'][-64:]
    elif kind == 'refund':
        signature = b'Refunded(bytes32)'; topics = [identifier]; data = '0x'
    elif kind == 'withdraw' and agreement.get('escrow_version', 1) == 2:
        signature = b'Withdrawn(bytes32,address,address,uint256)'
        topics = [identifier]+['0x'+word(int(owner, 16))]*2; data = '0x'+word(agreement['amount_wei'])
    elif kind == 'withdraw':
        signature = b'Withdrawn(address,address,uint256)'
        topics = ['0x'+word(int(owner, 16))]*2; data = '0x'+word(agreement['amount_wei'])
    else: raise RuntimeError('unsupported receipt action')
    return ['0x'+evm_wallet.keccak(signature).hex()]+topics, data


def match_transaction(found, decoded):
    for key, expected in [('hash', 'hash'), ('from', 'signer'), ('to', 'to'), ('input', 'input')]:
        if found.get(key) != decoded[expected].lower(): raise RuntimeError('RPC transaction differs from retained signed bytes')
    for key in ('chainId', 'type', 'nonce', 'gasPrice', 'gas', 'value'):
        if sepolia.quantity(found[key]) != sepolia.quantity(decoded[key]):
            raise RuntimeError('RPC transaction quantity differs from retained signed bytes')


def inspect_receipt(agreement, value, decoded, call, blocks, record):
    """Read-only primitive after network/clock identity; provider remains trusted.

    Successful transaction status is insufficient: match the exact transaction,
    canonical block membership and the contract's expected event. A receipt gap,
    failed claim or reorg does not clear the durable local exposure decision.
    """
    txid = decoded['hash'].lower()
    found = call('eth_getTransactionByHash', [txid])
    receipt = call('eth_getTransactionReceipt', [txid])
    record('response', {'transaction': found, 'receipt': receipt})
    result = {'txid': txid, 'kind': value['kind'], 'state': 'unobserved-by-provider',
        'provider_trusted': True, 'withdrawal_verified': False, 'send_authorized': False,
        'possible_secret_exposure': value['kind'] == 'claim', 'broadcast': False}
    if found is None:
        if receipt is not None: raise RuntimeError('receipt without exact transaction')
        return result
    match_transaction(found, decoded)
    if receipt is None:
        if found.get('blockHash') is not None or found.get('blockNumber') is not None:
            raise RuntimeError('mined transaction missing receipt; preserve uncertainty')
        result['state'] = 'pending-by-provider'; return result
    height = sepolia.quantity(receipt['blockNumber'])
    block_hash = '0x'+eth.data(receipt['blockHash'], 32).hex()
    index = sepolia.quantity(receipt['transactionIndex'])
    status = sepolia.quantity(receipt['status'])
    if (status not in (0, 1) or receipt['transactionHash'] != txid
            or receipt['from'] != decoded['signer'].lower() or receipt['to'] != decoded['to'].lower()
            or found['blockHash'] != block_hash or found['blockNumber'] != receipt['blockNumber']
            or found['transactionIndex'] != receipt['transactionIndex'] or height > blocks['latest']['height']):
        raise RuntimeError('receipt domain/index/status differs from exact transaction')
    block = call('eth_getBlockByNumber', [hex(height), False])
    if (block is None or block['hash'] != block_hash or block['number'] != hex(height)
            or index >= len(block['transactions']) or block['transactions'][index] != txid):
        raise RuntimeError('receipt is not a member of the current canonical block')
    code = call('eth_getCode', [agreement['escrow']['contract'],
        {'blockHash': block_hash, 'requireCanonical': True}])
    if (not isinstance(code, str) or not re.fullmatch(r'0x(?:[0-9a-f]{2}){1,24576}', code)
            or '0x'+evm_wallet.keccak(bytes.fromhex(code[2:])).hex() != agreement['escrow']['runtime_code_hash']):
        raise RuntimeError('receipt contract runtime differs from signed escrow')
    if sepolia.quantity(receipt['gasUsed']) > sepolia.quantity(decoded['gas']):
        raise RuntimeError('receipt gas exceeds signed gas limit')
    if sepolia.quantity(receipt['effectiveGasPrice']) != sepolia.quantity(decoded['gasPrice']):
        raise RuntimeError('receipt fee differs from legacy signed fee')
    topics, data = expected_event(agreement, value, decoded)
    matched = []
    if not isinstance(receipt['logs'], list): raise RuntimeError('receipt logs unavailable')
    for log in receipt['logs']:
        if (log['address'] == agreement['escrow']['contract'] and log['topics'] == topics and log['data'] == data):
            if (log.get('removed', False) is not False or log['transactionHash'] != txid
                    or log['blockHash'] != block_hash or log['blockNumber'] != hex(height)
                    or log['transactionIndex'] != receipt['transactionIndex']):
                raise RuntimeError('expected event is removed or from a different transaction')
            matched.append(log)
    if (status == 1 and len(matched) != 1) or (status == 0 and receipt['logs']):
        raise RuntimeError('receipt success lacks exact event, or reverted receipt contains logs')
    final = height <= blocks['provider_finalized']['height']
    # Recheck the receipt block after reading data (not only the observed tip).
    if call('eth_getBlockByNumber', [hex(height), False]) != block:
        raise RuntimeError('receipt block changed during verification')
    result.update(state=('confirmed-by-provider' if final else 'confirming-by-provider') if status else 'reverted-by-provider',
        receipt_status=status, block_hash=block_hash, block_height=height,
        provider_finalized=final, expected_event_verified=status == 1,
        withdrawal_verified=value['kind'] == 'withdraw' and status == 1 and final)
    record('checked-receipt', result)
    return result


def observe_locked(owner, consents, kind, endpoint=sepolia.ENDPOINT):
    files, checked, caller, _ = out.context(owner, consents, kind)
    if checked['synthetic_inputs'] is not False: raise RuntimeError('synthetic inputs cannot enter public delivery observation')
    role = caller['role']; agreement = files['proposal']['agreement']
    directory, binding = out.workspace(owner, files, checked, role)
    action, value = out.decision(directory, binding, agreement, kind)
    _, verified, decoded = retained(action, value, files, checked)
    rpc = sepolia.ReadOnlyRpc(endpoint)
    observed = folder(action, 'receipt-observations', identity(value, verified))
    publish(observed/'intent.json', dict(identity(value, verified), endpoint=endpoint, broadcast=False))
    started = time.monotonic(); blocks = sepolia.observe(rpc, endpoint)
    if blocks['status'] != 'observed' or not blocks['rpc_genesis_verified']:
        raise RuntimeError('ETH provider identity incomplete; no transaction hash disclosed')
    def record(label, data): publish(observed/(label+'.json'), data)
    result = inspect_receipt(agreement, value, decoded, rpc, blocks, record)
    eth.recheck(blocks, rpc)
    p = agreement['execution_plan']['policy']; now = int(time.time())
    if (time.monotonic()-started > p['observation_max_age_seconds']
            or not -p['clock_error_seconds'] <= now-blocks['latest']['timestamp'] <= p['eth_tip_max_age_seconds']):
        raise RuntimeError('receipt observation exceeded signed duration/clock bounds')
    if authority.bind_owner(owner, files, checked, out.action_phase(kind, role)) != caller or read(consents) != files['consents']:
        raise RuntimeError('owner acceptance changed during receipt observation')
    result.update(clock=blocks, observation_directory=str(observed),
        scope='current trusted-RPC receipt; prior attempts/observations retained, no reorg or inclusion guarantee')
    publish(observed/'report.json', result)
    return result


def main():
    os.umask(0o077)
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('owner', type=Path); p.add_argument('consents', type=Path)
    p.add_argument('action', choices=('lock', 'claim', 'refund', 'withdraw'))
    p.add_argument('--eth-rpc', default=sepolia.ENDPOINT)
    a = p.parse_args()
    with authority.owner_locked(a.owner): print(json.dumps(observe_locked(a.owner, a.consents, a.action, a.eth_rpc), indent=2))
    return 2


if __name__ == '__main__':
    try: raise SystemExit(main())
    except (RuntimeError, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        raise SystemExit('ETH receipt reconciliation refused; preserve private attempts/receipts. Nothing sent.') from None
