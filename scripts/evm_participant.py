#!/usr/bin/env python3
"""One owner's isolated-chain swap client. No node-unlocked signing or key export.

Commands run locally for that owner. Public agreement/order requests use stdin;
this is not a network signing service or an authenticated offer transport.
Every operation is fixed to a role, exact accepted native bundle and escrow.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import run_native_evm_gate as evm
import claim_precheck
import escrow_abi
import evm_wallet
import fee_policy
import native_funding
import native_owner
from recover_regtest_swap import auxiliary_depth, native_exit
from evm_journal import (InjectedStop, validate_intent, verify_contract, order_state, order_slot, local_order,
    require_reveal_window, receipt)
from regtest_node import rpc as zrpc, status
from regtest_wallet import save, capture, native
from signer_transport import private_file


def read(path):
    return json.loads(private_file(path, 200_000))


def initialize_key(directory, role):
    identity = evm_wallet.initialize(directory / 'ethereum')
    identity['role'] = role
    save(directory / 'identity.json', identity)
    return identity


def initialize(directory, role):
    manifest = read(directory / 'native/dkg-complete.json')
    if manifest['id'] != (1 if role == 'alice' else 2):
        raise RuntimeError('native participant role mismatch')
    # The client itself invokes the native verifier. A coordinator-supplied
    # boolean or receipt file is not an initialization substitute.
    native('regtest-export-recovery', directory / 'native', directory / 'recovery')
    identity = read(directory / 'identity.json') if (directory / 'identity.json').exists() else initialize_key(directory, role)
    if identity['role'] != role:
        raise RuntimeError('ETH owner role changed')
    return identity


def agreement_digest(agreement):
    return hashlib.sha256(json.dumps(agreement, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def domain():
    native = status()  # Verifies the isolated genesis and NU7 branch.
    if int(evm.rpc('eth_chainId'), 16) != evm.CHAIN:
        raise RuntimeError('owner client supports only the isolated EVM chain')
    return native


def funding(directory, terms):
    transaction = zrpc('getrawtransaction', [terms['funding_txid'], 1])
    if not transaction.get('in_active_chain') or transaction.get('confirmations', 0) < 2:
        raise RuntimeError('owner did not observe confirmed native funding')
    native_funding.observe(directory, terms, transaction)


def unspent_funding(directory, terms):
    observed = capture(directory / 'recovery')
    notes = read(Path(observed['file']))['notes']
    if not any(n['txid'] == terms['funding_txid'] and n['cmx'] == terms['pending_cmx']
               and n['value'] == terms['principal_zatoshi'] for n in notes):
        raise RuntimeError('owner did not observe the unspent agreed shared note')


def validate_agreement(directory, agreement, initial=False, prefunding=False, missing_funding=False):
    tip = domain()
    identity = read(directory / 'identity.json')
    bundle = read(directory / 'native/recovery-bundle.json')
    acknowledged = read(directory / 'native/recovery-receipt.json')
    # The receipt and envelope were produced by this participant's native
    # verifier, not received as an unauthenticated coordinator assertion.
    digest = hashlib.sha256(b'Latch recovery bundle v1\0' + json.dumps(bundle,
        sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()
    if acknowledged['durably_saved'] is not True or acknowledged['bundle_digest'] != digest or agreement['native'] != bundle['terms']:
        raise RuntimeError('ETH agreement differs from owner native recovery bundle')
    terms = bundle['terms']
    accepted_quote = directory / 'accepted-trade.json'
    if terms.get('trade') != (read(accepted_quote) if accepted_quote.exists() else None):
        raise RuntimeError('full agreement differs from locally accepted OTC quote')
    native_funding.controlled_refund_height(terms)
    fee_policy.policy(agreement)
    escrow_abi.version(agreement)
    own_field = 'recipient' if identity['role'] == 'alice' else 'maker'
    if agreement[own_field].lower() != identity['address']:
        raise RuntimeError('owner ETH address changed')
    for field in ('maker', 'recipient', 'contract'):
        if not re.fullmatch(r'0x[0-9a-fA-F]{40}', agreement[field]) or int(agreement[field], 16) == 0:
            raise RuntimeError('invalid agreed ETH address')
    expected_eth = terms['trade']['offer']['payload']['eth_amount_wei'] if 'trade' in terms else 10**16
    if (agreement['eth_chain_id'] != evm.CHAIN or type(agreement['amount_wei']) is not int
            or agreement['amount_wei'] != expected_eth):
        raise RuntimeError('unsupported agreed chain or amount')
    verify_contract(agreement)
    if agreement.get('consent_version') == 1:
        if terms.get('cross_chain_consent_required') is not True or terms['owner_pins'][identity['role']] != identity:
            raise RuntimeError('native bundle does not pin this ETH owner')
        if not re.fullmatch(r'0x[0-9a-f]{64}', agreement['eth_salt']):
            raise RuntimeError('exact agreed order salt required')
        code = bytes.fromhex(evm.rpc('eth_getCode', [agreement['contract'], 'latest'])[2:])
        if agreement['eth_code_hash'] != evm_wallet.keccak(code).hex():
            raise RuntimeError('agreed escrow code digest changed')
    elif prefunding or terms.get('cross_chain_consent_required'):
        raise RuntimeError('cross-chain consent version required')
    if not prefunding and not missing_funding:
        funding(directory, terms)
    if initial:
        now = int(evm.rpc('eth_getBlockByNumber', ['latest', False])['timestamp'], 16)
        if not now + 300 < agreement['eth_expiry'] <= now + 7200 or tip['blocks'] + 12 >= terms['refund_height']:
            raise RuntimeError('agreement outside controlled fixture time policy')
        fee_policy.require_prefunding_reserves(agreement, evm.rpc)
    return identity, terms


def consent(directory, agreement):
    identity, _ = validate_agreement(directory, agreement, initial=True, prefunding=True)
    payload = {'version': 1, 'role': identity['role'], 'agreement_digest': agreement_digest(agreement),
        'bundle_digest': read(directory / 'native/recovery-receipt.json')['bundle_digest']}
    digest = hashlib.sha256(b'Latch cross-chain funding consent v1\0' +
        json.dumps(payload, sort_keys=True, separators=(',', ':')).encode()).digest()
    # Pin the agreement before making a reusable signature available. This
    # owner's client cannot accept a replacement offer after a restart.
    save(directory / 'eth-agreement.json', agreement)
    signed = {'payload': payload, 'signature': evm_wallet.sign_digest(directory / 'ethereum', digest)}
    save(directory / 'funding-consent.json', signed)
    save(directory / 'eth-acceptance.json', {'role': identity['role'], 'address': identity['address'],
        'agreement_digest': payload['agreement_digest'], 'native_bundle_matches': True})
    return signed


def accept(directory, agreement):
    identity, _ = validate_agreement(directory, agreement, initial=True)
    save(directory / 'eth-agreement.json', agreement)
    response = {'role': identity['role'], 'address': identity['address'],
        'agreement_digest': agreement_digest(agreement), 'native_bundle_matches': True}
    save(directory / 'eth-acceptance.json', response)
    return response


def pin_order(directory, agreement, terms, order):
    if not isinstance(order, str) or not re.fullmatch(r'0x[0-9a-f]{64}', order):
        raise RuntimeError('canonical order identifier required')
    state = order_state(agreement, terms, order)
    save(directory / 'eth-order.json', {'order': order})
    return state


def observe_receipt(directory, intent, allow_reverted=False):
    observed = evm.rpc('eth_getTransactionReceipt', [intent['txid']])
    if observed is None:
        return None
    block = evm.rpc('eth_getBlockByNumber', [observed['blockNumber'], False])
    if (observed['status'] not in ('0x0','0x1') or not allow_reverted and observed['status'] != '0x1'
        or observed['transactionHash'] != intent['txid'] or not block or block['hash'] != observed['blockHash']):
        raise RuntimeError('owner transaction reverted or receipt is noncanonical')
    folder = directory / 'eth-receipts'
    folder.mkdir(mode=0o700, exist_ok=True)
    save(folder / f'{intent["txid"]}-{observed["blockHash"]}.json', observed)
    return observed


def canonical_settlement(agreement, order, action):
    signature = 'Claimed(bytes32,uint256)' if action == 'claim' else 'Refunded(bytes32)'
    event_topic = '0x' + evm_wallet.keccak(signature.encode()).hex()
    logs = evm.rpc('eth_getLogs',[{'address':agreement['contract'], 'fromBlock':'0x0',
        'toBlock':'latest','topics':[event_topic,order]}])
    if len(logs) != 1 or logs[0].get('removed',False):
        raise RuntimeError('unique canonical owner settlement unavailable')
    found = logs[0]
    receipt = evm.rpc('eth_getTransactionReceipt',[found['transactionHash']])
    block = evm.rpc('eth_getBlockByNumber',[found['blockNumber'],False])
    if not receipt or receipt['status'] != '0x1' or receipt['blockHash'] != found['blockHash'] or block['hash'] != found['blockHash']:
        raise RuntimeError('owner settlement receipt is not canonical')
    return found


def settled(directory, agreement, order, action, previous, role):
    found = canonical_settlement(agreement, order, action)
    result = {'role':role,'action':action,'txid':found['transactionHash'],'order':order,
        'new_transaction':False,'locally_signed':bool(previous),
        'settlement_via_other_relayer':not previous or previous['txid'] != found['transactionHash']}
    # A formerly canonical event can disappear and a different relayer can
    # settle the same order on the replacement branch. Preserve each validated
    # observation, but never use the old observation as current chain state.
    # Older fixed-name files remain historical and are not read for decisions.
    history = directory / 'eth-settlements'
    history.mkdir(mode=0o700, exist_ok=True)
    save(history / f'{action}-{found["transactionHash"]}-{found["blockHash"]}.json',
        dict(result, block_hash=found['blockHash'], block_number=int(found['blockNumber'],16)))
    return result


def withdraw_calldata(agreement, terms, order, address):
    v = escrow_abi.version(agreement)
    return escrow_abi.calldata(v, 'withdraw', order, local_order(agreement, terms) if v == 2 else None, to=address)


def withdrawal_attempts(directory, agreement, terms, order, address):
    """Validate every immutable withdrawal version before trusting any receipt."""
    original = directory/'eth-intent-withdraw.json'
    folder = directory/'eth-withdraw-attempts'
    extra = sorted(folder.glob('*.json')) if folder.exists() else []
    if folder.is_symlink() or len(extra)>32 or extra and not original.is_file():
        raise RuntimeError('invalid withdrawal history')
    attempts = [read(original)] if original.exists() else []
    for number,path in enumerate(extra,1):
        if path.name != f'{number:06d}.json':
            raise RuntimeError('withdrawal history sequence is incomplete')
        current = read(path)
        if current.get('withdrawal_predecessor') != attempts[-1]['txid']:
            raise RuntimeError('withdrawal history predecessor changed')
        attempts.append(current)
    expected = withdraw_calldata(agreement, terms, order, address)
    nonces = set()
    for attempt in attempts:
        tx = validate_intent(attempt)
        nonce = int(tx['nonce'],16)
        if (attempt['kind']!='withdraw' or tx['from'].lower()!=address
            or tx['to'].lower()!=agreement['contract'].lower() or tx['data']!=expected
            or int(tx.get('value','0x0'),16)!=0 or int(tx['gas'],16)!=fee_policy.policy(agreement)['gas_limits']['withdraw']
            or not 0<int(tx['gasPrice'],16)<=fee_policy.policy(agreement)['max_gas_price_wei'] or nonce in nonces):
            raise RuntimeError('withdrawal attempt differs from fixed owner action')
        nonces.add(nonce)
    return attempts


def withdraw(directory, agreement, terms, identity, order, state, fault_after_send):
    address,role = identity['address'],identity['role']
    if state != (2 if role=='alice' else 3):
        raise RuntimeError('owner withdrawal requires the agreed settlement')
    v = escrow_abi.version(agreement)
    attempts = withdrawal_attempts(directory,agreement,terms,order,address)
    successes = []
    for attempt in attempts:
        observed = observe_receipt(directory,attempt,allow_reverted=True)
        if observed and observed['status']=='0x1':
            events = [log for log in observed['logs'] if escrow_abi.withdrawn_event(v, log,
                agreement['contract'], order, address, address, agreement['amount_wei'])]
            if len(events)!=1:
                raise RuntimeError('withdrawal receipt does not pay the exact fixed owner')
            successes.append(attempt)
    if len(successes)>1:
        raise RuntimeError('multiple canonical withdrawals for one accepted order')
    if successes:
        return {'role':role,'action':'withdraw','txid':successes[0]['txid'],'order':order,
            'new_transaction':False,'locally_signed':True}
    if v == 1:
        credit = int(evm.rpc('eth_call',[{'to':agreement['contract'],
            'data':evm.calldata('credits(address)',address)},'latest']),16)
        if credit != agreement['amount_wei']:
            raise RuntimeError('owner has no exact agreed ETH credit')
    elif order_slot(agreement, terms, order) != (state, False):
        # v2 credits the order itself; PAID without a validated receipt above
        # means an unknown withdrawal, so refuse rather than guess.
        raise RuntimeError('owner has no exact agreed ETH credit')
    current = int(evm.rpc('eth_getTransactionCount',[address,'latest']),16)
    pending_nonce = int(evm.rpc('eth_getTransactionCount',[address,'pending']),16)
    intent = next((a for a in attempts if int(a['transaction']['nonce'],16)==current),None)
    pending = evm.rpc('eth_getTransactionByHash',[intent['txid']]) if intent else None
    if pending and pending.get('blockNumber') is not None:
        raise RuntimeError('withdrawal transaction/receipt observations disagree')
    if pending is None and pending_nonce != current:
        raise RuntimeError('unrelated pending nonce; refuse new withdrawal attempt')
    if intent is None:
        budget = fee_policy.require_action_budget(agreement, address, 'withdraw', evm.rpc)
        if len(attempts)>=fee_policy.policy(agreement)['withdrawal_attempt_limit']:
            raise RuntimeError('withdrawal fee or attempt limit exceeded')
        if budget['nonce'] != hex(current):
            raise RuntimeError('withdrawal nonce changed during fee checks')
        tx = {'from':address,'to':agreement['contract'],'gas':hex(budget['gas']),
            'gasPrice':budget['gas_price'],'nonce':budget['nonce'],'value':'0x0',
            'data':withdraw_calldata(agreement, terms, order, address)}
        intent = evm_wallet.sign(directory/'ethereum',tx,'withdraw')
        validate_intent(intent)
        if attempts:
            intent['withdrawal_predecessor'] = attempts[-1]['txid']
            folder = directory/'eth-withdraw-attempts'
            folder.mkdir(mode=0o700,exist_ok=True)
            path = folder/f'{len(attempts):06d}.json'
        else:
            path = directory/'eth-intent-withdraw.json'
        save(path,intent)  # Publish a complete signed version BEFORE sending.
    if pending is None and evm.rpc('eth_sendRawTransaction',[intent['raw']]) != intent['txid']:
        raise RuntimeError('withdrawal transaction identity changed')
    if fault_after_send:
        raise InjectedStop('owner-send-before-receipt')
    receipt(intent['txid'])
    if observe_receipt(directory,intent) is None:
        raise RuntimeError('withdrawal receipt disappeared')
    return {'role':role,'action':'withdraw','txid':intent['txid'],'order':order,
        'new_transaction':pending is None,'locally_signed':True}


def agreed_order_never_locked(agreement, order):
    """True only for the agreed order ID (maker and salt) with an empty slot."""
    agreed = evm.rpc('eth_call', [{'to': agreement['contract'], 'data': evm.calldata(
        'orderId(address,bytes32)', agreement['maker'], agreement['eth_salt'])}, 'latest'])
    slot = evm.rpc('eth_call', [{'to': agreement['contract'], 'data': evm.calldata('orders(bytes32)', order)}, 'latest'])
    return order == agreed and set(slot[2:]) == {'0'}


def native_recovery(directory, agreement, terms, role, order, action, fault_after_send):
    if action == 'native-refund' and agreed_order_never_locked(agreement, order):
        save(directory / 'eth-order.json', {'order': order})
        state = 0  # Checked against the expiry below; order_state rejects an empty slot.
    else:
        state = pin_order(directory, agreement, terms, order)
    mode = 'claim' if action == 'native-claim' else 'refund'
    witness = None
    if mode == 'claim':
        if state != 2:
            raise RuntimeError('native claim requires canonical ETH settlement')
        event = canonical_settlement(agreement, order, 'claim')
        witness = int(event['data'], 16).to_bytes(32, 'little').hex()
    else:
        # This owner's durable exposure history, never a peer/coordinator's
        # missing receipt, governs the no-reveal route.
        intent = directory / 'eth-intent-claim.json'
        if intent.exists() or intent.is_symlink():
            raise RuntimeError('own possible secret exposure; no native refund fallback')
        now = int(evm.rpc('eth_getBlockByNumber', ['latest', False])['timestamp'], 16)
        # State 0: the maker never locked. lock() requires refundAt to be at
        # least MIN_LOCK_SECONDS ahead, so past the agreed expiry the agreed
        # order can no longer be created, and nothing can make Alice reveal t.
        if state not in (0, 1, 3) or now < agreement['eth_expiry']:
            raise RuntimeError('native refund requires an expired or never-locked unclaimed ETH order')
        if state == 3:
            canonical_settlement(agreement, order, 'refund')
    root = native_owner.workspace(directory, role, terms,
        read(directory / 'native/recovery-bundle.json'), read(directory / 'native/recovery-receipt.json'))
    common = {'action': action, 'role': role, 'order': order,
        'coordinator_state_required': False, 'new_evm_transactions': 0,
        'client_mined_blocks': False, 'client_restored_node': False}
    if mode == 'refund' and status()['blocks'] <= terms['refund_height']:
        return dict(common, state='waiting-refund-height', refund_height=terms['refund_height'],
            new_transaction=False)
    funding_tx = native_funding.current(terms['funding_txid'])
    funding_depth = funding_tx.get('confirmations', 0) if funding_tx.get('in_active_chain') else 0
    if funding_depth < 2:
        if mode != 'claim':
            raise RuntimeError('native refund funding no longer confirmed')
        restored = native_funding.restore_published(directory, terms, fault_after_send, mine=False)
        return dict(common, state='waiting-funding-confirmations', funding_recovery=restored,
            new_transaction=restored['new_transaction'])
    native_funding.observe(directory, terms, funding_tx)
    if mode == 'refund' and auxiliary_depth(root) == 0:
        # First call: put Alice's auxiliary A on chain. R follows once A is mined.
        txid, sent = native_exit(root, 'auxiliary', mine=False)
        return dict(common, state='auxiliary-pending', txid=txid, confirmations=0, new_transaction=sent)
    txid, sent = native_exit(root, mode, witness, mine=False)
    if fault_after_send and sent:
        raise InjectedStop('native-exit-send-before-observation')
    tx = native_funding.current(txid)
    depth = tx.get('confirmations', 0) if tx.get('in_active_chain') else 0
    current_state = ('confirmed' if depth >= 2 else 'confirming' if depth else
        'pending' if txid in zrpc('getrawmempool') else 'not-observed')
    result = dict(common, state=current_state, txid=txid, confirmations=depth, new_transaction=sent)
    if depth >= 2:
        scanned = capture(root / role)
        if not any(n['txid'] == txid and n['value'] == terms['payout_zatoshi']
                   for n in read(Path(scanned['file']))['notes']):
            raise RuntimeError('owner did not decrypt the agreed native payout')
        result['received_zatoshi'] = terms['payout_zatoshi']
    return result


def execute(directory, action, request, fault_after_send=False):
    agreement = read(directory / 'eth-agreement.json')
    if read(directory / 'eth-acceptance.json')['agreement_digest'] != agreement_digest(agreement):
        raise RuntimeError('persisted ETH acceptance differs from agreement')
    identity, terms = validate_agreement(directory, agreement,
        missing_funding=action in ('restore-funding', 'native-claim'))
    role, address = identity['role'], identity['address']
    if (action in ('lock', 'refund', 'restore-funding', 'native-claim') and role != 'bob') or (action in ('claim', 'native-refund') and role != 'alice'):
        raise RuntimeError('operation not owned by this participant')
    if action in ('native-claim', 'native-refund'):
        return native_recovery(directory, agreement, terms, role, request.get('order'), action, fault_after_send)
    if action == 'restore-funding':
        # A missing native F is not permission to sign/re-fund a fresh swap.
        # Only Bob relays previously observed PUBLIC bytes after observing a
        # canonical ETH claim. Ambiguous/lost/expired EVM claims fail closed.
        order = request.get('order')
        if pin_order(directory, agreement, terms, order) != 2:
            raise RuntimeError('funding restoration requires a canonical ETH claim')
        canonical_settlement(agreement, order, 'claim')
        return native_funding.restore_published(directory, terms, fault_after_send)
    path = directory / f'eth-intent-{action}.json'
    previous = read(path) if path.exists() else None
    if action == 'lock':
        salt = request.get('salt')
        if not isinstance(salt, str) or not re.fullmatch(r'0x[0-9a-f]{64}', salt):
            raise RuntimeError('canonical salt required')
        if agreement.get('consent_version') == 1 and salt != agreement['eth_salt']:
            raise RuntimeError('lock salt differs from signed offer')
        order = evm.rpc('eth_call', [{'to': agreement['contract'],
            'data': evm.calldata('orderId(address,bytes32)', address, salt)}, 'latest'])
        save(directory / 'eth-lock-request.json', {'salt': salt, 'order': order})
    else:
        order = request.get('order')
        state = pin_order(directory, agreement, terms, order)
    if action=='withdraw':
        return withdraw(directory,agreement,terms,identity,order,state,fault_after_send)
    # Existing intents are never replaced. Validate actual signed bytes and
    # current chain receipts before treating a repeated operation as complete.
    if previous:
        tx = validate_intent(previous)
        if tx['from'].lower() != address or tx['to'].lower() != agreement['contract'].lower() or previous['kind'] != action:
            raise RuntimeError('owner signed intent context changed')
    # Anyone can relay a public witness to the fixed recipient. An earlier
    # owner call may be absent or reverted after such a relay; reconcile the
    # validated order/event before interpreting that receipt as a failure.
    if action in ('claim','refund') and state == (2 if action == 'claim' else 3):
        return settled(directory,agreement,order,action,previous,role)
    if previous:
        completed = observe_receipt(directory, previous)
        if completed:
            return {'role': role, 'action': action, 'txid': previous['txid'], 'order': order,
                'new_transaction': False, 'locally_signed': True}
    state = None if action == 'lock' else pin_order(directory, agreement, terms, order)
    now = int(evm.rpc('eth_getBlockByNumber', ['latest', False])['timestamp'], 16)
    if action == 'lock':
        if now + 300 >= agreement['eth_expiry'] or status()['blocks'] + 12 >= terms['refund_height']:
            raise RuntimeError('native/ETH window too short for owner funding')
        if not previous:
            unspent_funding(directory, terms)
        auxiliary = terms['aux_outpoint']
        # A deferred auxiliary is Alice's own unbroadcast transaction; only an
        # already-mined coin can be checked (and spent early) here.
        if not terms.get('refund_auxiliary_deferred') and zrpc('gettxout', [auxiliary['txid'], auxiliary['index'], True]) is None:
            raise RuntimeError('native refund auxiliary unavailable')
        data = evm.calldata('lock(bytes32,address,uint64,(uint256,uint256),bytes32)',
            salt, agreement['recipient'], agreement['eth_expiry'],
            f'({terms["point_x"]},{terms["point_y"]})', '0x' + agreement_digest(agreement))
        gas, value = fee_policy.policy(agreement)['gas_limits']['lock'], agreement['amount_wei']
    elif action == 'claim':
        if state != 1:
            raise RuntimeError('agreed ETH order is not claimable')
        require_reveal_window(agreement, terms)
        if not previous:
            unspent_funding(directory, terms)
            # Only public metadata enters RPC before this gate. Never use the
            # secret witness in remote estimateGas/eth_call as a preflight.
            budget = fee_policy.require_action_budget(agreement, address, action, evm.rpc)
        # Only Alice's client reads her secret. Neither coordinator nor RPC
        # signer receives it before this client accepts the exact current state.
        secret = read(directory / 'native/witness.json')['witness_uint256']
        v = escrow_abi.version(agreement)
        if v == 2 and not previous:
            # Before the first exposure only: the pinned bytecode must accept t
            # on a private throwaway node, so a verifier rejection cannot
            # publish t in a reverted claim. Never sent to the agreed chain.
            claim_precheck.verify(2, secret, terms['point_x'], terms['point_y'])
        data = escrow_abi.calldata(v, 'claim', order, local_order(agreement, terms) if v == 2 else None,
            witness=secret)
        gas, value = fee_policy.policy(agreement)['gas_limits']['claim'], 0
    elif action == 'refund':
        if state != 1 or now < agreement['eth_expiry']:
            raise RuntimeError('ETH refund not available')
        v = escrow_abi.version(agreement)
        data = escrow_abi.calldata(v, 'refund', order, local_order(agreement, terms) if v == 2 else None)
        gas, value = fee_policy.policy(agreement)['gas_limits']['refund'], 0
    else:
        raise RuntimeError('unsupported owner operation')
    if previous:
        intent = previous
        if intent['transaction']['data'] != data or int(intent['transaction'].get('value','0x0'),16) != value:
            raise RuntimeError('request differs from immutable signed intent')
    else:
        if action != 'claim':
            budget = fee_policy.require_action_budget(agreement, address, action, evm.rpc)
        if budget['gas'] != gas:
            raise RuntimeError('action gas differs from accepted limit')
        tx = {'from': address, 'to': agreement['contract'], 'gas': hex(budget['gas']),
            'gasPrice': budget['gas_price'], 'nonce': budget['nonce'],
            'value': hex(value), 'data': data}
        intent = evm_wallet.sign(directory / 'ethereum', tx, action)
        validate_intent(intent)
        save(path, intent)  # fsync BEFORE any possible first witness exposure.
    pending = evm.rpc('eth_getTransactionByHash', [intent['txid']])
    if pending is None and evm.rpc('eth_sendRawTransaction', [intent['raw']]) != intent['txid']:
        raise RuntimeError('owner transaction identity changed')
    if fault_after_send:
        raise InjectedStop('owner-send-before-receipt')
    receipt(intent['txid'])
    if observe_receipt(directory, intent) is None:
        raise RuntimeError('owner receipt disappeared')
    return {'role':role, 'action':action, 'txid':intent['txid'], 'order':order,
        'new_transaction': pending is None, 'locally_signed':True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['key-init','init','accept','consent','lock','claim','refund','withdraw','restore-funding',
        'native-claim','native-refund'])
    parser.add_argument('directory', type=Path)
    parser.add_argument('--role', choices=['alice','bob'])
    parser.add_argument('--fault-after-send', action='store_true')
    args = parser.parse_args()
    os.umask(0o077)
    directory = args.directory.resolve()
    with (directory / 'eth-client.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if args.action in ('init', 'key-init'):
            if not args.role:
                raise RuntimeError('initialization requires an owner role')
            result = (initialize_key if args.action == 'key-init' else initialize)(directory, args.role)
        else:
            raw = sys.stdin.buffer.read(65537)
            if len(raw) > 65536:
                raise RuntimeError('owner request too large')
            request = json.loads(raw)
            if not isinstance(request, dict):
                raise RuntimeError('owner request object required')
            result = (consent(directory, request) if args.action == 'consent' else
                accept(directory, request) if args.action == 'accept' else execute(directory, args.action, request, args.fault_after_send))
        print(json.dumps(result))


if __name__ == '__main__':
    try:
        main()
    except InjectedStop:
        print(json.dumps({'intentional_stop':'owner-send-before-receipt'}))
        sys.exit(75)
    except (OSError, ValueError, KeyError, RuntimeError, TypeError, subprocess.SubprocessError):
        # Untrusted RPC/errors must never print witness/raw-intent contents.
        print('Owner operation rejected; private state retained.', file=sys.stderr)
        sys.exit(1)
