#!/usr/bin/env python3
"""Verify the new readers against actual isolated EVM code/storage and faults.

No new native funding or proofs. The real local contract uses synthetic terms;
it is not a Sepolia identity/finality test. Separately, explicit RPC transcripts
check the strict public identity/clock pipeline. The real signed synthetic owner
fixture must be refused by the public preflight before any network request.
"""
import copy
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import time
import urllib.request
import fee_policy
import probe_sepolia as sepolia
import public_evm_observation as obs
import public_preflight as preflight
import public_eth_reconcile as eth_recovery
from regtest_wallet import ROOT, save
from run_native_evm_gate import calldata
import timestamp_policy
from check_public_authority import OWNER_FILES


def refuse(fn, message=None):
    try:
        fn()
    except (RuntimeError, ValueError) as error:
        if message is not None and str(error) != message:
            raise RuntimeError('unexpected refusal reason') from error
        return
    raise RuntimeError('unsafe new observation accepted')


def transcript(agreement, code):
    """Explicit model responses, NEVER offered as observed public chain data."""
    now = int(time.time())
    header = lambda n, age: {'number': hex(n), 'hash': '0x'+f'{n:064x}',
        'timestamp': hex(now-age), 'baseFeePerGas': '0x1'}
    blocks = {'0x0': dict(header(0, 1000), hash=sepolia.GENESIS),
        'finalized': header(10, 24), 'safe': header(11, 12), 'latest': header(12, 0)}
    words = obs.expected_order(agreement)
    calls = []
    def call(method, params=None):
        params = [] if params is None else params
        sepolia.read_method(method, params)
        calls.append((method, copy.deepcopy(params)))
        if method == 'eth_chainId': return hex(sepolia.CHAIN_ID)
        if method == 'eth_getBlockByNumber':
            tag = params[0]
            return blocks.get(tag) or next(b for b in blocks.values() if b['number'] == tag)
        if method == 'eth_maxPriorityFeePerGas': return '0x1'
        if method == 'eth_gasPrice': return hex(10**9)
        if method == 'eth_getCode': return code
        if method == 'eth_call': return '0x'+''.join(f'{w:064x}' for w in words)
        if method == 'eth_getTransactionCount': return '0x0'
        if method == 'eth_getBalance': return hex(10**20)
        raise RuntimeError('unexpected transcript method')
    return call, calls, blocks


def model_checks(agreement, code):
    now = int(time.time())
    model = copy.deepcopy(agreement)
    plan = timestamp_policy.build(now-10)
    model.update(execution_plan=plan, execution_plan_digest=timestamp_policy.digest(plan), eth_expiry=plan['eth_expiry'])
    model['native']['refund_lock'] = plan['native_refund_lock']
    call, calls, blocks = transcript(model, code)
    report = obs.observe(model, 'first_reveal', call, 'explicit-model-no-network')
    assert report['funding_authorized'] is False and report['reveal_authorized'] is False
    assert all(params[-1].get('requireCanonical') is True for method, params in calls
        if method in ('eth_getCode', 'eth_call'))
    # Identity refusal happens before revealing owner addresses or contract order.
    for kind in ('wrong-chain', 'wrong-genesis', 'pruned-genesis', 'finality-order'):
        call, calls, blocks = transcript(model, code)
        if kind == 'wrong-genesis': blocks['0x0']['hash'] = '0x'+'99'*32
        if kind == 'finality-order': blocks['finalized']['number'] = '0xff'
        def bad(method, params=None):
            if kind == 'wrong-chain' and method == 'eth_chainId': return '0x1'
            if kind == 'pruned-genesis' and method == 'eth_getBlockByNumber' and params[0] == '0x0':
                raise sepolia.RpcError(method, 4444)
            return call(method, params)
        refuse(lambda: obs.observe(model, 'first_reveal', bad, 'explicit-model-no-network'))
        assert not any(m in ('eth_getCode', 'eth_call', 'eth_getBalance') for m, _ in calls)
    call, calls, blocks = transcript(model, code)
    original = copy.deepcopy(blocks['latest'])
    def reorg(method, params=None):
        result = call(method, params)
        if method == 'eth_getBlockByNumber' and params[0] == original['number'] and any(m == 'eth_call' for m, _ in calls):
            return dict(result, hash='0x'+'99'*32)
        return result
    refuse(lambda: obs.observe(model, 'first_reveal', reorg, 'explicit-model-no-network'))
    call, _, blocks = transcript(model, code)
    blocks['latest']['timestamp'] = hex(now-121)
    blocks['safe']['timestamp'] = hex(now-130)
    blocks['finalized']['timestamp'] = hex(now-140)
    refuse(lambda: obs.observe(model, 'first_reveal', call, 'explicit-model-no-network'))
    # A public reader must never accept send methods or secret-bearing eth_call.
    refuse(lambda: sepolia.rpc('eth_sendRawTransaction', ['0x00']))
    refuse(lambda: sepolia.rpc('eth_estimateGas', [{'data': '0x00'}]))
    refuse(lambda: sepolia.rpc('eth_call', [{'to': model['escrow']['contract'], 'data': '0xdeadbeef'}, 'latest']))
    for kind in ('pending-nonce', 'pending-balance', 'confirmed-balance', 'fee-cap'):
        call, _, _ = transcript(model, code)
        latest = report['clock']['latest']
        def bad(method, params=None):
            if kind == 'pending-nonce' and method == 'eth_getTransactionCount' and params[-1] == 'pending': return '0x1'
            if kind == 'pending-balance' and method == 'eth_getBalance' and params[-1] == 'pending': return '0x0'
            if kind == 'confirmed-balance' and method == 'eth_getBalance' and isinstance(params[-1], dict): return '0x0'
            if kind == 'fee-cap' and method == 'eth_gasPrice': return hex(model['fee_policy']['max_gas_price_wei']+1)
            return call(method, params)
        refuse(lambda: obs.balances(model, bad, latest, 'first_reveal'))
    # Native confirmation/window checks consume only the agreed F from the
    # local decoder. These are model fields, not a fabricated public receipt.
    n = {'format': 'latch-testnet-transaction-observation-v1', 'genesis': model['native_genesis'],
        'branch': model['native_branch'], 'transaction': {'txid': model['native']['funding_txid'],
        'branch': model['native_branch'], 'version': 6}, 'status': 'mined',
        'mined_block': {'height': 100, 'hash': '11'*32, 'timestamp': now-900},
        'observed_tip': {'height': 111, 'hash': '22'*32, 'timestamp': now},
        'confirmations_by_provider': 12, 'observed_at': datetime.fromtimestamp(now, timezone.utc).isoformat(),
        'announced_upgrade': {'height': 0}}
    assert preflight.native_funding(model, n, now)['confirmations_by_provider'] == 12
    for kind in ('wrong-f', 'pending', 'eleven', 'stale', 'upgrade'):
        bad = copy.deepcopy(n)
        if kind == 'wrong-f': bad['transaction']['txid'] = '99'*32
        elif kind == 'pending': bad.update(status='mempool', mined_block=None)
        elif kind == 'eleven': bad['observed_tip']['height'] -= 1; bad['confirmations_by_provider'] -= 1
        elif kind == 'stale': bad['observed_at'] = datetime.fromtimestamp(now-121, timezone.utc).isoformat()
        else: bad['announced_upgrade']['height'] = 999
        refuse(lambda: preflight.native_funding(model, bad, now))
    return {'explicit_transcript_only': True, 'identity_before_address_disclosure': True,
        'hash_pinned_queries': True, 'changed_canonical_hash_refused': True,
        'stale_clock_refused': True, 'no_send_estimate_or_secret_call_allowed': True,
        'pending_nonce_both_balance_views_and_fee_cap_checked': True,
        'exact_native_f_confirmation_freshness_upgrade_checks': True}


def recovery_model_checks(agreement, code):
    # Recovery remains readable after BOTH original funding/reveal windows.
    model = copy.deepcopy(agreement)
    plan = timestamp_policy.build(int(time.time())-2*86400)
    model.update(execution_plan=plan, execution_plan_digest=timestamp_policy.digest(plan), eth_expiry=plan['eth_expiry'])
    model['native']['refund_lock'] = plan['native_refund_lock']
    call, calls, _ = transcript(model, code)
    report = obs.observe_recovery(model, call, 'explicit-model-no-network')
    assert not report['prior_exposure_excluded'] and not report['opening_obtained'] and not report['send_authorized']
    assert not any(m in ('eth_getTransactionCount', 'eth_getBalance', 'eth_gasPrice') for m, _ in calls)
    # A contradictory lifecycle is refused, but a checked claim response must
    # already have been handed to the durable recorder before the later failure.
    call, _, blocks = transcript(model, code)
    recorded = []
    def inconsistent(method, params=None):
        if method == 'eth_call':
            words = obs.expected_order(model)
            words[4] = 2 if params[-1]['blockHash'] == blocks['finalized']['hash'] else 3
            return '0x'+''.join(f'{w:064x}' for w in words)
        return call(method, params)
    refuse(lambda: obs.observe_recovery(model, inconsistent, 'explicit-model-no-network',
        lambda label, state: recorded.append((label, state))))
    assert recorded[0][1]['state'] == 2 and recorded[1][1]['state'] == 3
    return {'expired_windows_do_not_block_recovery': True,
        'no_new_action_nonce_or_balance_gate': True, 'contradictory_terminal_states_refused': True,
        'checked_claim_recorded_before_later_failure': True, 'prior_exposure_never_excluded': True}


def check(root, fixture):
    source = fixture/'coordinator'
    agreement = json.loads((source/'conditional-proposal.json').read_text())['agreement']
    root.mkdir(mode=0o700)
    # Calls the real native verifier (proofs, native receipts, both ECDSA consents)
    # and then refuses synthetic provenance, without making a network request.
    original = sepolia.ReadOnlyRpc
    def network_forbidden(*args, **kwargs):
        raise AssertionError('synthetic fixture reached public network initialization')
    sepolia.ReadOnlyRpc = network_forbidden
    try:
        refuse(lambda: preflight.preflight(source/'native-recovery.json', source/'conditional-proposal.json',
            source/'conditional-consents.json', 'funding', root/'must-not-exist', sepolia.ENDPOINT),
            'synthetic inputs cannot enter public execution observations')
        assert not (root/'must-not-exist').exists()
        copied_owner = root/'owner'; copied_owner.mkdir(mode=0o700)
        for name in OWNER_FILES:
            shutil.copyfile(fixture/'alice'/name, copied_owner/name); os.chmod(copied_owner/name, 0o600)
        refuse(lambda: eth_recovery.observe(copied_owner, source/'conditional-consents.json'),
            'synthetic inputs cannot enter public ETH recovery')
        assert not (copied_owner/'public-eth-observations').exists()
    finally:
        sepolia.ReadOnlyRpc = original
    artifact = json.loads((ROOT/'.local/forge-out/PointEscrow.sol/PointEscrow.json').read_text())
    code = artifact['deployedBytecode']['object']
    if not code.startswith('0x'): code = '0x'+code
    assert '0x'+obs.keccak(bytes.fromhex(code[2:])).hex() == agreement['escrow']['runtime_code_hash']
    models = model_checks(agreement, code)
    recovery_models = recovery_model_checks(agreement, code)
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0)); port = sock.getsockname()[1]
    def rpc(method, params=None):
        req = urllib.request.Request(f'http://127.0.0.1:{port}', json.dumps({
            'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params or []}).encode(),
            {'Content-Type': 'application/json'})
        with urllib.request.urlopen(req, timeout=10) as response: value = json.load(response)
        if 'error' in value: raise RuntimeError('owned local RPC error')
        return value['result']
    with (root/'anvil.log').open('x') as log:
        process = subprocess.Popen(['anvil', '--host', '127.0.0.1', '--port', str(port),
            '--chain-id', str(sepolia.CHAIN_ID), '--silent'], stdout=log, stderr=log)
        save(root/'process.json', {'pid': process.pid, 'port': port, 'scope': 'owned ephemeral isolated observation check'})
        try:
            for _ in range(100):
                if process.poll() is not None: raise RuntimeError('owned Anvil exited')
                try:
                    if rpc('eth_chainId') == hex(sepolia.CHAIN_ID): break
                except OSError: pass
                time.sleep(.1)
            else: raise RuntimeError('owned Anvil startup timeout')
            # Same chain ID cannot make an isolated genesis pass the public gate.
            refuse(lambda: sepolia.observe(rpc, 'owned-isolated-node'))
            bob, alice = rpc('eth_accounts')[:2]
            def send(tx):
                txid = rpc('eth_sendTransaction', [tx])
                for _ in range(100):
                    receipt = rpc('eth_getTransactionReceipt', [txid])
                    if receipt is not None:
                        if receipt['status'] != '0x1': raise RuntimeError('local observation fixture transaction failed')
                        return receipt
                    time.sleep(.05)
                raise RuntimeError('local observation fixture receipt timeout')
            deployed = send({'from': bob, 'data': artifact['bytecode']['object'], 'gas': hex(5_000_000)})
            local = copy.deepcopy(agreement)
            local['escrow']['contract'] = deployed['contractAddress']
            local.update(maker=bob, recipient=alice)
            local['eth_expiry'] = int(rpc('eth_getBlockByNumber', ['latest', False])['timestamp'], 16)+3600
            def blocks():
                b = sepolia.block('latest', rpc)
                # Explicit test stand-in for finalized label, only for the lower
                # state reader. Anvil cannot prove public consensus finality.
                return {'provider_finalized': b, 'latest': b}
            empty = blocks()
            before = obs.inspect_escrow(local, rpc, empty, 'funding')
            assert obs.inspect_escrow(local, rpc, empty, 'recovery')['states']['latest']['state'] == 0
            obs.balances(local, rpc, empty['latest'], 'funding')
            bad = copy.deepcopy(local); bad['escrow']['runtime_code_hash'] = '0x'+'22'*32
            refuse(lambda: obs.inspect_escrow(bad, rpc, empty, 'funding'))
            locked = send({'from': bob, 'to': local['escrow']['contract'], 'value': hex(local['amount_wei']),
                'gas': hex(700_000), 'data': calldata('lock(bytes32,address,uint64,(uint256,uint256),bytes32)',
                local['escrow']['salt'], alice, local['eth_expiry'],
                f'({local["point_x"]},{local["point_y"]})', '0x'+obs.digest(local))})
            assert locked['logs'][0]['topics'][1] == before['order_id']
            current = blocks()
            obs.inspect_escrow(local, rpc, current, 'first_reveal')
            assert obs.inspect_escrow(local, rpc,
                {'provider_finalized': empty['latest'], 'latest': current['latest']}, 'recovery')['states']['latest']['state'] == 1
            refuse(lambda: obs.inspect_escrow(local, rpc, current, 'eth_lock'))
            refuse(lambda: obs.inspect_escrow(local, rpc,
                {'provider_finalized': empty['latest'], 'latest': current['latest']}, 'first_reveal'))
            bad = copy.deepcopy(local); bad['amount_wei'] += 1
            refuse(lambda: obs.inspect_escrow(bad, rpc, current, 'first_reveal'))
            obs.balances(local, rpc, current['latest'], 'first_reveal')
            # Separate purely local order with explicit public test scalar1.
            # This exercises the terminal reader against real contract storage,
            # not the native agreement or any retained owner's adaptor opening.
            pallas = (ROOT/'contracts/src/Pallas.sol').read_text()
            claimed_order = copy.deepcopy(local)
            claimed_order['escrow']['salt'] = '0x'+'91'*32
            claimed_order['point_x'] = re.search(r'GX = (0x[0-9a-f]+);', pallas)[1]
            claimed_order['point_y'] = re.search(r'GY = (0x[0-9a-f]+);', pallas)[1]
            send({'from': bob, 'to': local['escrow']['contract'], 'value': hex(local['amount_wei']),
                'gas': hex(700_000), 'data': calldata('lock(bytes32,address,uint64,(uint256,uint256),bytes32)',
                claimed_order['escrow']['salt'], alice, local['eth_expiry'],
                f'({claimed_order["point_x"]},{claimed_order["point_y"]})', '0x'+obs.digest(claimed_order))})
            claimed = send({'from': bob, 'to': local['escrow']['contract'], 'gas': hex(1_000_000),
                'data': calldata('claim(bytes32,uint256)', obs.order_id(claimed_order), 1)})
            history_root = root/'history'; history_root.mkdir(mode=0o700)
            interrupted = history_root/('01'*16); interrupted.mkdir(mode=0o700)
            save(interrupted/'intent.json', {'agreement_digest': obs.digest(claimed_order)})
            def record(label, state):
                save(interrupted/(label+'.json'), {'agreement_digest': obs.digest(claimed_order), 'state': state})
            terminal = obs.inspect_escrow(claimed_order, rpc, blocks(), 'recovery', record)
            assert terminal['states']['latest']['state'] == 2
            # Simulate no final report after RPC/clock failure; the exact checked
            # claim state was already persisted by the production callback path.
            prior = eth_recovery.history(history_root, obs.digest(claimed_order))
            assert prior['claim_seen_before'] and prior['incomplete'] == 1
            absent = history_root/('02'*16); absent.mkdir(mode=0o700)
            save(absent/'intent.json', {'agreement_digest': obs.digest(claimed_order)})
            save(absent/'latest.json', {'agreement_digest': obs.digest(claimed_order),
                'state': dict(terminal['states']['latest'], state=0)})
            assert eth_recovery.history(history_root, obs.digest(claimed_order))['claim_seen_before']
            rpc('anvil_setBalance', [alice, '0x0']); rpc('evm_mine')
            refuse(lambda: obs.balances(local, rpc, blocks()['latest'], 'first_reveal'))
            rpc('evm_setNextBlockTimestamp', [local['eth_expiry']]); rpc('evm_mine')
            refunded = send({'from': bob, 'to': local['escrow']['contract'], 'gas': hex(200_000),
                'data': calldata('refund(bytes32)', before['order_id'])})
            refuse(lambda: obs.inspect_escrow(local, rpc, blocks(), 'first_reveal'))
            assert obs.inspect_escrow(local, rpc, blocks(), 'recovery')['states']['latest']['state'] == 3
            withdrawn = send({'from': bob, 'to': local['escrow']['contract'], 'gas': hex(200_000),
                'data': calldata('withdraw(address)', bob)})
            save(root/'local-transactions.json', {'deploy': deployed, 'lock': locked,
                'refund': refunded, 'withdraw': withdrawn, 'separate_test_order_claim': claimed})
            return {'scope': 'actual isolated EVM reader tests plus explicitly modeled public identity/clock responses',
                'signed_synthetic_fixture_refused_before_network': True, 'synthetic_native_inputs': True,
                'same_chain_id_wrong_genesis_refused': True,
                'actual_runtime_hash_and_empty_locked_refunded_states_checked': True,
                'exact_amount_terms_commitment_and_local_order_id_checked': True,
                'lock_not_finalized_refused': True, 'actual_insufficient_reserve_refused': True,
                'local_refund_withdrawal_completed': True, 'public_network': False,
                'public_finality_verified': False, 'public_funding_authorized': False,
                'transcript_checks': models, 'recovery_transcript_checks': recovery_models,
                'actual_empty_locked_claimed_refunded_recovery_readers': True,
                'partial_claim_history_survives_later_negative_observation': True,
                'synthetic_public_recovery_refused_before_network': True}
        finally:
            process.terminate()
            try: process.wait(timeout=10)
            except subprocess.TimeoutExpired: process.kill(); process.wait()
            save(root/'process-ended.json', {'pid': process.pid, 'exit_code': process.returncode})


if __name__ == '__main__':
    os.umask(0o077)
    print(json.dumps(check(*(Path(p).resolve() for p in sys.argv[1:3])), indent=2))
