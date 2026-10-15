#!/usr/bin/env python3
"""Real signed ETH success/refund/withdrawal on a fresh owned isolated EVM.

Uses copied signed synthetic native agreements; no native funds, public RPC or
new proofs. The test installs the exact existing compiled runtime at the agreed
address and models finality labels using actual isolated block hashes. This is
not a public deployment, positive public preflight or atomic settlement test.
"""
import copy
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import time
import urllib.request
import public_authority as authority
import public_eth_delivery as delivery
import public_eth_outgoing as out
import public_evm_observation as eth
import probe_sepolia as sepolia
from regtest_wallet import ROOT, save
from testnet_wallet import read
from check_public_authority import refuses


def recovery_models(agreement, code):
    from check_public_observation import transcript
    import timestamp_policy
    model = copy.deepcopy(agreement)
    plan = timestamp_policy.build(int(time.time())-2*86400)
    model.update(execution_plan=plan, execution_plan_digest=timestamp_policy.digest(plan), eth_expiry=plan['eth_expiry'])
    model['native']['refund_lock'] = plan['native_refund_lock']
    for role, action, state in (('bob', 'refund', 1), ('bob', 'withdraw', 3), ('alice', 'withdraw', 2)):
        base, calls, blocks = transcript(model, code)
        def call(method, params=None):
            if method == 'eth_call':
                sepolia.read_method(method, params)
                if params[0]['data'].startswith(eth.CREDIT_SELECTOR):
                    return '0x'+f'{model["amount_wei"] if action == "withdraw" else 0:064x}'
                words = eth.expected_order(model); words[4] = state
                return '0x'+''.join(f'{w:064x}' for w in words)
            return base(method, params)
        observed = eth.observe_recovery(model, call, 'explicit-model-only', action=action, role=role)
        assert observed['action_checks']['action'] == action
        for fault in ('other-credit', 'pending-nonce', 'mismatched-state', 'stale-clock'):
            def bad(method, params=None):
                if fault == 'pending-nonce' and method == 'eth_getTransactionCount' and params[-1] == 'pending': return '0x1'
                if fault == 'stale-clock' and method == 'eth_getBlockByNumber':
                    value = copy.deepcopy(call(method, params)); value['timestamp'] = hex(int(value['timestamp'], 16)-10000)
                    return value
                if method == 'eth_call':
                    if fault == 'other-credit' and params[0]['data'].startswith(eth.CREDIT_SELECTOR): return '0x'+f'{2*model["amount_wei"]:064x}'
                    if fault == 'mismatched-state' and params[0]['data'].startswith('0x9c3f1e90'):
                        words = eth.expected_order(model); words[4] = 1
                        if params[-1]['blockHash'] == blocks['latest']['hash']: words[4] = 2
                        return '0x'+''.join(f'{w:064x}' for w in words)
                return call(method, params)
            refuses(lambda: eth.observe_recovery(model, bad, 'explicit-model-only', action=action, role=role), '')
    return {'explicit_model_only': True, 'expired_window_recovery_action_checks': True,
        'other_credit_pending_nonce_inconsistent_state_stale_clock_refused': True}


def check(root, fixture):
    root.mkdir(mode=0o700)
    if read(fixture/'coordinator/native-recovery.json')['synthetic_inputs'] is not True:
        raise RuntimeError('explicit synthetic fixture required')
    for role in ('alice', 'bob'):
        shutil.copytree(fixture/role, root/role)
        save(root/role/'both-consents.json', read(fixture/'coordinator/conditional-consents.json'))
    with authority.owner_locked(root/'bob'):
        files, checked, _, _ = out.context(root/'bob', root/'bob/both-consents.json')
    agreement = files['proposal']['agreement']; target = agreement['escrow']['contract']
    artifact = json.loads((ROOT/'.local/forge-out/PointEscrow.sol/PointEscrow.json').read_text())
    code = '0x'+artifact['deployedBytecode']['object'].removeprefix('0x')
    assert '0x'+eth.keccak(bytes.fromhex(code[2:])).hex() == agreement['escrow']['runtime_code_hash']
    models = recovery_models(agreement, code)
    assert eth.CREDIT_SELECTOR == '0xfe5ff468'
    sepolia.read_method('eth_call', [{'to': target, 'data': eth.CREDIT_SELECTOR+'0'*24+agreement['maker'][2:]}, 'latest'])
    for payload in ('0x63f44968'+'00'*64, eth.CREDIT_SELECTOR+'1'*64):
        refuses(lambda: sepolia.read_method('eth_call', [{'to': target, 'data': payload}, 'latest']), 'getters')
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0)); port = sock.getsockname()[1]
    endpoint = f'http://127.0.0.1:{port}'
    def rpc(method, params=None):
        req = urllib.request.Request(endpoint, json.dumps({'jsonrpc': '2.0', 'id': 1,
            'method': method, 'params': params or []}).encode(), {'Content-Type': 'application/json'})
        with urllib.request.urlopen(req, timeout=15) as response: result = json.load(response)
        if 'error' in result: raise RuntimeError('owned local RPC error')
        return result['result']
    def blocks():
        b = sepolia.block('latest', rpc)
        return {'latest': b, 'provider_finalized': b, 'provider_safe': b}
    def observe(owner, kind, call=rpc):
        with authority.owner_locked(owner):
            f, c, caller, _ = out.context(owner, owner/'both-consents.json', kind)
            directory, binding = out.workspace(owner, f, c, caller['role'])
            action, value = out.decision(directory, binding, agreement, kind)
            _, verified, decoded = delivery.retained(action, value, f, c)
            record = delivery.folder(action, 'receipt-observations', delivery.identity(value, verified))
            save(record/'intent.json', {'isolated_check': True})
            result = delivery.inspect_receipt(agreement, value, decoded, call, blocks(),
                lambda label, data: save(record/(label+'.json'), data))
            save(record/'report.json', result)
            return result
    def prepare(owner, kind):
        with authority.owner_locked(owner):
            f, c, caller, _ = out.context(owner, owner/'both-consents.json', kind)
            directory, binding = out.workspace(owner, f, c, caller['role'])
            b = blocks()
            if kind in ('refund', 'withdraw'):
                escrow = eth.inspect_escrow(agreement, rpc, b, 'recovery')
                checks = eth.recovery_action(agreement, rpc, b, escrow, caller['role'], kind, b['latest']['timestamp'])
                reserve = checks['reserve']
                out.require_recovery_action(kind, {'action_checks': checks, 'claim_seen_ever': False,
                    'verified_native_opening_available': False})
            else:
                eth.inspect_escrow(agreement, rpc, b, out.PHASE[kind])
                reserve = eth.action_reserve(agreement, rpc, b['latest'], caller['role'], kind)
            action = out.commit(directory, binding, agreement, kind, reserve,
                {'owned_isolated_evm': True, 'public_preflight': False})
            result = out.finish(owner, directory, binding, f, c, kind)
            return action, out.decision(directory, binding, agreement, kind)[1], f, c, result
    def guard(value, verified):
        # Actual isolated transaction observation precedes a new attempt. A
        # found pending/mined transaction is monitored rather than sent again.
        if rpc('eth_getTransactionByHash', [verified['txid']]) is not None:
            raise RuntimeError('exact transaction already observed; no repeat send')
        tx = value['transaction_base']; role = 'alice' if tx['from'] == agreement['recipient'] else 'bob'
        b = blocks(); action = value['kind']
        phase = out.PHASE[action] if action in out.PHASE else 'recovery'
        escrow = eth.inspect_escrow(agreement, rpc, b, phase)
        if action in ('refund', 'withdraw'):
            reserve = eth.recovery_action(agreement, rpc, b, escrow, role, action, b['latest']['timestamp'])['reserve']
        else: reserve = eth.action_reserve(agreement, rpc, b['latest'], role, action)
        if (int(tx['nonce'], 16) != reserve['nonce'] or int(tx['gasPrice'], 16) < b['latest']['base_fee_wei']):
            raise RuntimeError('retained nonce/fee not executable')
    def send(prepared):
        action, value, f, c, _ = prepared
        with authority.owner_locked(action.parent.parent):
            return delivery.send_once(action, value, f, c,
                lambda raw: rpc('eth_sendRawTransaction', [raw]), guard)
    def credit(role):
        return int(rpc('eth_call', [{'to': target, 'data': eth.CREDIT_SELECTOR+'0'*24+
            agreement['owners'][role]['address'][2:]}, 'latest']), 16)
    with (root/'anvil.log').open('x') as log:
        process = subprocess.Popen(['anvil', '--host', '127.0.0.1', '--port', str(port),
            '--chain-id', str(sepolia.CHAIN_ID), '--timestamp', str(agreement['execution_plan']['created_at']),
            '--silent'], stdout=log, stderr=log)
        save(root/'process.json', {'pid': process.pid, 'port': port, 'scope': 'owned ephemeral ETH delivery check'})
        try:
            for _ in range(100):
                if process.poll() is not None: raise RuntimeError('owned Anvil exited')
                try:
                    if rpc('eth_chainId') == hex(sepolia.CHAIN_ID): break
                except OSError: pass
                time.sleep(.1)
            else: raise RuntimeError('owned Anvil startup timeout')
            refuses(lambda: sepolia.observe(rpc, 'owned-isolated-node'), 'genesis mismatch')
            rpc('anvil_setCode', [target, code])
            for role in ('alice', 'bob'):
                rpc('anvil_setBalance', [agreement['owners'][role]['address'], hex(20*10**18)])
            rpc('evm_mine')
            for role in ('alice', 'bob'):
                owner = root/role
                out.operate('init', owner, owner/'both-consents.json')
                refuses(lambda: out.operate('prepare', owner, owner/'both-consents.json', endpoint,
                    'withdraw' if role == 'alice' else 'refund'), 'synthetic inputs')
                with authority.owner_locked(owner):
                    refuses(lambda: delivery.observe_locked(owner, owner/'both-consents.json',
                        'withdraw', endpoint), 'synthetic inputs')
            locked = prepare(root/'bob', 'lock'); assert send(locked)['status'] == 'submitted'
            assert observe(root/'bob', 'lock')['state'] == 'confirmed-by-provider'
            snapshot = rpc('evm_snapshot')
            shutil.copytree(root/'bob', root/'refund-bob')
            # Early refund refused on the actual still-locked contract.
            b = blocks(); escrow = eth.inspect_escrow(agreement, rpc, b, 'recovery')
            refuses(lambda: eth.recovery_action(agreement, rpc, b, escrow, 'bob', 'refund',
                b['latest']['timestamp']), 'timestamp not mature')
            claim = prepare(root/'alice', 'claim')
            action, value, f, c, _ = claim
            # The exact owned child submits the real signed claim then SIGKILLs
            # itself before the delivery callback can return/checkpoint.
            guard(value, claim[-1]['checked'])
            worker = r'''
import json,os,signal,sys,urllib.request
from pathlib import Path
import public_authority as authority
import public_eth_outgoing as out
import public_eth_delivery as delivery
owner=Path(sys.argv[1]); endpoint=sys.argv[2]
assert endpoint.startswith('http://127.0.0.1:')
def send(raw):
 req=urllib.request.Request(endpoint,json.dumps({'jsonrpc':'2.0','id':1,'method':'eth_sendRawTransaction','params':[raw]}).encode(),{'Content-Type':'application/json'})
 with urllib.request.urlopen(req,timeout=15) as response: result=json.load(response)
 if 'error' in result: raise RuntimeError('isolated submit failed')
 os.kill(os.getpid(),signal.SIGKILL)
with authority.owner_locked(owner):
 f,c,caller,_=out.context(owner,owner/'both-consents.json','claim')
 d,b=out.workspace(owner,f,c,'alice'); a,v=out.decision(d,b,f['proposal']['agreement'],'claim')
 delivery.send_once(a,v,f,c,send,lambda *_:None)
'''
            child = subprocess.run([sys.executable, '-c', worker, str(root/'alice'), endpoint],
                env=dict(os.environ, PYTHONPATH=str(ROOT/'scripts')), capture_output=True, timeout=120)
            if child.returncode != -signal.SIGKILL:
                raise RuntimeError('claim did not reach actual post-submit SIGKILL boundary')
            attempts = list((action/'send-attempts').glob('*/intent.json'))
            assert len(attempts) == 1 and not (attempts[0].parent/'result.json').exists()
            assert observe(root/'alice', 'claim')['state'] == 'confirmed-by-provider'
            refuses(lambda: send(claim), 'already observed')
            assert len(list((action/'send-attempts').glob('*/intent.json'))) == 1
            assert credit('alice') == agreement['amount_wei']
            # Known opening or claim history prevents original-asset fallback.
            for key in ('claim_seen_ever', 'verified_native_opening_available'):
                model = {'action_checks': {'action': 'refund'}, 'claim_seen_ever': False,
                    'verified_native_opening_available': False}; model[key] = True
                refuses(lambda: out.require_recovery_action('refund', model), 'forbids ETH refund')
            withdrawal = prepare(root/'alice', 'withdraw')
            a, v, _, _, _ = withdrawal
            # Same value with another recipient is not accepted signed intent.
            original = (a/'decision.json').read_bytes(); changed = read(a/'decision.json')
            changed['calldata_prefix'] = changed['calldata_prefix'][:-40]+agreement['maker'][2:]
            (a/'decision.json').write_text(json.dumps(changed))
            try: refuses(lambda: out.operate('inspect', root/'alice', root/'alice/both-consents.json',
                action='withdraw'), 'decision differs')
            finally: (a/'decision.json').write_bytes(original)
            before = int(rpc('eth_getBalance', [agreement['recipient'], 'latest']), 16)
            assert send(withdrawal)['status'] == 'submitted'
            alice_paid = observe(root/'alice', 'withdraw'); assert alice_paid['withdrawal_verified']
            receipt = rpc('eth_getTransactionReceipt', [alice_paid['txid']])
            fee = int(receipt['gasUsed'], 16)*int(receipt['effectiveGasPrice'], 16)
            assert int(rpc('eth_getBalance', [agreement['recipient'], 'latest']), 16) == before+agreement['amount_wei']-fee
            assert credit('alice') == 0
            def missing_event(method, params=None):
                result = rpc(method, params)
                if method == 'eth_getTransactionReceipt' and result is not None: result['logs'] = []
                return result
            refuses(lambda: observe(root/'alice', 'withdraw', missing_event), 'lacks exact event')
            # Completed raw replay needs no signing key, and cannot redirect the withdrawal.
            (root/'alice/ethereum').rename(root/'alice/ethereum-offline')
            policy = '(version 1)(allow default)(deny network*)'+''.join(
                '(deny file-read* file-write* (subpath '+json.dumps(str(path))+'))'
                for path in (fixture, root/'bob', root/'refund-bob', root/'alice/ethereum-offline', root/'alice/setup-round1.json'))
            replay = subprocess.run(['/usr/bin/sandbox-exec', '-p', policy, sys.executable,
                str(ROOT/'scripts/public_eth_outgoing.py'), 'resume', str(root/'alice'),
                str(root/'alice/both-consents.json'), '--action', 'withdraw'], capture_output=True, text=True, timeout=120)
            assert replay.returncode == 2 and json.loads(replay.stdout)['raw_bytes_reused']
            # Controlled local fork removes claim/withdrawal, but never erases
            # Alice's decision or previously checked receipt history.
            assert rpc('evm_revert', [snapshot])
            assert observe(root/'alice', 'withdraw')['state'] == 'unobserved-by-provider'
            assert out.operate('init', root/'alice', root/'alice/both-consents.json')['local_claim_may_be_exposed']
            assert list((a/'receipt-observations').glob('*/checked-receipt.json'))
            rpc('evm_setNextBlockTimestamp', [agreement['eth_expiry']+61]); rpc('evm_mine')
            refunded = prepare(root/'refund-bob', 'refund'); assert send(refunded)['status'] == 'submitted'
            assert observe(root/'refund-bob', 'refund')['state'] == 'confirmed-by-provider'
            assert credit('bob') == agreement['amount_wei']
            bob_withdrawal = prepare(root/'refund-bob', 'withdraw')
            before = int(rpc('eth_getBalance', [agreement['maker'], 'latest']), 16)
            assert send(bob_withdrawal)['status'] == 'submitted'
            bob_paid = observe(root/'refund-bob', 'withdraw'); assert bob_paid['withdrawal_verified']
            receipt = rpc('eth_getTransactionReceipt', [bob_paid['txid']])
            fee = int(receipt['gasUsed'], 16)*int(receipt['effectiveGasPrice'], 16)
            assert int(rpc('eth_getBalance', [agreement['maker'], 'latest']), 16) == before+agreement['amount_wei']-fee
            assert credit('bob') == 0
            report = {'scope': 'actual signed isolated ETH execution using synthetic native agreements; modeled finality labels',
                'recovery_policy_transcripts': models,
                'claim_success_withdrawal': alice_paid, 'refund_withdrawal': bob_paid,
                'actual_sigkill_after_claim_submission_before_checkpoint': True,
                'exact_receipt_recovery_without_resubmission': True,
                'actual_recipient_balance_increase_equals_credit_minus_gas_both_roles': True,
                'mature_refund_and_exact_dedicated_credit_checked': True,
                'changed_withdrawal_destination_and_missing_event_refused': True,
                'known_opening_or_claim_history_refuses_refund': True,
                'local_reorg_preserves_claim_exposure_and_previous_receipts': True,
                'withdrawal_replay_with_network_keys_and_peer_roots_denied': True,
                'public_synthetic_and_wrong_genesis_guards_pass': True,
                'compiled_runtime_installed_in_owned_evm': True, 'public_deployment': False,
                'public_transfers': False, 'new_native_proofs': 0, 'public_funded_preflight': False}
            save(root/'report.json', report)
            return report
        finally:
            if process.poll() is None: process.terminate()
            try: process.wait(timeout=10)
            except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=10)
            save(root/'process.json', {'pid': process.pid, 'port': port,
                'scope': 'owned ephemeral ETH delivery check', 'stopped': True, 'exit_code': process.returncode})


if __name__ == '__main__':
    os.umask(0o077)
    print(json.dumps(check(*(Path(p).resolve() for p in sys.argv[1:3])), indent=2))
