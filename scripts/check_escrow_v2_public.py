#!/usr/bin/env python3
"""PointEscrowV2 through the PUBLIC client code paths on an owned, isolated EVM.

No Sepolia request, no key, no native proof. A synthetic v2 agreement in the
public agreement shape is settled with Anvil's unlocked accounts on chain id
11155111. Every read goes through the read-only Sepolia allow-list first.
Checks, against the real v2 contract:
  - the exact calldata from public_eth_outgoing.prefix() for lock, claim,
    refund and withdraw executes, and any altered order word reverts;
  - the observation reader in every phase, including the PAID flag, and the
    comb-table code pin;
  - recovery_action readiness for refund and withdraw, and refusal after PAID;
  - Bob's opening capture from the real claim transaction;
  - public_eth_delivery.expected_event against the real receipts;
  - the v2 deployment specification and policy pins.
"""
import copy
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import urllib.request
import escrow_abi
import fee_policy
import probe_sepolia as sepolia
import public_agreement
import public_deploy
import public_eth_delivery as delivery
import public_eth_outgoing as out
import public_evm_observation as obs
import public_opening as opening

# pasta_curves vector (contracts/test/PallasVectors.t.sol, vector 3): public test scalar.
K = 0x0c67421df8d3ae89643f1af5d0ab86613c17f2cda8835e3914efcaa5805b3611
KX = '0x027c4ff5156586fb9742a9faace499f6a14533f3c05119a27c8e0990d57a74f1'
KY = '0x0e0d47ab8f5bc4f2666f7a4fac65c57c7e8a7ed7ebbb1b9a8a5ff479c93bf235'
# secp256k1 generator: the public key of the well-known test scalar 1 (no secret used).
G_PUBLIC = ('0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
            '483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8')


def refuse(fn):
    try:
        fn()
    except (RuntimeError, ValueError):
        return True
    raise RuntimeError('unsafe v2 public input accepted')


def check(root):
    root.mkdir(mode=0o700)
    policy = public_agreement.validate_policy(2)
    assert public_agreement.validate_policy()['escrow']['runtime_code_hash'] != policy['escrow']['runtime_code_hash']
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    url = f'http://127.0.0.1:{port}'
    allowed = []

    def raw(method, params):
        req = urllib.request.Request(url, json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method,
            'params': params}).encode(), {'Content-Type': 'application/json'})
        with urllib.request.urlopen(req, timeout=10) as response:
            value = json.load(response)
        if 'error' in value:
            raise RuntimeError('owned local RPC error')
        return value['result']

    def rpc(method, params=None):
        # The readers must stay inside the public read-only allow-list.
        params = [] if params is None else params
        sepolia.read_method(method, params)
        allowed.append(method)
        return raw(method, params)

    def send(tx):
        txid = raw('eth_sendTransaction', [tx])
        for _ in range(100):
            receipt = raw('eth_getTransactionReceipt', [txid])
            if receipt is not None:
                return receipt
            time.sleep(.05)
        raise RuntimeError('local receipt timeout')

    def ok(tx):
        receipt = send(tx)
        if receipt['status'] != '0x1':
            raise RuntimeError('expected success')
        return receipt

    def reverts(tx):
        try:
            raw('eth_call', [tx, 'latest'])
        except RuntimeError:
            return True
        raise RuntimeError('altered v2 call did not revert')

    def blocks():
        b = sepolia.block('latest', rpc)
        # Explicit stand-in for the finalized label in this lower-level reader test.
        return {'provider_finalized': b, 'latest': b}

    process = subprocess.Popen(['anvil', '--host', '127.0.0.1', '--port', str(port), '--chain-id',
        str(sepolia.CHAIN_ID), '--silent'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(100):
            try:
                if raw('eth_chainId', []) == hex(sepolia.CHAIN_ID):
                    break
            except OSError:
                time.sleep(.1)
        else:
            raise RuntimeError('owned Anvil startup timeout')
        bob, alice, relayer = raw('eth_accounts', [])[:3]
        deployed = ok({'from': bob, 'data': escrow_abi.creation_code(2), 'gas': hex(5_000_000)})
        contract = deployed['contractAddress']
        code = raw('eth_getCode', [contract, 'latest'])
        assert '0x' + obs.keccak(bytes.fromhex(code[2:])).hex() == policy['escrow']['runtime_code_hash']
        now = int(raw('eth_getBlockByNumber', ['latest', False])['timestamp'], 16)

        def agreement(salt):
            return {'eth_chain_id': sepolia.CHAIN_ID, 'escrow_version': 2,
                'escrow': {'contract': contract, 'salt': salt, 'runtime_code_hash': policy['escrow']['runtime_code_hash'],
                    'creation_code_hash': policy['escrow']['creation_code_hash'],
                    'table_code_hash': policy['escrow']['table_code_hash'], 'constructor_arguments': '0x'},
                'maker': bob, 'recipient': alice, 'amount_wei': 10**15, 'eth_expiry': now + 3600,
                'point_x': KX, 'point_y': KY, 'owners': {'alice': {'address': alice}, 'bob': {'address': bob}},
                'fee_policy': fee_policy.default(), 'execution_plan': {'policy': {'clock_error_seconds': 60}}}

        def event(a, kind, sender, receipt, data_hex=None):
            topics, data = delivery.expected_event(a, {'kind': kind, 'transaction_base': {'from': sender}},
                {'input': data_hex or ''})
            logs = [log for log in receipt['logs'] if log['address'].lower() == contract.lower()]
            assert len(logs) == 1 and logs[0]['topics'] == topics and logs[0]['data'] == data, kind

        def altered_words(data, words):
            # Flip one bit in each order word (words 1..7 after the id).
            return [data[:10 + 64 * w] + format(int(data[10 + 64 * w:74 + 64 * w], 16) ^ 1, '064x')
                    + data[74 + 64 * w:] for w in words]

        # --- success path ---
        a = agreement('0x' + '51' * 32)
        empty = blocks()
        assert obs.inspect_escrow(a, rpc, empty, 'funding')['states']['latest'] == dict(
            obs.inspect_escrow(a, rpc, empty, 'eth_lock')['states']['latest'])
        assert obs.inspect_escrow(a, rpc, empty, 'recovery')['states']['latest']['state'] == 0
        refuse(lambda: obs.inspect_escrow(a, rpc, empty, 'first_reveal'))
        bad = copy.deepcopy(a); bad['escrow']['table_code_hash'] = '0x' + '22' * 32
        refuse(lambda: obs.inspect_escrow(bad, rpc, empty, 'funding'))
        lock_data = out.prefix(a, 'lock')
        locked = ok({'from': bob, 'to': contract, 'value': hex(a['amount_wei']), 'gas': hex(1_000_000),
            'data': lock_data})
        event(a, 'lock', bob, locked)
        current = blocks()
        reveal = obs.inspect_escrow(a, rpc, current, 'first_reveal')['states']['latest']
        assert (reveal['state'], reveal['paid']) == (1, False)
        refuse(lambda: obs.inspect_escrow(a, rpc, current, 'eth_lock'))
        for field in ('amount_wei', 'eth_expiry'):
            changed = copy.deepcopy(a); changed[field] += 1
            refuse(lambda: obs.inspect_escrow(changed, rpc, current, 'first_reveal'))
        claim_data = out.prefix(a, 'claim') + K.to_bytes(32, 'big').hex()
        assert escrow_abi.shape(claim_data) == (2, 'claim')
        for altered in altered_words(claim_data, range(1, 8)):
            reverts({'from': relayer, 'to': contract, 'data': altered})
        claimed = ok({'from': relayer, 'to': contract, 'gas': hex(1_000_000), 'data': claim_data})
        event(a, 'claim', relayer, claimed, claim_data)
        found = raw('eth_getTransactionByHash', [claimed['transactionHash']])
        assert opening.from_transaction(a, claimed['transactionHash'], found) == K.to_bytes(32, 'little').hex()
        other = agreement('0x' + '52' * 32)
        refuse(lambda: opening.from_transaction(other, claimed['transactionHash'], found))
        terminal = blocks()
        state = obs.inspect_escrow(a, rpc, terminal, 'recovery')
        assert (state['states']['latest']['state'], state['states']['latest']['paid']) == (2, False)
        refuse(lambda: obs.inspect_escrow(a, rpc, terminal, 'first_reveal'))
        ready = obs.recovery_action(a, rpc, terminal, state, 'alice', 'withdraw')
        assert ready['credit_wei'] == a['amount_wei'] and ready['reserve']['address'] == alice
        withdraw_data = out.prefix(a, 'withdraw', 'alice')
        for altered in altered_words(withdraw_data, range(1, 8)):
            reverts({'from': alice, 'to': contract, 'data': altered})
        reverts({'from': relayer, 'to': contract, 'data': withdraw_data})  # only the credited owner
        withdrawn = ok({'from': alice, 'to': contract, 'gas': hex(200_000), 'data': withdraw_data})
        event(a, 'withdraw', alice, withdrawn)
        paid = obs.inspect_escrow(a, rpc, blocks(), 'recovery')
        assert (paid['states']['latest']['state'], paid['states']['latest']['paid']) == (2, True)
        refuse(lambda: obs.recovery_action(a, rpc, blocks(), paid, 'alice', 'withdraw'))
        reverts({'from': alice, 'to': contract, 'data': withdraw_data})

        # --- no-reveal refund path ---
        r = agreement('0x' + '61' * 32)
        ok({'from': bob, 'to': contract, 'value': hex(r['amount_wei']), 'gas': hex(1_000_000),
            'data': out.prefix(r, 'lock')})
        refund_data = out.prefix(r, 'refund')
        reverts({'from': bob, 'to': contract, 'data': refund_data})  # before expiry
        raw('evm_setNextBlockTimestamp', [r['eth_expiry']]); raw('evm_mine', [])
        expired = blocks()
        locked_state = obs.inspect_escrow(r, rpc, expired, 'recovery')
        refuse(lambda: obs.recovery_action(r, rpc, expired, locked_state, 'bob', 'refund', now=r['eth_expiry']))
        assert obs.recovery_action(r, rpc, expired, locked_state, 'bob', 'refund', now=r['eth_expiry'] + 61)['credit_wei'] == 0
        for altered in altered_words(refund_data, range(1, 8)):
            reverts({'from': relayer, 'to': contract, 'data': altered})
        reverts({'from': alice, 'to': contract, 'data': out.prefix(r, 'claim') + K.to_bytes(32, 'big').hex()})
        refunded = ok({'from': relayer, 'to': contract, 'gas': hex(200_000), 'data': refund_data})
        event(r, 'refund', relayer, refunded)
        state = obs.inspect_escrow(r, rpc, blocks(), 'recovery')
        assert (state['states']['latest']['state'], state['states']['latest']['paid']) == (3, False)
        maker_withdraw = out.prefix(r, 'withdraw', 'bob')
        reverts({'from': alice, 'to': contract, 'data': out.prefix(r, 'withdraw', 'alice')})
        withdrawn_r = ok({'from': bob, 'to': contract, 'gas': hex(200_000), 'data': maker_withdraw})
        event(r, 'withdraw', bob, withdrawn_r)

        # --- never locked: stays empty and can no longer be created ---
        n = agreement('0x' + '71' * 32)
        assert obs.inspect_escrow(n, rpc, blocks(), 'recovery')['states']['latest']['state'] == 0
        reverts({'from': bob, 'to': contract, 'value': hex(n['amount_wei']), 'data': out.prefix(n, 'lock')})

        # --- deployment specification ---
        owner = root / 'deployer'; owner.mkdir(mode=0o700)
        (owner / 'identity.json').write_text(json.dumps({'public_key': G_PUBLIC, 'chain_id': sepolia.CHAIN_ID,
            'address': '0x7e5f4552091a69125d5dfcb7b8c2659029395bdf'}))
        spec, initcode = public_deploy.specification(owner, 10**8, 2)
        v1_spec, _ = public_deploy.specification(owner, 10**8, 1)
        assert (spec['escrow_version'] == 2 and spec['table'] == escrow_abi.table_address(spec['contract'])
                and spec['gas'] == public_deploy.GAS_BY_VERSION[2]
                and '0x' + initcode.hex() == escrow_abi.creation_code(2) and 'escrow_version' not in v1_spec
                and v1_spec['gas'] == public_deploy.GAS)
        return {'scope': 'PointEscrowV2 through public client code on an owned isolated EVM (chain id 11155111)',
            'public_network': False, 'keys_read': False, 'native_proofs': False,
            'read_methods_used': sorted(set(allowed)), 'all_reads_within_read_only_allowlist': True,
            'exact_public_calldata_executed': ['lock', 'claim', 'withdraw', 'refund'],
            'altered_order_words_reverted': {'claim': 7, 'refund': 7, 'withdraw': 7},
            'relayer_claim_and_refund_credit_fixed_owner': True, 'non_owner_withdraw_reverted': True,
            'observation_phases_and_paid_flag_checked': True, 'table_code_pin_checked': True,
            'opening_captured_from_real_claim': True, 'delivery_events_match_receipts': True,
            'never_locked_order_empty_and_late_lock_reverted': True, 'deploy_spec_v2_checked': True}
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill(); process.wait()


if __name__ == '__main__':
    os.umask(0o077)
    print(json.dumps(check(Path(sys.argv[1]).resolve()), indent=2))
