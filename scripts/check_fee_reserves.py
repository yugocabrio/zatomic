#!/usr/bin/env python3
"""Actual isolated operator gate for gas-starved first-witness exposure.

One new fixture only. Changes no existing wallet or public chain. Interrupted
fixtures retain the ordinary operator recovery layout and node checkpoint.
"""
import argparse
import copy
import json
import os
from pathlib import Path
import fee_policy
import owner_swap as flow
import run_native_evm_gate as evm
from check_independent_operators import Operators, setup, complete
from evm_journal import checkpoint, order_state
from regtest_node import rpc, status
from regtest_wallet import save, require_capacity


def boundaries():
    agreement = {'amount_wei': 10**16, 'fee_policy': fee_policy.default()}
    required = fee_policy.required_balance(agreement, 'claim')
    def observation(balance=required, pending='0x0', price='0x3b9aca00', base='0x1'):
        calls = []
        def fake(method, params=None):
            calls.append(method)
            if method == 'eth_gasPrice': return price
            if method == 'eth_getBlockByNumber': return {'baseFeePerGas': base}
            if method == 'eth_getTransactionCount': return pending if params[1] == 'pending' else '0x0'
            if method == 'eth_getBalance': return hex(balance)
            raise AssertionError('gate attempted a calldata or transaction RPC')
        return fake, calls
    exact, calls = observation()
    assert fee_policy.require_action_budget(agreement, 'public-fixture', 'claim', exact)['required_balance_wei'] == required
    for args in ({'balance': required-1}, {'pending': '0x1'}, {'price': hex(100*10**9+1)}, {'base': hex(2*10**9)}, {'price': '0x01'}):
        fake, _ = observation(**args)
        try: fee_policy.require_action_budget(agreement, 'public-fixture', 'claim', fake)
        except RuntimeError: pass
        else: raise AssertionError('unsafe budget accepted')
    legacy = {'amount_wei': 10**16, 'fee_policy': copy.deepcopy(fee_policy.LEGACY)}
    assert fee_policy.policy(legacy)['gas_limits']['lock'] == 700_000
    assert fee_policy.policy({'amount_wei': 1})['profile'] == 'bounded-legacy-eth-v1'
    for modify in (lambda p:p.update(max_gas_price_wei=True),lambda p:p.update(extra=1),lambda p:p['gas_limits'].update(claim=1),
            lambda p:p['gas_limits'].update(lock=700_000),lambda p:p.update(profile='bounded-legacy-eth-v3')):
        altered=copy.deepcopy(agreement);modify(altered['fee_policy'])
        try: fee_policy.policy(altered)
        except RuntimeError: pass
        else: raise AssertionError('changed fee policy accepted')
    return {'arithmetic_boundary_and_malformed_policy_checks': True, 'gate_rpc_methods': sorted(set(calls))}


def check(root):
    bounds = boundaries()
    root.mkdir(mode=0o700)
    harness = root/'harness'; harness.mkdir(mode=0o700)
    save(harness/'mode.json', {'mode':'success'})
    actors=Operators(root)
    with flow.chain_lock(), flow.node(harness):
        require_capacity(133)
        agreement,consents=setup(actors,harness)
        packet={'agreement':agreement,'consents':consents}
        changed=copy.deepcopy(packet)
        changed['agreement']['fee_policy']['max_gas_price_wei'] //= 2
        actors.invoke('coordinator','source-fund',changed,reject=True)
        original={r:evm.rpc('eth_getBalance',[agreement[k],'latest']) for r,k in [('alice','recipient'),('bob','maker')]}
        save(harness/'original-gas-balances.json',original)
        blocked=[]
        for role,field in [('alice','recipient'),('bob','maker')]:
            evm.rpc('anvil_setBalance',[agreement[field],'0x0'])
            actors.invoke('coordinator','source-fund',packet,reject=True)
            if any((actors.paths['coordinator']/p).exists() for p in ('source-release.json','swap/funding.hex')):
                raise RuntimeError('gas-starved source released native funding')
            blocked.append(role)
            evm.rpc('anvil_setBalance',[agreement[field],original[role]])
        checkpoint(harness)
        actors.invoke('coordinator','source-fund',packet)
        rpc('generate',[2],timeout=300)
        locked=actors.invoke('bob','lock',{'salt':agreement['eth_salt']})
        checkpoint(harness)
        order=locked['order']
        before=evm.rpc('eth_getTransactionCount',[agreement['recipient'],'latest'])
        evm.rpc('anvil_setBalance',[agreement['recipient'],'0x0'])
        actors.invoke('alice','claim',{'order':order},reject=True)
        if ((actors.paths['alice']/'eth-intent-claim.json').exists()
                or order_state(agreement,agreement['native'],order)!=1
                or evm.rpc('eth_getTransactionCount',[agreement['recipient'],'latest'])!=before):
            raise RuntimeError('gas-starved first claim created an exposure intent or settlement')
        evm.rpc('anvil_setBalance',[agreement['recipient'],original['alice']])
        checkpoint(harness)
        gates=dict(bounds,source_refused_gas_starved_owners=blocked,
            changed_signed_fee_cap_rejected=True,first_claim_insufficient_gas_rejected_before_intent=True,
            no_secret_calldata_rpc_in_gas_gate=True)
        save(harness/'fee-gates.json',gates)
        result=complete(actors,harness,agreement,consents,'success')
        save(harness/'complete.json',result)
        repeated=complete(actors,harness,agreement,consents,'success')
        if repeated['new_native_transactions'] or repeated['new_evm_transactions']:
            raise RuntimeError('fee policy replay duplicated payment')
        return dict(gates,settlement=result,repeat_new_transactions=0,native_height=status()['blocks'])


if __name__=='__main__':
    os.umask(0o077)
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('directory',type=Path,nargs='?')
    a=p.parse_args()
    print(json.dumps(check(a.directory.resolve()) if a.directory else boundaries(),indent=2))
