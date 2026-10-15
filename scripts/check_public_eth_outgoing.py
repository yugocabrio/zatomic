#!/usr/bin/env python3
"""Actual EIP-155/native signing on copied synthetic public-profile state.

Reserve observations are explicitly modeled. No RPC or network transfer, no new
native proof graph. Private keys and calldata never appear in the public report.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from check_independent_operators import Operators
from check_public_authority import refuses
import public_authority as authority
import public_eth_outgoing as out
import fee_policy
from regtest_wallet import ROOT, save
from testnet_wallet import read


def check_lock_abi(agreement):
    # Independent Foundry ABI encoder; all arguments are agreed public terms,
    # never a private claim opening or signed transaction.
    from public_evm_observation import digest
    encoded = subprocess.run(['cast', 'calldata', 'lock(bytes32,address,uint64,(uint256,uint256),bytes32)',
        agreement['escrow']['salt'], agreement['recipient'], str(agreement['eth_expiry']),
        '('+agreement['point_x']+','+agreement['point_y']+')', '0x'+digest(agreement)],
        capture_output=True, text=True, timeout=15, check=True).stdout.strip()
    if encoded != out.prefix(agreement, 'lock'): raise RuntimeError('lock encoding differs from independent ABI encoder')
    return {'lock_calldata_matches_independent_foundry_abi_encoder': True}


def budget(agreement, kind):
    required = fee_policy.required_balance(agreement, kind)
    return {'address': agreement['owners'][out.ROLE[kind]]['address'], 'action': kind,
        'nonce': 0, 'gas_price_wei': 1_000_000_000, 'gas_limit': fee_policy.policy(agreement)['gas_limits'][kind],
        'required_balance_wei': required, 'confirmed_balance_wei': required, 'pending_balance_wei': required}


def check(root, fixture):
    if read(fixture/'coordinator/native-recovery.json')['synthetic_inputs'] is not True:
        raise RuntimeError('only explicitly synthetic unfunded fixture permitted')
    root.mkdir(mode=0o700); (root/'harness').mkdir(mode=0o700)
    for role in ('alice', 'bob'): shutil.copytree(fixture/role, root/role)
    actors = Operators(root)
    summaries = {}
    for role, kind in (('bob', 'lock'), ('alice', 'claim')):
        owner = root/role
        consents = owner/'both-consents.json'; save(consents, read(fixture/'coordinator/conditional-consents.json'))
        with authority.owner_locked(owner):
            files, checked, _, found = out.context(owner, consents)
            assert found == kind
            if role == 'alice':
                refuses(lambda: out.require_no_local_claim(owner, files, checked), 'no refund fallback')
            directory, binding = out.workspace(owner, files, checked, role)
            if role == 'alice': assert not out.require_no_local_claim(owner, files, checked)['local_claim_may_be_exposed']
            agreement = files['proposal']['agreement']
            if kind == 'lock': check_lock_abi(agreement)
            reserve = budget(agreement, kind)
            bad = dict(reserve, pending_balance_wei=0)
            refuses(lambda: out.commit(directory, binding, agreement, kind, bad, {'synthetic': True}), 'reserve')
            assert not (directory/kind).exists()
            # A real child commits before reading its opening and signals this
            # exact boundary. SIGKILL leaves no signed bytes and no key access.
            config = owner/'sign-check.json'; save(config, {'reserve': reserve})
        code = '''
import json,sys,time
from pathlib import Path
import public_eth_outgoing as out
import public_authority as authority
from testnet_wallet import read
owner=Path(sys.argv[1]); consents=owner/'both-consents.json'
with authority.owner_locked(owner):
 files,checked,_,kind=out.context(owner,consents)
 directory,binding=out.workspace(owner,files,checked,out.ROLE[kind])
 out.commit(directory,binding,files['proposal']['agreement'],kind,read(owner/'sign-check.json')['reserve'],
  {'synthetic_transcript':True,'live_checks_in_this_invocation':False})
 print('decision-persisted',flush=True)
 time.sleep(60)
'''
        # Test harness owns this precise child, and only terminates that child.
        child = subprocess.Popen(actors.command(role, [sys.executable, '-c', code, str(owner)]),
            env=dict(os.environ, PYTHONPATH=str(ROOT/'scripts')), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            import select
            if not select.select([child.stdout], [], [], 120)[0] or child.stdout.readline().strip() != 'decision-persisted':
                raise RuntimeError('did not reach committed ETH crash boundary')
            child.kill(); child.communicate(timeout=15)
        finally:
            if child.poll() is None: child.kill(); child.communicate(timeout=15)
        assert not (directory/kind/'transaction.hex').exists()
        assert not (directory/kind/'opening-check').exists()
        if role == 'alice':
            with authority.owner_locked(owner):
                refuses(lambda: out.require_no_local_claim(owner, files, checked), 'no refund fallback')
        # Full live entry refuses our synthetic data BEFORE constructing any RPC.
        refuses(lambda: out.operate('prepare', owner, consents, 'http://127.0.0.1:1'), 'synthetic inputs')
        with authority.owner_locked(owner):
            inspected = out.finish(owner, directory, binding, files, checked, kind, True)
            assert not inspected['private_signed_bytes_saved']
            result = out.finish(owner, directory, binding, files, checked, kind)
        raw_path = directory/kind/'transaction.hex'; raw = raw_path.read_bytes()
        signed_path = directory/kind/'signed.json'; signed = signed_path.read_bytes()
        # Completed replay must need no owner signing key or private witness.
        (owner/'ethereum').rename(owner/'ethereum-offline')
        (owner/'setup-round1.json').rename(owner/'setup-round1-offline.json')
        policy = '(version 1)(allow default)(deny network*)'+''.join(
            '(deny file-read* file-write* (subpath '+json.dumps(str(p))+'))'
            for p in (fixture, root/('bob' if role == 'alice' else 'alice'), root/'harness',
                owner/'ethereum-offline', owner/'setup-round1-offline.json'))
        def replay():
            p = subprocess.run(['/usr/bin/sandbox-exec', '-p', policy, sys.executable,
                str(ROOT/'scripts/public_eth_outgoing.py'), 'resume', str(owner), str(consents)],
                capture_output=True, text=True, timeout=180)
            if p.returncode != 2:
                save(root/'harness'/f'{role}-error.json', {'stdout': p.stdout, 'stderr': p.stderr})
                raise RuntimeError('keyless ETH replay failed')
            return json.loads(p.stdout)
        recovered = replay()
        assert recovered['raw_bytes_reused'] and recovered['checked'] == result['checked']
        assert raw_path.read_bytes() == raw and signed_path.read_bytes() == signed
        signed_path.rename(directory/kind/'signed-test-backup.json')
        assert replay()['raw_bytes_reused'] and signed_path.read_bytes() == signed
        # Real signature/decoded payload validation, not just saved hash flags.
        damaged = bytearray.fromhex(raw.decode()); damaged[-1] ^= 1
        raw_path.write_text(damaged.hex())
        try:
            with authority.owner_locked(owner):
                try: out.finish(owner, directory, binding, files, checked, kind, True)
                except (RuntimeError, subprocess.SubprocessError): pass
                else: raise RuntimeError('damaged signed ETH bytes accepted')
        finally: raw_path.write_bytes(raw)
        decision = directory/kind/'decision.json'; original = decision.read_bytes(); changed = read(decision)
        changed['transaction_base']['nonce'] = '0x1'; decision.write_text(json.dumps(changed))
        try:
            with authority.owner_locked(owner):
                refuses(lambda: out.finish(owner, directory, binding, files, checked, kind, True), 'signed ETH bytes')
        finally: decision.write_bytes(original)
        if role == 'alice':
            # Reinitialization never resets this sticky local claim history.
            assert out.operate('init', owner, consents)['local_claim_may_be_exposed']
        summaries[kind] = result['checked']
    report = {'scope': 'actual Sepolia-domain signatures and native adaptor verification; synthetic inputs and modeled reserves',
        'transactions': summaries, 'real_sigkill_after_decision_before_key_or_opening_read': True,
        'missing_history_and_pending_claim_forbid_refund_fallback': True,
        'insufficient_reserve_refused_before_decision': True, 'synthetic_live_entry_refused': True,
        'actual_native_claim_opening_verified': True, 'exact_signed_bytes_replayed_without_keys_or_original_roots': True,
        'lock_calldata_matches_independent_foundry_abi_encoder': True,
        'interrupted_raw_before_signed_journal_resumed': True,
        'corrupt_signed_bytes_and_changed_nonce_refused': True, 'claim_reinitialization_cannot_clear_exposure': True,
        'rpc_calls': 0, 'new_native_proofs': 0, 'public_funded_execution': False, 'broadcast': False}
    save(root/'report.json', report)
    return report


if __name__ == '__main__':
    os.umask(0o077)
    print(json.dumps(check(*(Path(p).resolve() for p in sys.argv[1:3])), indent=2))
