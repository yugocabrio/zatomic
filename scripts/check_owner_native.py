#!/usr/bin/env python3
"""Actual owner-only native exits against continuing owned chains.

The checker alone restores Anvil/checkpoints and mines. The CLI sees its own
directory, continuing RPC, and public build artifacts; it never advances clocks.
"""
import argparse
import contextlib
import json
import os
from pathlib import Path
import detached_owner
import owner_swap as flow
import prefunding_swap
import run_native_evm_gate as evm
from check_native_funding_reorg import fork, restore as restore_fork
from evm_journal import checkpoint
from regtest_node import rpc, status
from regtest_wallet import save, native
from run_client_swap import client


def call(action, owner, order, stop=False, reject=False):
    before = status()['tip']
    evm_before = evm.rpc('eth_blockNumber')
    result = client(action, owner, {'order': order}, stop=stop, reject=reject)
    if status()['tip'] != before or evm.rpc('eth_blockNumber') != evm_before:
        raise RuntimeError('native owner CLI advanced a chain clock')
    return result


def pending_exit(owner, mode):
    files = list((owner / 'recovery').glob(f'{mode}-*.hex'))
    if len(files) != 1:
        raise RuntimeError('expected one retained exit authorization')
    txid = native('regtest-inspect', files[0])['txid']
    if txid not in rpc('getrawmempool'):
        raise RuntimeError('owner exit was not genuinely pending')
    return txid


def check(directory, orphan_funding=False):
    with flow.chain_lock():
        detached_owner.restore(directory)
        restore_fork(directory)
        mode = flow.read(directory / 'setup.json')['mode']
        if mode not in ('success', 'refund') or (directory / '08-complete.json').exists():
            raise RuntimeError('requires a fresh funded pause')
        role = 'bob' if mode == 'success' else 'alice'
        action = 'native-claim' if mode == 'success' else 'native-refund'
        exit_mode = 'claim' if mode == 'success' else 'refund'
        checks = []
        with contextlib.ExitStack() as forks:
            with flow.node(directory, restore=True):
                agreement = flow.validate_recovery(directory)
                terms = agreement['native']
                order = flow.read(directory / '04-eth-locked.json')['order']
                wrong_role = 'alice' if role == 'bob' else 'bob'
                call(action, directory / 'owners' / wrong_role, order, reject=True)
                call(action, directory / 'owners' / role, '0x' + '00' * 32, reject=True)
                checks.append({'case': 'wrong_owner_and_order', 'rejected': True})
                if mode == 'refund':
                    call(action, directory / 'owners/alice', order, reject=True)
                    evm.rpc('evm_setNextBlockTimestamp', [agreement['eth_expiry']])
                    evm.rpc('evm_mine')
                    client('refund', directory / 'owners/bob', {'order': order})
                    checkpoint(directory)
                else:
                    flow.public_event(agreement, 'Claimed(bytes32,uint256)', order)
                if orphan_funding:
                    if mode != 'success':
                        raise RuntimeError('funding restoration test requires actual ETH claim')
                    funded = rpc('getrawtransaction', [terms['funding_txid'], 1])
                    if funded['confirmations'] != 2:
                        raise RuntimeError('run immediately after F reaches two confirmations')
                    forks.enter_context(fork(directory, funded['blockhash'], terms['funding_txid']))
                    miner = native('regtest-init', directory / 'owner-fork-miner')
                    rpc('generatetoaddress', [1, miner['address']], timeout=300)
                with detached_owner.isolated(directory, role) as owner:
                    if directory.exists() or (owner / 'ethereum').exists():
                        raise RuntimeError('coordinator or signing key was not detached')
                    if orphan_funding:
                        call(action, owner, order, stop=True)
                        if terms['funding_txid'] not in rpc('getrawmempool'):
                            raise RuntimeError('funding was not pending after owner exit')
                        for depth in (0, 1):
                            waiting = call(action, owner, order)
                            if (waiting['state'] != 'waiting-funding-confirmations' or waiting['new_transaction']
                                    or waiting['funding_recovery']['confirmations'] != depth):
                                raise RuntimeError('owner did not wait for F confirmations')
                            rpc('generate', [1], timeout=300)
                        checks.append({'case': 'funding_send_restart', 'pending_and_depth_one_waited': True,
                            'source_authority_used': False, 'clock_advanced_by_checker_only': True})
                    if mode == 'refund':
                        waiting = call(action, owner, order)
                        if waiting['state'] != 'waiting-refund-height' or waiting['new_transaction']:
                            raise RuntimeError('owner did not wait for native refund height')
                        rpc('generate', [terms['refund_height'] + 1 - status()['blocks']], timeout=300)
                        checks.append({'case': 'refund_deadline', 'owner_waited_without_mining': True})
                    call(action, owner, order, stop=True)
                    txid = pending_exit(owner, exit_mode)
                    pending = call(action, owner, order)
                    if pending['state'] != 'pending' or pending['new_transaction'] or pending['txid'] != txid:
                        raise RuntimeError('owner restart did not preserve pending exit')
                    rpc('generate', [1], timeout=300)
                    confirming = call(action, owner, order)
                    if confirming['state'] != 'confirming' or confirming['new_transaction']:
                        raise RuntimeError('owner repeated one-confirmation exit')
                    rpc('generate', [1], timeout=300)
                    confirmed = call(action, owner, order)
                    if (confirmed['state'] != 'confirmed' or confirmed['new_transaction']
                            or confirmed['received_zatoshi'] != terms['payout_zatoshi']):
                        raise RuntimeError('owner did not decrypt confirmed native payout')
                    checks.append({'case': 'native_send_restart', 'pending': pending, 'one_confirmation': confirming,
                        'confirmed': confirmed, 'retained_authorization_versions': len(list((owner / 'recovery').glob(f'{exit_mode}-*.hex')))})
                completed = flow.finish(directory, agreement, order, recovered=True)
                checkpoint(directory)
                chosen = status()['tip']
            # The native fork restores after both directories and EVM checkpoint
            # have been reconciled. No owner command reads that checkpoint.
        if status()['tip'] != chosen:
            raise RuntimeError('owner-native replacement branch was not retained')
    repeated = prefunding_swap.recover(directory)
    if repeated['new_native_transactions'] or repeated['new_evm_transactions']:
        raise RuntimeError('normal recovery repeated an owner-settled payment')
    result = {'scope': 'continuing owned chains; one detached owner directory, no OS sandbox',
        'mode': mode, 'checks': checks, 'native_txid': txid, 'completed': completed, 'repeat': repeated,
        'coordinator_directory_unavailable_to_normal_paths': True, 'owner_eth_signing_key_offline': True,
        'owner_did_not_restore_node_or_mine': True, 'orphaned_funding': orphan_funding,
        'independent_hosts': False, 'public_testnet': False, 'directories_restored': directory.exists()}
    save(directory / 'owner-native-checks.json', result)
    return result


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('directory', type=Path)
    p.add_argument('--orphan-funding', action='store_true')
    p.add_argument('--restore-only', action='store_true')
    a = p.parse_args()
    os.umask(0o077)
    directory = a.directory.resolve()
    if a.restore_only:
        with flow.chain_lock():
            detached_owner.restore(directory)
            restore_fork(directory)
        print(json.dumps({'restored': True}))
    else:
        print(json.dumps(check(directory, a.orphan_funding), indent=2))
