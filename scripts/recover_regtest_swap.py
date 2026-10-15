#!/usr/bin/env python3
"""Resume an isolated-chain swap from durable receipts and chain state.

If ETH was claimed, Bob completes the prepared native claim using the public
witness. An outgoing signed claim may be replayed within its safe window; it is
never treated as an unrevealed swap. Otherwise original assets are refunded.
This restores the OWNED Anvil snapshot; it is not public-network reorg recovery.
"""
import argparse
import fcntl
import json
import os
from pathlib import Path
import socket
import subprocess
import time
import run_native_evm_gate as evm
from regtest_node import ROOT, rpc as zrpc, status, RpcError
from regtest_wallet import native, capture, save
from run_regtest_swap import broadcast
from evm_journal import send as send_evm, replay as replay_outgoing, verify_contract, order_state, validate_intent


def topic(signature):
    return subprocess.check_output(['cast', 'keccak', signature], text=True).strip()


def confirmed(txid):
    try:
        tx = zrpc('getrawtransaction', [txid, 1])
    except RuntimeError:
        return False
    return bool(tx.get('in_active_chain') and tx.get('confirmations', 0) >= 2)


def record_once(directory, stage, value):
    if not (directory / f'{stage}.json').exists():
        save(directory / f'{stage}.json', value)


def native_exit(swap, mode, witness=None, mine=True):
    # Reconcile current chain/mempool, never an old completion journal. Mining
    # here is explicitly the isolated harness's confirmation mechanism.
    status()
    if mode not in ('claim', 'refund'):
        raise RuntimeError('unknown native exit')
    files = sorted(swap.glob(f'{mode}-*.hex'))
    txids = set()
    for path in files:
        info = native('regtest-inspect', path)
        txids.add(info['txid'])
    if len(txids) > 1:
        raise RuntimeError('native exit history changed signed effects')
    if txids:
        txid = next(iter(txids))
        try:
            tx = zrpc('getrawtransaction', [txid, 1])
        except RpcError as exc:
            if exc.code != -5:
                raise
            tx = {}
        depth = tx.get('confirmations', 0) if tx.get('in_active_chain') else 0
        if depth >= 2:
            return txid, False
        if depth > 0 or txid in zrpc('getrawmempool'):
            # A canonical or pending transaction must not be sent a second
            # time: Zebra rejects already-mined effects. Observe this exact
            # payment reaching depth, without constructing another proof.
            if mine:
                zrpc('generate', [2 - depth], timeout=300)
                if not confirmed(txid):
                    raise RuntimeError('observed native exit did not regain confirmations')
            return txid, False
    # An orphaned authorization can reference an invalidated anchor. Re-scan
    # the selected branch and re-prove from the accepted owner bundle. The
    # signed outputs, fees, nullifier and txid must stay unchanged.
    observed = capture(swap)
    args = ['regtest-finish', swap, observed['file'], mode]
    if witness is not None:
        args.append(witness)
    info = native(*args)
    if txids and info['txid'] not in txids:
        raise RuntimeError('re-proving changed native payment effects; not broadcast')
    if mine:
        broadcast(Path(info['file']), info['txid'])
    elif zrpc('sendrawtransaction', [Path(info['file']).read_text().strip()], timeout=180) != info['txid']:
        raise RuntimeError('native exit broadcast changed payment identity')
    return info['txid'], True


def require_workspace_route(directory, agreement, terms, ready):
    # Check the role before replay can mutate the owned EVM. Even a missing
    # claim receipt does not let an Alice refund workspace ignore exposed t.
    exposed = False
    for path in (directory / 'evm-outgoing').glob('*.json'):
        intent = json.loads(path.read_text())
        validate_intent(intent)
        exposed |= intent['kind'] == 'claim'
    locked = directory / '04-eth-locked.json'
    if locked.exists():
        exposed |= order_state(agreement, terms, json.loads(locked.read_text())['order']) == 2
    else:
        exposed |= bool(evm.rpc('eth_getLogs', [{'address': agreement['contract'],
            'fromBlock': '0x0', 'toBlock': 'latest', 'topics': [topic('Claimed(bytes32,uint256)')]}]))
    required = 'claim' if exposed else 'refund'
    if ready['mode'] != required:
        raise RuntimeError('recovery workspace does not own the required native exit; no calls replayed')


def funding_only_refund(directory, terms, swap):
    # No Ethereum setup artifacts may exist. Absence of a single progress file
    # is not evidence that an external call never happened.
    if any((directory / name).exists() for name in ('agreement.json', 'evm-checkpoint.json', 'evm-receipts', '04-eth-locked.json')):
        raise RuntimeError('ETH outcome uncertain; refusing a funding-only refund')
    tx = zrpc('getrawtransaction', [terms['funding_txid'], 1])
    if not tx.get('in_active_chain') or tx.get('confirmations', 0) < 2:
        # The owned local node may still have F in its mempool after the runner
        # died between sendrawtransaction and progress-file creation. Do not
        # re-fund: mine the already-observed transaction and verify it again.
        zrpc('generate', [2], timeout=300)
    if not confirmed(terms['funding_txid']):
        raise RuntimeError('existing funding not confirmed; no new funding submitted')
    record_once(directory, '02-funded', {'txid': terms['funding_txid'], 'in_active_chain': True, 'confirmations': 2})
    missing = max(0, terms['refund_height'] + 1 - status()['blocks'])
    if missing:
        zrpc('generate', [missing], timeout=300)
    txid, sent = native_exit(swap, 'refund')
    observed = capture(swap / 'alice')
    notes = json.loads(Path(observed['file']).read_text())['notes']
    if not any(n['txid'] == txid and n['value'] == 1_000_000 for n in notes):
        raise RuntimeError('funding-only refund amount not decrypted')
    record_once(directory, '06-zec-refunded', {'txid': txid, 'in_active_chain': True, 'confirmations': 2})
    result = {'scope': 'owned local chain; interruption before any ETH setup',
        'mode': 'funding-refund', 'native_txid': txid, 'native_amount_zatoshi': 1_000_000,
        'eth_not_locked': True, 'eth_wei_received': 0, 'public_testnet': False,
        'no_peer_spend_signature_requested_during_recovery': True,
        'native_canonical_with_at_least_two_confirmations': True}
    record_once(directory, '09-recovered', result)
    record_once(directory, '08-complete', result)
    return {**result, 'new_native_transactions': int(sent), 'new_evm_transactions': 0}


def recover(directory, native_directory=None):
    os.umask(0o077)
    status()
    swap = native_directory or directory / 'swap'
    terms = json.loads((swap / 'terms.json').read_text())
    if native_directory:
        ready = json.loads((swap / 'recovery-ready.json').read_text())
        if ready['funding_txid'] != terms['funding_txid'] or ready['spending_keys_exported'] is not False:
            raise RuntimeError('independent native recovery bundle mismatch')
    if not (directory / '04-eth-locked.json').exists() and not (directory / 'agreement.json').exists():
        if native_directory and ready['mode'] != 'refund':
            raise RuntimeError('this participant does not own the native refund')
        return funding_only_refund(directory, terms, swap)
    agreement = json.loads((directory / 'agreement.json').read_text())
    checkpoint = json.loads((directory / 'evm-checkpoint.json').read_text())
    if agreement['native'] != terms or checkpoint['chain_id'] != evm.CHAIN or agreement['eth_chain_id'] != evm.CHAIN:
        raise RuntimeError('recovery journal domain mismatch')
    if not confirmed(terms['funding_txid']):
        raise RuntimeError('recorded native funding is no longer confirmed; refuse cached state')
    with socket.socket() as probe:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        probe.bind(('127.0.0.1', evm.PORT))
    with (directory / 'recovery-anvil.log').open('a') as log:
        process = subprocess.Popen(['anvil', '--host', '127.0.0.1', '--port', str(evm.PORT),
            '--chain-id', str(evm.CHAIN), '--silent'], cwd=ROOT, stdout=log, stderr=log)
        try:
            for _ in range(100):
                if process.poll() is not None:
                    raise RuntimeError('owned recovery node exited')
                try:
                    if int(evm.rpc('eth_chainId'), 16) == evm.CHAIN:
                        break
                except OSError:
                    pass
                time.sleep(.1)
            else:
                raise RuntimeError('recovery node startup timeout')
            if not evm.rpc('anvil_loadState', [checkpoint['state']]):
                raise RuntimeError('snapshot restore failed')
            verify_contract(agreement)
            if native_directory:
                require_workspace_route(directory, agreement, terms, ready)
            replayed = replay_outgoing(directory, agreement, terms)
            contract = agreement['contract']
            if not (directory / '04-eth-locked.json').exists():
                locks = evm.rpc('eth_getLogs', [{'address': contract, 'fromBlock': '0x0', 'toBlock': 'latest',
                    'topics': [topic('Locked(bytes32,address,address,uint256,uint64,uint256,uint256,bytes32)')]}])
                if len(locks) != 1 or locks[0].get('removed', False):
                    raise RuntimeError('cannot reconcile a unique canonical ETH lock')
                record_once(directory, '04-eth-locked', {'txid': locks[0]['transactionHash'], 'order': locks[0]['topics'][1]})
            locked = json.loads((directory / '04-eth-locked.json').read_text())
            order = locked['order']
            state = order_state(agreement, terms, order)
            sent = 0
            if state == 2:
                if native_directory and ready['mode'] != 'claim':
                    raise RuntimeError('this participant does not own the native claim')
                logs = evm.rpc('eth_getLogs', [{'address': contract, 'fromBlock': '0x0',
                    'toBlock': 'latest', 'topics': [topic('Claimed(bytes32,uint256)'), order]}])
                if len(logs) != 1 or logs[0].get('removed', False):
                    raise RuntimeError('canonical public witness unavailable')
                receipt = evm.rpc('eth_getTransactionReceipt', [logs[0]['transactionHash']])
                if receipt is None or receipt['status'] != '0x1':
                    raise RuntimeError('public witness receipt unavailable')
                witness = int(logs[0]['data'], 16).to_bytes(32, 'little').hex()
                # Does not read Alice's directory or spend share.
                native_txid, native_sent = native_exit(swap, 'claim', witness)
                mode, owner, receiver = 'success', agreement['recipient'], swap / 'bob'
                observed_from_public_event = True
            elif state in (1, 3):
                if native_directory and ready['mode'] != 'refund':
                    raise RuntimeError('this participant does not own the native refund')
                if state == 1:
                    current = int(evm.rpc('eth_getBlockByNumber', ['latest', False])['timestamp'], 16)
                    if current < agreement['eth_expiry']:
                        evm.rpc('evm_setNextBlockTimestamp', [agreement['eth_expiry']])
                        evm.rpc('evm_mine')
                    refunded = send_evm(directory, {'from': agreement['maker'], 'to': contract, 'gas': hex(200_000),
                        'data': evm.calldata('refund(bytes32)', order)}, kind='refund')
                    record_once(directory, '05-eth-refunded', {'txid': refunded['transactionHash']})
                    sent += 1
                missing = max(0, terms['refund_height'] + 1 - status()['blocks'])
                if missing:
                    zrpc('generate', [missing], timeout=300)
                native_txid, native_sent = native_exit(swap, 'refund')
                mode, owner, receiver = 'refund', agreement['maker'], swap / 'alice'
                observed_from_public_event = False
            else:
                raise RuntimeError('restored order is not funded')
            record_once(directory, '06-zec-claimed' if mode == 'success' else '06-zec-refunded',
                        {'txid': native_txid, 'in_active_chain': True, 'confirmations': 2})
            scanned = capture(receiver)
            notes = json.loads(Path(scanned['file']).read_text())['notes']
            if not any(n['txid'] == native_txid and n['value'] == 1_000_000 for n in notes):
                raise RuntimeError('recovered native amount not decrypted by recipient')
            credit = int(evm.rpc('eth_call', [{'to': contract, 'data': evm.calldata('credits(address)', owner)}, 'latest']), 16)
            if credit == 10**16:
                before = int(evm.rpc('eth_getBalance', [owner, 'latest']), 16)
                withdrawn = send_evm(directory, {'from': owner, 'to': contract, 'gas': hex(200_000),
                    'data': evm.calldata('withdraw(address)', owner)}, kind='withdraw')
                sent += 1
                after = int(evm.rpc('eth_getBalance', [owner, 'latest']), 16)
                fee = int(withdrawn['gasUsed'], 16) * int(withdrawn['effectiveGasPrice'], 16)
                if after - before + fee != 10**16:
                    raise RuntimeError('recovered ETH amount differs')
            elif credit == 0:
                owner_topic = '0x' + owner.removeprefix('0x').lower().zfill(64)
                logs = evm.rpc('eth_getLogs', [{'address': contract, 'fromBlock': '0x0', 'toBlock': 'latest',
                    'topics': [topic('Withdrawn(address,address,uint256)'), owner_topic, owner_topic]}])
                if not any(int(log['data'], 16) == 10**16 and not log.get('removed', False) for log in logs):
                    raise RuntimeError('zero credit without a verified previous withdrawal')
            else:
                raise RuntimeError('unexpected recovery credit')
            result = {'scope': 'resumed owned local chains; not public-network reorg proof',
                'mode': mode, 'public_testnet': False, 'same_host_setup': True,
                'independent_signer_processes': terms.get('independent_signer_processes', False),
                'native_txid': native_txid, 'native_amount_zatoshi': 1_000_000,
                'native_canonical_with_at_least_two_confirmations': True,
                'eth_wei_received': 10**16, 'witness_recovered_from_public_event': observed_from_public_event,
                'no_peer_spend_signature_requested_during_recovery': True,
                'zec_principal_shielded': True, 'refund_has_transparent_auxiliary': True}
            if native_directory:
                result['separate_native_recovery_workspace'] = True
            save(directory / '09-recovered.json', result)
            if not (directory / '08-complete.json').exists():
                save(directory / '08-complete.json', result)
            return {**result, 'new_native_transactions': int(native_sent), 'new_evm_transactions': sent, 'identical_outgoing_transactions_replayed': replayed}
        finally:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('--native-directory', type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    with (ROOT / '.local/chain-driver.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        print(json.dumps(recover(args.directory.resolve(), args.native_directory.resolve() if args.native_directory else None), indent=2))
