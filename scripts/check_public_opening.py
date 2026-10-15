#!/usr/bin/env python3
"""Actual pending EVM claim -> real native opening acceptance and C reproof.

Local ETH terms are explicitly synthetic and differ from the signed public
agreement's network deployment. The native portable bundle uses synthetic
inputs. No public transfer, full funded public swap or mempool coverage claim.
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
from check_public_authority import OWNER_FILES
from check_public_outgoing import copy_private
import public_opening as opening
import public_evm_observation as eth
import probe_sepolia as sepolia
from regtest_wallet import ROOT, native, save
from run_native_evm_gate import calldata
from testnet_wallet import read


def refuses(fn):
    try: fn()
    except (RuntimeError, ValueError, subprocess.SubprocessError): return
    raise RuntimeError('invalid opening/query accepted')


def check_resume(root, fixture, pending):
    """Explicit provider transcript at the interrupted response boundary.

    Reuses the real isolated claim's candidate scalar but binds the packet to
    the original signed public agreement's order/address. This is not a claimed
    public transaction; the native crypto and caller verification are real.
    """
    root.mkdir(mode=0o700)
    owner = root/'bob'; owner.mkdir(mode=0o700)
    for name in OWNER_FILES: copy_private(fixture/'bob'/name, owner/name)
    consents = root/'consents.json'; copy_private(fixture/'coordinator/conditional-consents.json', consents)
    with opening.authority.owner_locked(owner):
        files, checked, _ = opening.context(owner, consents)
        directory = opening.workspace(owner, files, checked)
    agreement = files['proposal']['agreement']
    tx = read(pending)['response']
    tx.update(to=agreement['escrow']['contract'], input=opening.CLAIM_SELECTOR+eth.order_id(agreement)[2:]+tx['input'][-64:])
    observations = directory/'observations'; observations.mkdir(mode=0o700)
    identifier = '01'*16; entry = observations/identifier; entry.mkdir(mode=0o700)
    save(entry/'intent.json', {'agreement_digest': checked['agreement_digest'],
        'transaction': tx['hash'], 'from_block': None, 'to_block': None})
    save(entry/'transaction.json', {'response': tx})
    assert not (directory/'opening.json').exists()
    policy = '(version 1)(allow default)(deny network*)'+''.join(
        '(deny file-read* file-write* (subpath '+json.dumps(str(p))+'))' for p in (fixture, pending.parent))
    command = ['/usr/bin/sandbox-exec', '-p', policy, sys.executable, str(ROOT/'scripts/public_opening.py'),
        'resume', str(owner), str(consents), '--observation', identifier]
    result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, timeout=120)
    assert result.returncode == 2, 'offline opening resume failed'
    report = json.loads(result.stdout)
    assert report['offline'] and report['opening_available'] and report['native_authorization']['native_claim_authorization_verified']
    before = (directory/'opening.json').read_bytes()
    replay = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, timeout=120)
    assert replay.returncode == 2 and json.loads(replay.stdout) == report
    assert (directory/'opening.json').read_bytes() == before
    return {'saved_response_before_candidate_resumed_offline': True,
        'resume_native_verification_and_idempotence': True, 'resume_network_and_original_roots_denied': True,
        'resume_provider_packet_explicitly_modeled': True}


def check(root, fixture, witness):
    root.mkdir(mode=0o700)
    owner = root/'bob'; owner.mkdir(mode=0o700)
    for name in OWNER_FILES: copy_private(fixture/'bob'/name, owner/name)
    consents = root/'consents.json'; copy_private(fixture/'coordinator/conditional-consents.json', consents)
    with opening.authority.owner_locked(owner):
        files, checked, _ = opening.context(owner, consents)
        directory = opening.workspace(owner, files, checked)
    refuses(lambda: opening.capture(owner, consents, txid='0x'+'11'*32))
    assert not (directory/'observations').exists()
    assert opening.CLAIM_SELECTOR == calldata('claim(bytes32,uint256)', '0x'+'00'*32, 1)[:10]
    assert sepolia.CLAIM_TOPIC == '0x'+eth.keccak(b'Claimed(bytes32,uint256)').hex()
    for value in (0, opening.Q, 2**256-1):
        refuses(lambda: opening.scalar('0x'+f'{value:064x}'))
    for method, params in [('eth_sendRawTransaction', ['0x00']), ('eth_getTransactionByHash', ['pending']),
            ('eth_getLogs', [{'address': '0x'+'11'*20, 'fromBlock': '0x0', 'toBlock': 'latest', 'topics': []}])]:
        refuses(lambda: sepolia.read_method(method, params))
    artifact = json.loads((ROOT/'.local/forge-out/PointEscrow.sol/PointEscrow.json').read_text())
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0)); port = sock.getsockname()[1]
    def rpc(method, params=None):
        req = urllib.request.Request(f'http://127.0.0.1:{port}', json.dumps({
            'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params or []}).encode(),
            {'Content-Type': 'application/json'})
        with urllib.request.urlopen(req, timeout=10) as response: result = json.load(response)
        if 'error' in result: raise RuntimeError('owned local RPC rejected observation fixture')
        return result['result']
    def send(tx):
        txid = rpc('eth_sendTransaction', [tx])
        for _ in range(100):
            result = rpc('eth_getTransactionReceipt', [txid])
            if result is not None:
                if result['status'] != '0x1': raise RuntimeError('local claim fixture reverted')
                return result
            time.sleep(.05)
        raise RuntimeError('local transaction timeout')
    with (root/'anvil.log').open('x') as log:
        proc = subprocess.Popen(['anvil', '--host', '127.0.0.1', '--port', str(port), '--chain-id',
            str(sepolia.CHAIN_ID), '--silent'], stdout=log, stderr=log)
        save(root/'process.json', {'pid': proc.pid, 'port': port, 'scope': 'owned ephemeral opening check'})
        try:
            for _ in range(100):
                if proc.poll() is not None: raise RuntimeError('owned Anvil exited')
                try:
                    if rpc('eth_chainId') == hex(sepolia.CHAIN_ID): break
                except OSError: pass
                time.sleep(.1)
            else: raise RuntimeError('owned Anvil startup timeout')
            maker, recipient = rpc('eth_accounts')[:2]
            deployed = send({'from': maker, 'data': artifact['bytecode']['object'], 'gas': hex(5_000_000)})
            model = copy.deepcopy(files['proposal']['agreement'])
            model['escrow']['contract'] = deployed['contractAddress']
            model.update(maker=maker, recipient=recipient, eth_expiry=int(time.time())+3600)
            # Explicit lower-level model domain, NOT another signed consent.
            model_checked = dict(checked, agreement_digest=eth.digest(model))
            send({'from': maker, 'to': model['escrow']['contract'], 'value': hex(model['amount_wei']),
                'gas': hex(700_000), 'data': calldata('lock(bytes32,address,uint64,(uint256,uint256),bytes32)',
                model['escrow']['salt'], recipient, model['eth_expiry'],
                f'({model["point_x"]},{model["point_y"]})', '0x'+eth.digest(model))})
            # This is the retained synthetic test's already observed opening;
            # neither Alice's source wallet nor any owner signing key is opened.
            scalar = int.from_bytes(bytes.fromhex(read(witness/'observed-opening.json')['witness_le']), 'little')
            rpc('evm_setAutomine', [False])
            txid = rpc('eth_sendTransaction', [{'from': maker, 'to': model['escrow']['contract'],
                'gas': hex(1_000_000), 'data': calldata('claim(bytes32,uint256)', eth.order_id(model), scalar)}])
            tx = rpc('eth_getTransactionByHash', [txid]); assert tx['blockNumber'] is None
            calls = []
            def reader(method, params):
                sepolia.read_method(method, params); calls.append(method)
                return rpc(method, params)
            pending = root/'pending'; pending.mkdir(mode=0o700)
            result = opening.acquire(model, directory, model_checked, pending, reader, txid=txid)
            assert result['opening_available'] and not result['settlement_verified']
            assert calls == ['eth_getTransactionByHash']
            assert rpc('eth_getTransactionReceipt', [txid]) is None
            retained = (directory/'opening.json').read_bytes()
            # A foreign call cannot authorize a different agreement; native
            # acceptance additionally rejects a correctly shaped but wrong t.
            wrong = dict(tx, input=tx['input'][:-64]+f'{1:064x}')
            bad = root/'wrong-scalar'; bad.mkdir(mode=0o700)
            refuses(lambda: opening.acquire(model, directory, model_checked, bad, lambda *_: wrong, txid=txid))
            assert (directory/'opening.json').read_bytes() == retained
            for field, val in [('to', '0x'+'99'*20), ('chainId', '0x1'), ('input', tx['input']+'00')]:
                refuses(lambda: opening.from_transaction(model, txid, dict(tx, **{field: val})))
            rpc('evm_mine'); rpc('evm_setAutomine', [True])
            receipt = rpc('eth_getTransactionReceipt', [txid]); assert receipt['status'] == '0x1'
            h = int(receipt['blockNumber'], 16)
            event_dir = root/'mined-event'; event_dir.mkdir(mode=0o700)
            assert opening.acquire(model, directory, model_checked, event_dir, reader, first=h, last=h)['opening_available']
            # Explicit removed/negative provider transcripts after the real claim.
            removed = copy.deepcopy(receipt['logs']); removed[0]['removed'] = True
            orphan = root/'removed-event'; orphan.mkdir(mode=0o700)
            assert opening.acquire(model, directory, model_checked, orphan, lambda *_: removed, first=h, last=h)['opening_available']
            absent = root/'absent'; absent.mkdir(mode=0o700)
            assert opening.acquire(model, directory, model_checked, absent, lambda *_: None, txid=txid)['opening_available']
            assert (directory/'opening.json').read_bytes() == retained
            save(root/'local-transactions.json', {'deployment': deployed, 'claim': receipt})
        finally:
            proc.terminate()
            try: proc.wait(timeout=10)
            except subprocess.TimeoutExpired: proc.kill(); proc.wait()
            save(root/'process-ended.json', {'pid': proc.pid, 'exit_code': proc.returncode})
    # Fresh process can inspect only Bob's accepted packets and retained opening.
    # Deny original fixture/witness and network in addition to not providing keys.
    policy = '(version 1)(allow default)(deny network*)'+''.join(
        '(deny file-read* file-write* (subpath '+json.dumps(str(p))+'))' for p in (fixture, witness))
    p = subprocess.run(['/usr/bin/sandbox-exec', '-p', policy, sys.executable,
        str(ROOT/'scripts/public_opening.py'), 'inspect', str(owner), str(consents)],
        cwd=ROOT, capture_output=True, text=True, timeout=120)
    assert p.returncode == 2 and json.loads(p.stdout)['native_authorization']['native_claim_authorization_verified']
    # Native recovery consumes the accepted file directly, not an external
    # report/boolean. Historical unspent synthetic checkpoints, no broadcast.
    watch = root/'watch'; watch.mkdir(mode=0o700)
    for name in ('watch-binding.json', 'network.json', 'native-recovery.json', 'owner-receipt.json', 'joint-fvk.bin'):
        copy_private(witness/'bob'/name, watch/name)
    points = {read(p)['height']: p for p in (witness/'bob').glob('compact-*.json')}
    copy_private(points[4_500_001], watch/'anchor.json'); copy_private(points[4_500_012], watch/'current.json')
    proof = native('testnet-recovery-prove', watch, watch/'anchor.json', watch/'current.json', root/'claim-proof', directory/'opening.json')
    assert proof['proof_and_signatures_verified'] and proof['mode'] == 'claim' and proof['synthetic_inputs']
    assert not proof['broadcast']
    resumed = check_resume(root/'resume-check', fixture, root/'pending/transaction.json')
    save(root/'result.json', {'real_pending_claim_captured_before_mining': True,
        'real_claim_event_captured': True, 'removed_and_absent_transcripts_preserve_opening': True,
        'wrong_scalar_native_refused_without_overwrite': True, 'exact_domain_and_canonical_scalar_checked': True,
        'owner_bound_offline_restart_with_network_original_roots_denied': True,
        'actual_native_claim_reproof_from_captured_opening': True,
        'public_synthetic_guard_intact': True, 'public_rpc_calls': 0, 'public_transfers': 0,
        'public_funded_swap': False, 'complete_mempool_monitor': False,
        'scope': 'actual isolated pending EVM call and native authorization/reproof; synthetic native inputs and unsigned local EVM terms', **resumed})
    return read(root/'result.json')


if __name__ == '__main__':
    os.umask(0o077)
    print(json.dumps(check(*(Path(p).resolve() for p in sys.argv[1:4])), indent=2))
