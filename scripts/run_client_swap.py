#!/usr/bin/env python3
"""Real isolated swap with separate owner-held ETH keys and local action journals.

The harness funds synthetic balances and deploys the contract. Only owner
clients sign swap calls. It never reads Alice's witness or either ETH key.
This is a same-host process test, not independent-host or public-network proof.
"""
import argparse
import copy
import fcntl
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import owned_process
import run_native_evm_gate as evm
import fee_policy
from regtest_node import ROOT, rpc as zrpc, status
from regtest_wallet import native, capture, save
from run_regtest_swap import reject_native, event
from run_tls_swap import run as tls_run
from recover_regtest_swap import native_exit, topic
from evm_participant import agreement_digest
from evm_wallet import check_standard_vector


def client(action, directory, packet=None, role=None, stop=False, reject=False):
    args = [sys.executable, str(ROOT / 'scripts/evm_participant.py'), action, str(directory)]
    if role:
        args.extend(['--role', role])
    if stop:
        args.append('--fault-after-send')
    process = owned_process.run(args, input=json.dumps(packet or {}), capture_output=True,
        text=True, cwd=ROOT, timeout=300 if action in ('native-claim', 'native-refund') else 45)
    expected = 1 if reject else 75 if stop else 0
    if process.returncode != expected:
        raise RuntimeError(f'owner {action} did not return expected status {expected}')
    if reject:
        if process.stdout or process.stderr != 'Owner operation rejected; private state retained.\n':
            raise RuntimeError('owner rejection exposed unexpected data')
        return True
    return json.loads(process.stdout)


def run(directory, mode, bank, relay_pending=False):
    # The source-wallet preparer still acts on Alice's behalf in this fixture.
    paused = tls_run('success' if mode == 'success' else 'refund', directory, bank, 'zec-funded')
    if not paused.get('interrupted'):
        raise RuntimeError('native setup did not pause at funding')
    with (ROOT / '.local/chain-driver.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        owners = directory / 'owners'
        owners.mkdir(mode=0o700)
        addresses, workspaces = {}, {}
        for role in ('alice','bob'):
            owner = owners / role
            owner.mkdir(mode=0o700)
            (directory / 'swap' / role).rename(owner / 'native')
            addresses[role] = client('init', owner, role=role)['address']
            workspace = owner / 'recovery'
            workspaces[role] = workspace
        terms = json.loads((directory / 'swap/terms.json').read_text())
        # After preparation, native exits use only each owner's exported data.
        (directory / 'swap').rename(directory / 'coordinator-native-offline')
        with socket.socket() as probe:
            probe.bind(('127.0.0.1',evm.PORT))
        with (directory / 'client-anvil.log').open('x') as log:
            process = subprocess.Popen(['anvil','--host','127.0.0.1','--port',str(evm.PORT),
                '--chain-id',str(evm.CHAIN),'--silent'], stdout=log, stderr=log, cwd=ROOT)
            try:
                for _ in range(100):
                    if process.poll() is not None:
                        raise RuntimeError('owned client fixture node exited')
                    try:
                        if int(evm.rpc('eth_chainId'),16)==evm.CHAIN:
                            break
                    except OSError:
                        pass
                    time.sleep(.1)
                else:
                    raise RuntimeError('owned client fixture startup timed out')
                accounts = evm.rpc('eth_accounts')
                for address in addresses.values():
                    if address.lower() in [a.lower() for a in accounts]:
                        raise RuntimeError('owner key unexpectedly unlocked at node')
                    evm.rpc('anvil_setBalance',[address,hex(10**18)])
                    try:
                        evm.rpc('eth_signTransaction',[{'from':address,'to':accounts[0],
                            'value':'0x0','gas':hex(21000)}])
                    except RuntimeError:
                        pass
                    else:
                        raise RuntimeError('node could sign for owner')
                artifact=json.loads((ROOT/'.local/forge-out/PointEscrow.sol/PointEscrow.json').read_text())
                deployed=evm.send({'from':accounts[0],'data':artifact['bytecode']['object'],'gas':hex(5_000_000)})
                expiry=int(evm.rpc('eth_getBlockByNumber',['latest',False])['timestamp'],16)+3600
                agreement={'native':terms,'eth_chain_id':evm.CHAIN,'contract':deployed['contractAddress'],
                    'maker':addresses['bob'],'recipient':addresses['alice'],'amount_wei':10**16,'eth_expiry':expiry,
                    'fee_policy':fee_policy.default(),
                    'scope':'owner-held keys on controlled local chains; not public-network timing policy'}
                rejected=[]
                for name, role, mutate in [
                    ('own ETH recipient replaced','alice',lambda a:a.update(recipient=accounts[0])),
                    ('own ETH maker replaced','bob',lambda a:a.update(maker=accounts[0])),
                    ('native amount changed','bob',lambda a:a['native'].update(payout_zatoshi=2_000_000)),
                    ('wrong ETH chain','alice',lambda a:a.update(eth_chain_id=1)),
                    ('short ETH window','alice',lambda a:a.update(eth_expiry=expiry-3590)),
                    ('wrong contract code','bob',lambda a:a.update(contract=accounts[0]))]:
                    changed=copy.deepcopy(agreement)
                    mutate(changed)
                    client('accept',owners/role,changed,reject=True)
                    rejected.append(name)
                for role in ('alice','bob'):
                    accepted=client('accept',owners/role,agreement)
                    if accepted['agreement_digest']!=agreement_digest(agreement):
                        raise RuntimeError('owner acceptance differs')
                # Standard marker also prevents the legacy recovery helper
                # from mistaking this new ETH flow for a funding-only stop.
                save(directory/'agreement.json',agreement)
                salt='0x'+os.urandom(32).hex()
                locked=client('lock',owners/'bob',{'salt':salt},stop=True)
                if locked.get('intentional_stop')!='owner-send-before-receipt':
                    raise RuntimeError('lock interruption absent')
                locked=client('lock',owners/'bob',{'salt':salt})
                if locked['new_transaction']:
                    raise RuntimeError('owner restart replaced a confirmed lock')
                order=locked['order']
                event(directory,'04-client-locked',locked)
                client('refund',owners/'bob',{'order':order},reject=True)
                rejected.append('early ETH refund')
                client('claim',owners/'bob',{'order':order},reject=True)
                rejected.append('wrong owner claim')
                bad_order='0x'+'00'*32
                client('claim',owners/'alice',{'order':bad_order},reject=True)
                rejected.append('unknown order before witness access')
                if (owners/'alice/eth-intent-claim.json').exists():
                    raise RuntimeError('rejected request produced claim intent')
                if mode=='success':
                    # Alice can validate/reveal without reading Bob's client.
                    (owners/'bob').rename(owners/'bob-offline')
                    try:
                        evm.rpc('evm_setAutomine',[False])
                        client('claim',owners/'alice',{'order':order},stop=True)
                        latest=evm.rpc('eth_getBlockByNumber',['pending',True])
                        pending=[t for t in latest['transactions'] if t['to'].lower()==agreement['contract'].lower()]
                        if len(pending)!=1 or evm.rpc('eth_getTransactionReceipt',[pending[0]['hash']]) is not None:
                            raise RuntimeError('claim not actually pending before restart')
                        mempool_hash=pending[0]['hash']
                        # No private journal is read to discover the pending call.
                        if pending[0]['input'][:10] != evm.calldata('claim(bytes32,uint256)',order,0)[:10]:
                            raise RuntimeError('pending transaction is not the claim')
                        if relay_pending:
                            # The competing relayer sees only public mempool
                            # calldata, submits at a higher fee, and cannot
                            # change the escrow's fixed recipient.
                            relayed_hash=evm.rpc('eth_sendTransaction',[{'from':accounts[0],
                                'to':agreement['contract'],'gas':hex(1_000_000),
                                'gasPrice':hex(2*int(pending[0]['gasPrice'],16)),
                                'data':pending[0]['input']}])
                        evm.rpc('evm_mine')
                        evm.rpc('evm_setAutomine',[True])
                        claimed=client('claim',owners/'alice',{'order':order})
                        expected_hash=relayed_hash if relay_pending else mempool_hash
                        if claimed['txid']!=expected_hash or claimed['new_transaction']:
                            raise RuntimeError('restart did not reconcile original pending claim')
                        if relay_pending:
                            original=evm.rpc('eth_getTransactionReceipt',[mempool_hash])
                            thief=int(evm.rpc('eth_call',[{'to':agreement['contract'],
                                'data':evm.calldata('credits(address)',accounts[0])},'latest']),16)
                            if original['status']!='0x0' or thief!=0 or not claimed['settlement_via_other_relayer']:
                                raise RuntimeError('competing relay did not exercise fixed-recipient reconciliation')
                    finally:
                        (owners/'bob-offline').rename(owners/'bob')
                    event(directory,'05-client-claimed',claimed)
                    logs=evm.rpc('eth_getLogs',[{'address':agreement['contract'],'fromBlock':'0x0',
                        'toBlock':'latest','topics':[topic('Claimed(bytes32,uint256)'),order]}])
                    if len(logs)!=1:
                        raise RuntimeError('unique public witness unavailable')
                    witness=int(logs[0]['data'],16).to_bytes(32,'little').hex()
                    (owners/'alice').rename(owners/'alice-offline')
                    try:
                        txid,sent=native_exit(workspaces['bob'],'claim',witness)
                        again,resent=native_exit(workspaces['bob'],'claim',witness)
                    finally:
                        (owners/'alice-offline').rename(owners/'alice')
                    receiver,paid='bob','alice'
                    witness_source='public canonical EVM event; never Alice files'
                else:
                    evm.rpc('evm_setNextBlockTimestamp',[expiry]); evm.rpc('evm_mine')
                    client('refund',owners/'bob',{'order':order},stop=True)
                    refunded=client('refund',owners/'bob',{'order':order})
                    if refunded['new_transaction']:
                        raise RuntimeError('refund restart replaced original transaction')
                    event(directory,'05-client-refunded',refunded)
                    blocks=max(0,terms['refund_height']+1-status()['blocks'])
                    if blocks: zrpc('generate',[blocks],timeout=300)
                    (owners/'bob').rename(owners/'bob-offline')
                    try:
                        if (owners/'alice/eth-intent-claim.json').exists():
                            raise RuntimeError('potential secret exposure forbids no-reveal fixture refund')
                        txid,sent=native_exit(workspaces['alice'],'refund')
                        again,resent=native_exit(workspaces['alice'],'refund')
                    finally:
                        (owners/'bob-offline').rename(owners/'bob')
                    receiver,paid='alice','bob'
                    witness_source='never revealed'
                if not sent or resent or txid!=again:
                    raise RuntimeError('native exit reconciliation failed')
                observed=capture(workspaces[receiver]/receiver)
                notes=json.loads(Path(observed['file']).read_text())['notes']
                if not any(n['txid']==txid and n['value']==1_000_000 for n in notes):
                    raise RuntimeError('native recipient did not decrypt payout')
                before=int(evm.rpc('eth_getBalance',[addresses[paid],'latest']),16)
                withdrawn=client('withdraw',owners/paid,{'order':order})
                receipt=evm.rpc('eth_getTransactionReceipt',[withdrawn['txid']])
                after=int(evm.rpc('eth_getBalance',[addresses[paid],'latest']),16)
                fee=int(receipt['gasUsed'],16)*int(receipt['effectiveGasPrice'],16)
                if after-before+fee!=10**16 or client('withdraw',owners/paid,{'order':order})['new_transaction']:
                    raise RuntimeError('owner ETH payout or withdrawal replay failed')
                result={'scope':'actual owned local chains; separate owner ETH keys and native data',
                    'mode':mode,'native_txid':txid,'native_amount_zatoshi':1_000_000,'eth_wei_received':10**16,
                    'eth_owner_addresses':addresses,'eth_lock_tx':locked['txid'],'eth_withdraw_tx':withdrawn['txid'],
                    'node_cannot_sign_for_owners':True,'coordinator_reads_unrevealed_witness_or_eth_keys':False,
                    'coordinator_native_files_offline':True,'peer_files_offline_during_native_exit':True,
                    'owner_send_receipt_gap_reconciled':True,'native_and_eth_replay_create_no_transaction':True,
                    'claim_observed_pending_before_mining':mode=='success','witness_source':witness_source,
                    'competing_relayer_claimed_first':relay_pending,
                    'rejected':rejected,'standard_vector':check_standard_vector(),
                    'public_testnet':False,'independent_hosts':False,'source_wallet_preparer_still_alice_local':True}
                event(directory,'08-complete',result)
                return result
            finally:
                # Preserve this test node's final state for investigation only;
                # owner clients never call anvil_loadState or use RPC signing.
                if process.poll() is None:
                    try: save(directory/'client-final-evm-state.json',{'state':evm.rpc('anvil_dumpState')})
                    finally: process.terminate()
                try: process.wait(timeout=10)
                except subprocess.TimeoutExpired: process.kill(); process.wait()


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode',choices=['success','refund'])
    parser.add_argument('directory',type=Path)
    parser.add_argument('--existing-bank',type=Path)
    parser.add_argument('--relay-pending-claim',action='store_true')
    args=parser.parse_args()
    os.umask(0o077)
    if args.relay_pending_claim and args.mode!='success':
        parser.error('pending relay gate requires success mode')
    print(json.dumps(run(args.directory.resolve(),args.mode,args.existing_bank.resolve() if args.existing_bank else None,args.relay_pending_claim),indent=2))
