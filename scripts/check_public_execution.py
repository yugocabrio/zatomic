#!/usr/bin/env python3
"""Actual retained native validation, modeled live decisions and crash journals.

No public RPC/send, no new proof and no node acceptance claim. ETH on-chain
execution of the changed fee policy has its separate owned EVM check.
"""
import copy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import select
import shutil
import subprocess
import sys
import time
import public_authority as authority
import public_native_execute as execute
import public_outgoing as outgoing
import public_recovery_decision as recovery
import public_eth_execute as eth_execute
import public_eth_outgoing as eth_out
import fee_policy
from public_evm_observation import digest
from check_public_authority import OWNER_FILES, refuses
from check_public_outgoing import copy_private
from regtest_wallet import ROOT, save
from testnet_wallet import read


def decision_model(agreement, checked, now):
    stamp=datetime.fromtimestamp(now,timezone.utc).isoformat()
    clock={'genesis':agreement['native_genesis'],'branch_id':agreement['native_branch'],
        'observed_at':stamp,'provider_header_timestamp':now,'announced_upgrade':{'height':0}}
    native={'agreement_digest':digest(agreement),'mode':checked['mode'],'txid':checked['txid'],
        'version':checked['bytes_sha256'],'native_state':'unobserved-by-provider','native_clock':clock,
        'native_observed_tip':{'height':5000000,'hash':'11'*32,'timestamp':now},
        'current_unspent_witness_check':{'exact_funding_note_unspent_in_scan':True,'canonical_trees_rechecked':True}}
    local={'local_history_initialized':True,'local_claim_may_be_exposed':False}
    eth={'agreement_digest':digest(agreement),'claim_seen_ever':False,
        'clock':{'observed_at':stamp,'chain_id':11155111,'expected_genesis':recovery.timestamp_policy.ETH_GENESIS,
            'rpc_genesis_verified':True,'status':'observed','latest':{'timestamp':now}},
        'escrow':{'states':{k:{'state':3} for k in ('provider_finalized','latest')}}}
    aux={'observed_tip':copy.deepcopy(native['native_observed_tip']),'observed_at':stamp}
    result=recovery.decide(agreement,checked['mode'],native,local,eth,aux,now)
    result.update(native=native,local_claim_history=local,eth_observation=eth,auxiliary=aux,reader_errors=[])
    return result


def check(root, fixture):
    root.mkdir(mode=0o700); reports={}
    for role in ('alice','bob'):
        owner=root/role; owner.mkdir(mode=0o700)
        for name in OWNER_FILES: copy_private(fixture/role/name,owner/name)
        shutil.copytree(fixture/role/outgoing.JOURNAL,owner/outgoing.JOURNAL)
        with authority.owner_locked(owner): journal=outgoing.verified_journal_locked(owner)
        version=journal['versions'][0]['bytes_sha256']; raw,checked=execute.retain(journal,version)
        assert checked['proof_and_signatures_verified'] and journal['binding']['synthetic_inputs']
        consents=journal['directory']/'consents.json'; agreement=journal['files']['proposal']['agreement']
        refuses(lambda:execute.execute(owner,version,consents,owner/'no-watch-wallet',broadcast=True),'synthetic inputs')
        assert not (journal['directory']/'delivery').exists()
        now=agreement['native']['refund_lock']['value']+61 if role=='alice' else agreement['execution_plan']['created_at']+60
        decision=decision_model(agreement,checked,now)
        assert execute.require_decision(decision,agreement,checked,now)==now+60
        for fault in ('wrong-version','blocker','reader-failure','missing-witness','observed','exposure','stale'):
            bad=copy.deepcopy(decision); t=now
            if fault=='wrong-version': bad['native']['version']='99'*32
            elif fault=='blocker': bad['blockers']=['test-required-check-failed']
            elif fault=='reader-failure': bad['reader_errors']=['reader-failed']
            elif fault=='missing-witness': bad['native']['current_unspent_witness_check']=None
            elif fault=='observed': bad['action']='monitor-native-exit'
            elif fault=='exposure':
                if role=='bob': continue
                bad['local_claim_history']['local_claim_may_be_exposed']=True
            else: t+=121
            refuses(lambda:execute.require_decision(bad,agreement,checked,t),'')
        if role=='alice':
            bad=copy.deepcopy(decision); bad['auxiliary']['observed_at']=datetime.fromtimestamp(now-121,timezone.utc).isoformat()
            refuses(lambda:execute.require_decision(bad,agreement,checked,now),'auxiliary')
            # The transport must expire with the oldest input check, not merely
            # the most recent native tip; no stale auxiliary window extension.
            bad['auxiliary']['observed_at']=datetime.fromtimestamp(now-110,timezone.utc).isoformat()
            assert execute.require_decision(bad,agreement,checked,now)==now+10
        identity={'agreement_digest':journal['binding']['agreement_digest'],'mode':checked['mode'],
            'txid':checked['txid'],'bytes_sha256':version}
        folder=owner/'test-delivery'
        # Real child persists an intent and then is killed before any transport.
        config={'identity':identity,'raw_file':str(journal['directory']/'versions'/(version+'.hex'))}
        save(owner/'test-send-config.json',config)
        child_code='''
import sys,time
from pathlib import Path
import public_authority as authority
import public_native_execute as execute
import public_outgoing as out
from testnet_wallet import read
owner=Path(sys.argv[1]); config=read(owner/'test-send-config.json')
def stop(raw,validity):
 print('intent-persisted',flush=True); time.sleep(60)
with authority.owner_locked(owner):
 execute.send_once(owner/'test-delivery',config['identity'],out.raw_bytes(Path(config['raw_file'])),lambda:int(time.time())+60,stop)
'''
        child=subprocess.Popen([sys.executable,'-c',child_code,str(owner)],env=dict(os.environ,PYTHONPATH=str(ROOT/'scripts')),
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        try:
            if not select.select([child.stdout],[],[],30)[0] or child.stdout.readline().strip()!='intent-persisted':
                raise RuntimeError('native intent crash boundary not reached')
            child.kill(); child.communicate(timeout=10)
        finally:
            if child.poll() is None: child.kill();child.communicate(timeout=10)
        attempts=list(folder.glob('*/intent.json')); assert len(attempts)==1 and not (attempts[0].parent/'result.json').exists()
        # A callback failure retains uncertainty without fabricating a receipt.
        def failed(raw,validity): raise OSError('explicit disconnected transport, not a node response')
        with authority.owner_locked(owner):
            result=execute.send_once(folder,identity,raw,lambda:int(time.time())+60,failed)
        assert result['status']=='uncertain' and len(list(folder.glob('*/intent.json')))==2
        assert hashlib.sha256(raw).hexdigest()==version
        reports[role]={'actual_native_bytes_verified':version,'mode':checked['mode'],
            'public_synthetic_send_refused':True,'same_bytes_retained_after_sigkill_and_transport_error':True,
            'modeled_live_policy_refusals_pass':True}
        # Inherited owner lock outlives Python parent descriptor closure. Node
        # validates the actual fd and keeps it, with all network denied.
        with authority.owner_locked(owner) as fd:
            meta=os.fstat(fd); lock={'fd':fd,'dev':meta.st_dev,'ino':meta.st_ino}
            value={'raw_hex':raw.hex(),'sha256':version,'txid':checked['txid'],
                'valid_until':int(time.time())+60,'lock_fds':[lock]}
            code="import {validate} from './scripts/send_testnet_transaction.mjs';let chunks=[];for await(const c of process.stdin)chunks.push(c);validate(JSON.parse(Buffer.concat(chunks)));console.log('holding');setTimeout(()=>{},60000);"
            node=subprocess.Popen(['/usr/bin/sandbox-exec','-p','(version 1)(allow default)(deny network*)',
                'node','--input-type=module','-e',code],cwd=ROOT,stdin=subprocess.PIPE,stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,text=True,pass_fds=(fd,))
            node.stdin.write(json.dumps(value));node.stdin.close()
            if not select.select([node.stdout],[],[],10)[0] or node.stdout.readline().strip()!='holding':
                node.kill();node.wait(timeout=10);raise RuntimeError('inherited node lock validation failed')
        try:
            try:
                with authority.owner_locked(owner): pass
            except BlockingIOError: pass
            else: raise RuntimeError('writer lost inherited owner lock')
        finally:
            node.terminate();node.wait(timeout=10)
        with authority.owner_locked(owner): pass
    # Fee policy is tested on actual EVM separately; these isolate changed cap/
    # nonce/reserve selection without pretending to observe a public account.
    kind='lock'; price=fee_policy.policy(agreement)['max_gas_price_wei']; amount=fee_policy.required_balance(agreement,kind)
    reserve={'address':agreement['maker'],'action':kind,'nonce':0,'gas_price_wei':1,
        'gas_limit':fee_policy.policy(agreement)['gas_limits'][kind],'required_balance_wei':amount,
        'confirmed_balance_wei':amount,'pending_balance_wei':amount}
    value={'kind':kind,'transaction_base':eth_out.transaction_base(agreement,kind,reserve)}
    assert int(value['transaction_base']['gasPrice'],16)==price
    eth_execute.require_fee_nonce(value,reserve,agreement)
    for changed in (dict(reserve,nonce=1),dict(reserve,pending_balance_wei=0),dict(reserve,gas_price_wei=price+1)):
        refuses(lambda:eth_execute.require_fee_nonce(value,changed,agreement),'not executable')
    result={'scope':'real retained native proof/signature validation; explicit policy and failed transport models only',
        'owners':reports,'inherited_node_writer_lock_retained_after_parent_close':True,
        'oldest_auxiliary_observation_bounds_native_transport':True,'ceiling_fee_nonce_and_reserve_policy_checked':True,
        'public_rpc_calls':0,'native_node_submissions':0,'new_native_proofs':0,'public_transfers':False}
    save(root/'report.json',result);return result


if __name__=='__main__':
    os.umask(0o077)
    print(json.dumps(check(*(Path(p).resolve() for p in sys.argv[1:3])),indent=2))
