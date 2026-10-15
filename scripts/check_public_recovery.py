#!/usr/bin/env python3
"""Complete native exit authorization using a NONEXISTENT public-profile coin.

Real signatures/proofs and isolated owner receipts, no RPC/new proofs/funding.
The public reserved-source entry point must reject this diagnostic provenance.
"""
import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from check_independent_operators import Operators
from regtest_node import ROOT
from regtest_wallet import save


def check(root,fixture):
    if not all((fixture/p).is_file() for p in (
            'presigned/exit-presignatures.json','alice/graph-review.json','bob/graph-review.json')):
        raise RuntimeError('completed unfunded presigning fixture required')
    packet=json.loads((fixture/'coordinator/review.json').read_text())
    if packet['graph']['input_binding']['synthetic'] is not True:
        raise RuntimeError('only nonexistent synthetic inputs permitted')
    shutil.copytree(fixture,root)
    actors=Operators(root)
    binary=ROOT/'target/release/shielded-swap-native'
    bundle_path=root/'coordinator/native-recovery.json'
    def native(*args,reject=False):
        result=subprocess.run([str(binary),*map(str,args)],capture_output=True,text=True,timeout=180)
        if (result.returncode!=0)!=reject:
            save(root/'harness/native-recovery-error.json',{'stderr':result.stderr,'stdout':result.stdout})
            raise RuntimeError('unexpected native recovery result')
        return None if reject else json.loads(result.stdout)
    make=['check-public-recovery-synthetic',root/'coordinator/review.json',
        root/'presigned/exit-presignatures.json',bundle_path]
    result=native(*make)
    bundle=json.loads(bundle_path.read_text())
    if result['synthetic_inputs'] is not True or not result['native_exit_bundle_complete'] or result['funding_authorized']:
        raise RuntimeError('recovery scope incorrectly promoted')
    saved=bundle_path.read_bytes()
    if not native(*make)['reused_bundle'] or bundle_path.read_bytes()!=saved:
        raise RuntimeError('native bundle replay changed')
    # This command cannot interpret the synthetic graph as a source reservation.
    bank=root/'coordinator/unfunded-source'
    bank.mkdir(mode=0o700)
    native('testnet-prepare-recovery',bank,root/'coordinator',root/'coordinator/review.json',
        root/'presigned/exit-presignatures.json',reject=True)
    if (root/'coordinator/native-recovery-intent.json').exists():
        raise RuntimeError('unreserved diagnostic reached source signing')
    count=0
    def accept(role,value,reject=False):
        nonlocal count
        count+=1
        incoming=root/role/f'recovery-in-{count}.json'
        output=root/role/f'recovery-out-{count}.json'
        save(incoming,value)
        p=subprocess.run(actors.command(role,[sys.executable,str(ROOT/'scripts/testnet_owner.py'),
            'recovery-accept',str(root/role),'--packet',str(incoming),'--out',str(output)]),
            capture_output=True,text=True,timeout=180)
        if p.returncode!=(1 if reject else 0):
            save(root/'harness'/f'owner-recovery-error-{count}.json',{'stdout':p.stdout,'stderr':p.stderr})
            raise RuntimeError('unexpected owner recovery result')
        return None if reject else json.loads(output.read_text())
    # Each rejected candidate precedes persistence, not just an immutable-file
    # rejection after a good bundle was stored.
    damaged=copy.deepcopy(bundle);damaged['refund']=packet['refund']
    accept('alice',damaged,True)
    damaged=copy.deepcopy(bundle)
    sig=bundle['presignatures']['refund_spend_signature']
    raw=bytes.fromhex(damaged['refund']);at=raw.find(bytes.fromhex(sig))
    if at<0 or raw.count(bytes.fromhex(sig))!=1:raise RuntimeError('refund signature location')
    changed=bytearray(raw);changed[at+63]^=1
    damaged['refund']=changed.hex() # checked copy remains valid
    accept('alice',damaged,True)
    damaged=copy.deepcopy(bundle);damaged['presignatures']['claim']['s_hat']='00'*32
    accept('bob',damaged,True)
    damaged=copy.deepcopy(bundle);damaged['synthetic_inputs']=False
    accept('bob',damaged,True)
    for role in ('alice','bob'):
        if any((root/role/p).exists() for p in ('public-native-recovery.json','public-native-recovery-receipt.json')):
            raise RuntimeError('invalid candidate persisted a recovery record')
    # Simulate interruption after the durable bundle, before receipt signing.
    save(root/'bob/public-native-recovery.json',bundle)
    receipts={role:accept(role,bundle) for role in ('alice','bob')}
    for role in ('alice','bob'):
        if not (root/role/'public-native-recovery.json').is_file():raise RuntimeError('receipt without bundle')
        if receipts[role]['payload']['execution_plan_digest'] is None:raise RuntimeError('missing plan binding')
        # Existing receipt is validated and replayed without private identity key.
        (root/role/'ethereum').rename(root/role/'ethereum-offline')
        if accept(role,bundle)!=receipts[role]:raise RuntimeError('receipt restart changed')
    receipt_path=root/'coordinator/receipts.json'
    save(receipt_path,receipts)
    both=native('testnet-recovery-receipts',bundle_path,receipt_path)
    for attack in ('swapped','signature','plan','missing'):
        bad=copy.deepcopy(receipts)
        if attack=='swapped':bad={'alice':receipts['bob'],'bob':receipts['alice']}
        elif attack=='signature':bad['bob']['signature']['s']='00'*32
        elif attack=='plan':bad['bob']['payload']['execution_plan_digest']='00'*32
        else:del bad['bob']
        target=root/'coordinator'/f'bad-{attack}.json';save(target,bad)
        native('testnet-recovery-receipts',bundle_path,target,reject=True)
    # Restart and verify each saved bundle with source+peer unavailable.
    (root/'coordinator').rename(root/'coordinator-offline')
    (root/'bob').rename(root/'bob-offline')
    if accept('alice',bundle)!=receipts['alice']:raise RuntimeError('offline Alice receipt changed')
    (root/'bob-offline').rename(root/'bob')
    (root/'alice').rename(root/'alice-offline')
    if accept('bob',bundle)!=receipts['bob']:raise RuntimeError('offline Bob receipt changed')
    (root/'alice-offline').rename(root/'alice')
    (root/'coordinator-offline').rename(root/'coordinator')
    return {'scope':'actual native signatures/proof verification for nonexistent synthetic inputs; same-host isolated owners',
        'bundle_digest':both['bundle_digest'],'review_packet_digest':both['review_packet_digest'],
        'graph_digest':both['graph_digest'],'execution_plan_digest':both['execution_plan_digest'],
        'conditional_claim_verified':True,'refund_shielded_and_auxiliary_signatures_verified':True,
        'exact_reviewed_reproving_material_verified':True,'both_identity_signed_receipts_verified':True,
        'partial_bundle_receipt_gap_resumed':True,'receipt_replay_without_identity_key':True,
        'source_and_peer_offline_revalidation':True,'incomplete_and_damaged_exits_rejected_before_persistence':True,
        'synthetic_provenance_cannot_be_promoted':True,'public_entrypoint_refuses_no_reservation':True,
        'changed_missing_or_swapped_receipts_refused':True,'owner_accept_commands':count,
        'funding_authorized':False,'broadcast':False,'public_chain_acceptance':False}


if __name__=='__main__':
    os.umask(0o077)
    print(json.dumps(check(*(Path(p).resolve() for p in sys.argv[1:3])),indent=2))
