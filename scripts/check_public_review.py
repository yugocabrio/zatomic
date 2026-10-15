#!/usr/bin/env python3
"""Review real generated proofs using owner copies with source/peer roots denied.

Inputs are an earlier synthetic graph and unfunded owner setup. No RPC or
proving; original fixtures remain unchanged and no spend signatures are made.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from check_independent_operators import Operators
from regtest_node import ROOT
from regtest_wallet import save
import timestamp_policy


def check(root,setup,graph):
    root.mkdir(mode=0o700)
    (root/'harness').mkdir(mode=0o700)
    for role in ('alice','bob'):
        shutil.copytree(setup/role,root/role)
    shutil.copytree(graph,root/'coordinator')
    source=root/'coordinator'
    meta=json.loads((source/'graph.json').read_text())
    if meta['input_binding']['synthetic'] is not True:
        raise RuntimeError('this check accepts only explicit unfunded synthetic graphs')
    plan=timestamp_policy.build(meta['refund_lock']['value']-108000)
    save(source/'plan.json',plan)
    shutil.copyfile(root/'alice/authenticated-destinations.json',source/'destinations.json')
    os.chmod(source/'destinations.json',0o600)
    result=subprocess.run([sys.executable,str(ROOT/'scripts/export_testnet_review.py'),str(source),
        str(source/'destinations.json'),str(source/'plan.json'),str(source/'review.json')],
        capture_output=True,text=True,timeout=120)
    if result.returncode:
        save(root/'harness/export-error.json',{'stderr':result.stderr})
        raise RuntimeError('review export failed')
    packet=json.loads((source/'review.json').read_text())
    expected={'format','graph','destinations','plan','funding_preview','claim','refund','claim_check','refund_check'}
    if set(packet)!=expected or (source/'funding.pczt').read_bytes().hex() in json.dumps(packet):
        raise RuntimeError('review export leaked source PCZT')
    actors=Operators(root)
    count=0
    def review(role,value,reject=False):
        nonlocal count
        count+=1
        incoming=root/role/f'review-in-{count}.json'
        output=root/role/f'review-out-{count}.json'
        save(incoming,value)
        result=subprocess.run(actors.command(role,[sys.executable,str(ROOT/'scripts/testnet_owner.py'),
            'graph-review',str(root/role),'--packet',str(incoming),'--out',str(output)]),
            capture_output=True,text=True,timeout=120)
        if result.returncode != (1 if reject else 0):
            save(root/'harness'/f'review-error-{count}.json',{'stderr':result.stderr,'stdout':result.stdout})
            raise RuntimeError('unexpected owner review result')
        return None if reject else json.loads(output.read_text())
    changed=copy.deepcopy(packet); changed['plan']['policy']['native_early_header_seconds']=0
    review('alice',changed,True)
    changed=copy.deepcopy(packet); changed['graph']['funding_txid']='00'*32
    review('alice',changed,True)
    changed=copy.deepcopy(packet)
    changed['plan']=timestamp_policy.build(plan['created_at']+1)
    changed['graph']['refund_lock']=changed['plan']['native_refund_lock']
    review('alice',changed,True) # Metadata and plan agree; the actual R still differs.
    changed=copy.deepcopy(packet); changed['claim_check']=packet['refund_check']
    changed['graph']['files']['claim-check.pczt']=hashlib.sha256(bytes.fromhex(changed['claim_check'])).hexdigest()
    review('alice',changed,True) # Hash updated: actual proving material must still match C.
    reports={role:review(role,packet) for role in ('alice','bob')}
    if reports['alice']!=reports['bob']:
        raise RuntimeError('owners reviewed different signature contexts')
    for role in ('alice','bob'):
        if review(role,packet)!=reports[role]: raise RuntimeError('review restart changed')
        changed=copy.deepcopy(packet); changed['graph']['scope']+=' changed'
        review(role,changed,True)
        # Public marker proves inaccessible source; no key is read for the test.
        cmd=[sys.executable,'-c',
            'from pathlib import Path; import sys\ntry: Path(sys.argv[1]).read_bytes()\n'
            'except PermissionError: sys.exit(0)\nelse: sys.exit(9)',str(source/'graph.json')]
        if subprocess.run(actors.command(role,cmd),capture_output=True).returncode:
            raise RuntimeError('owner could read private source root')
    return {'scope':'same-host isolated owners; real proofs for synthetic nonexistent inputs; no RPC or source signatures',
        'owner_review_commands':count,'both_owners_verified_three_proofs':True,
        'both_owners_verified_deferred_reproving_material':True,
        'source_root_denied':True,'source_funding_pczt_excluded':True,
        'clock_funding_identity_refund_lock_and_checked_material_mutations_refused':True,
        'immutable_review_after_restart':True,'review_packet_digest':reports['alice']['review_packet_digest'],
        'graph_digest':reports['alice']['graph_digest'],'funding_authorized':False,
        'signatures_created':False,'public_funding':False}


if __name__=='__main__':
    os.umask(0o077)
    print(json.dumps(check(*(Path(p).resolve() for p in sys.argv[1:4])),indent=2))
