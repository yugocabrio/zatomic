#!/usr/bin/env python3
"""Real owner consent over one complete synthetic public-profile agreement.

No RPC, deployment or source signing. All keys/state are copied from a finished
unfunded fixture. These signatures are conditional, not a transaction release.
"""
import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from check_independent_operators import Operators
from public_agreement import validate_policy
from regtest_node import ROOT
from regtest_wallet import save


def check(root,fixture):
    bundle=json.loads((fixture/'coordinator/native-recovery.json').read_text())
    if bundle['synthetic_inputs'] is not True:raise RuntimeError('only unfunded synthetic fixture allowed')
    for role in ('alice','bob'):
        if not (fixture/role/'public-native-recovery-receipt.json').is_file():raise RuntimeError('complete recovery fixture first')
    validate_policy()
    shutil.copytree(fixture,root)
    for role in ('alice','bob'):
        (root/role/'ethereum-offline').rename(root/role/'ethereum')
    binary=ROOT/'target/release/shielded-swap-native'
    actors=Operators(root)
    source=root/'coordinator'
    proposal_path=source/'conditional-proposal.json'
    salt='0x'+os.urandom(32).hex()
    def run(command,reject=False):
        p=subprocess.run(command,capture_output=True,text=True,timeout=180)
        if (p.returncode!=0)!=reject:
            save(root/'harness/consent-error.json',{'stderr':p.stderr,'stdout':p.stdout})
            raise RuntimeError('unexpected conditional consent result')
        return None if reject else json.loads(p.stdout)
    stage=[sys.executable,str(ROOT/'scripts/public_agreement.py'),str(source/'native-recovery.json'),
        str(source/'receipts.json'),'0x'+'11'*20,salt,str(proposal_path)]
    staged=run(stage)
    if run(stage)!=staged:raise RuntimeError('proposal replay changed')
    proposal=json.loads(proposal_path.read_text())
    count=0
    def sign(role,value,reject=False,direct=False):
        nonlocal count
        count+=1
        incoming=root/role/f'consent-in-{count}.json';save(incoming,value)
        output=root/role/f'consent-out-{count}.json'
        args=([str(binary),'testnet-owner-consent',str(root/role),str(incoming)] if direct else
            [sys.executable,str(ROOT/'scripts/testnet_owner.py'),'consent',str(root/role),
             '--packet',str(incoming),'--out',str(output)])
        result=run(actors.command(role,args),reject)
        return None if reject else (result if direct else json.loads(output.read_text()))
    # Exercise direct native validation as well as the wrapper; no native digest
    # signing bypass for changed amount, code or observation policy.
    for field in ('amount','code','policy','plan'):
        bad=copy.deepcopy(proposal)
        if field=='amount':bad['agreement']['amount_wei']+=1
        elif field=='code':bad['agreement']['escrow']['runtime_code_hash']='0x'+'22'*32
        elif field=='policy':bad['agreement']['observation_policy']['native_min_confirmations']=1
        else:bad['agreement']['execution_plan']['native_refund_lock']['value']+=1
        sign('alice',bad,True,True)
    bad=copy.deepcopy(proposal);bad['receipts']['bob']['signature']['r']='00'*32
    sign('bob',bad,True)
    if any((root/role/'public-consent-proposal.json').exists() for role in ('alice','bob')):
        raise RuntimeError('invalid agreement persisted before rejection')
    # Simulate the durable-proposal/before-signature gap.
    save(root/'bob/public-consent-proposal.json',proposal)
    consents={role:sign(role,proposal) for role in ('alice','bob')}
    for role in ('alice','bob'):
        (root/role/'ethereum').rename(root/role/'ethereum-offline')
        if sign(role,proposal)!=consents[role]:raise RuntimeError('consent restart changed or needed identity key')
    changed_path=source/'different-proposal.json'
    changed_stage=[*stage];changed_stage[-3]='0x'+'33'*20;changed_stage[-1]=str(changed_path)
    run(changed_stage)
    changed=json.loads(changed_path.read_text())
    sign('alice',changed,True,True) # Otherwise-valid different target after consent.
    output=source/'conditional-consents.json';save(output,consents)
    verify=[str(binary),'testnet-check-consents',str(source/'native-recovery.json'),str(proposal_path),str(output)]
    checked=run(verify)
    if checked['funding_authorized'] or checked['live_observations_checked'] or checked['synthetic_inputs'] is not True:
        raise RuntimeError('offline conditional consent incorrectly promoted')
    for attack in ('swapped','signature','receipt-domain'):
        bad=copy.deepcopy(consents)
        if attack=='swapped':bad={'alice':consents['bob'],'bob':consents['alice']}
        elif attack=='signature':bad['bob']['signature']['s']='00'*32
        else:bad['bob']['signature']=proposal['receipts']['bob']['signature']
        target=source/f'invalid-consent-{attack}.json';save(target,bad)
        run([*verify[:-1],str(target)],True)
    return {'scope':'actual offline owner signatures; synthetic native inputs and an unobserved intended Sepolia address',
        'agreement_digest':checked['agreement_digest'],'bundle_digest':checked['bundle_digest'],
        'both_owner_signatures_verified':True,'direct_native_amount_code_policy_plan_mutations_refused':True,
        'invalid_recovery_receipt_refused':True,'proposal_persisted_before_signing':True,
        'simulated_proposal_signature_gap_resumed':True,'replay_without_identity_key':True,
        'otherwise_valid_changed_contract_after_consent_refused':True,
        'wrong_role_invalid_signature_and_recovery_domain_substitution_refused':True,
        'owner_commands':count,'funding_authorized':False,'live_observations_checked':False,
        'contract_deployed_or_observed':False,'broadcast':False}


if __name__=='__main__':
    os.umask(0o077)
    print(json.dumps(check(*(Path(p).resolve() for p in sys.argv[1:3])),indent=2))
