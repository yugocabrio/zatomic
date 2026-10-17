#!/usr/bin/env python3
"""Real owner keys and FROST DKG in separate OS-private roots. No RPC/funds.

The harness copies only explicit exchange packets. This is same-host isolation,
not independent administration or a production encrypted transport.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from check_independent_operators import Operators
from regtest_node import ROOT
from regtest_wallet import save
from testnet_owner import fingerprint


def check(root):
    root.mkdir(mode=0o700)
    (root/'harness').mkdir(mode=0o700)
    actors=Operators(root)
    count=0
    def invoke(role,action,packet=None,reject=False):
        nonlocal count
        count+=1
        directory=root/role
        if packet is not None:
            incoming=directory/f'in-{count}.json'
            save(incoming,packet)
        output=directory/f'out-{count}.json'
        args=[sys.executable,str(ROOT/'scripts/testnet_owner.py'),action,str(directory),'--out',str(output)]
        if action=='init': args+=['--role',role]
        if packet is not None: args+=['--packet',str(incoming)]
        result=subprocess.run(actors.command(role,args),capture_output=True,text=True,timeout=60)
        if result.returncode != (1 if reject else 0):
            save(root/'harness'/f'error-{count}.json',{'stdout':result.stdout,'stderr':result.stderr})
            raise RuntimeError(f'public owner {role}/{action} unexpected result')
        if reject:
            if output.exists(): raise RuntimeError('rejected step emitted packet')
            return None
        summary=json.loads(result.stdout)
        if set(summary) != {'file','action','packet_sha256','funding_authorized','broadcast'}:
            raise RuntimeError('private packet leaked into terminal output')
        return json.loads(output.read_text())
    def resign(role,packet):
        # Simulate a malicious *authenticated* peer, using only its own signer.
        digest=hashlib.sha256(b'Latch public owner setup v1\0'+json.dumps(packet['payload'],
            sort_keys=True,separators=(',',':')).encode()).hexdigest()
        result=subprocess.run(actors.command(role,[str(ROOT/'target/release/shielded-swap-native'),
            'evm-sign-digest',str(root/role/'ethereum')]),input=digest+'\n',text=True,
            capture_output=True,check=True,timeout=10)
        packet['signature']=json.loads(result.stdout)
        return packet
    identities={r:invoke(r,'init')['identity'] for r in ('alice','bob')}
    for role in identities:
        peer=identities['bob' if role=='alice' else 'alice']
        invoke(role,'trust-peer',{'identity':peer,'expected_identity_sha256':'00'*32},reject=True)
        invoke(role,'trust-peer',{'identity':peer,'expected_identity_sha256':fingerprint(peer)})
    # Verify the OS boundary using public markers, not by reading real secrets.
    for role in identities:
        other='bob' if role=='alice' else 'alice'
        cmd=[sys.executable,'-c',
            'from pathlib import Path; import sys\ntry: Path(sys.argv[1]).read_bytes()\n'
            'except PermissionError: sys.exit(0)\nelse: sys.exit(9)',str(root/other/'identity.json')]
        if subprocess.run(actors.command(role,cmd),capture_output=True).returncode:
            raise RuntimeError('peer private-root isolation failed')
    offer=invoke('alice','offer-create',{'zec_amount':'0.02','eth_amount':'0.015000000000000001'})
    changed=copy.deepcopy(offer); changed['offer']['payload']['eth_chain_id']=31338
    invoke('bob','offer-accept',changed,reject=True)
    accepted=invoke('bob','offer-accept',offer)
    invoke('alice','offer-accept',accepted)
    first={r:invoke(r,'setup-start') for r in identities}
    for role in identities:
        if invoke(role,'setup-start')!=first[role]: raise RuntimeError('round1 restart changed')
    changed=copy.deepcopy(first['alice']); changed['payload']['quote_digest']='00'*32
    invoke('bob','setup-round2',changed,reject=True)
    changed=copy.deepcopy(first['bob']); changed['payload']['receiver']=first['alice']['payload']['receiver']
    invoke('alice','setup-round2',changed,reject=True)
    second={r:invoke(r,'setup-round2',first['bob' if r=='alice' else 'alice']) for r in identities}
    for role in identities:
        peer='bob' if role=='alice' else 'alice'
        if invoke(role,'setup-round2',first[peer])!=second[role]: raise RuntimeError('round2 restart changed')
    changed=copy.deepcopy(first['bob']); changed['payload']['receiver']=first['alice']['payload']['joint_seed_fvk']
    invoke('alice','setup-round2',resign('bob',changed),reject=True)
    changed=copy.deepcopy(second['alice']); changed['payload']['to']='alice'
    invoke('bob','setup-finish',resign('alice',changed),reject=True)
    ready={r:invoke(r,'setup-finish',second['bob' if r=='alice' else 'alice']) for r in identities}
    for role in identities:
        peer='bob' if role=='alice' else 'alice'
        if invoke(role,'setup-finish',second[peer])!=ready[role]: raise RuntimeError('complete restart changed')
    changed=copy.deepcopy(ready['bob']); changed['payload']['setup']['destinations']['bob_receiver']=first['alice']['payload']['receiver']
    invoke('alice','setup-agree',resign('bob',changed),reject=True)
    final={r:invoke(r,'setup-agree',ready['bob' if r=='alice' else 'alice']) for r in identities}
    if final['alice']!=final['bob']: raise RuntimeError('different destination descriptors')
    verified=invoke('alice','verify-destinations',final['alice'])
    for role in identities:
        peer='bob' if role=='alice' else 'alice'
        if invoke(role,'setup-agree',ready[peer])!=final[role]: raise RuntimeError('agreement replay changed')
    changed=copy.deepcopy(final['alice']); del changed['receipts']['bob']
    invoke('alice','verify-destinations',changed,reject=True)
    changed=copy.deepcopy(final['alice']); changed['setup']['destinations']['joint_fvk']=first['alice']['payload']['joint_seed_fvk']
    invoke('alice','verify-destinations',changed,reject=True)
    # The legacy spender must still refuse the public-profile accepted quote.
    legacy=subprocess.run([str(ROOT/'target/release/shielded-swap-native'),'otc-verify-acceptance',
        str(root/'alice/accepted-trade.json')],capture_output=True)
    if not legacy.returncode: raise RuntimeError('public quote admitted to isolated spender')
    if any(root.rglob('funding.pczt')) or any(root.rglob('agreement.json')):
        raise RuntimeError('setup unexpectedly constructed or authorized a spend')
    return {'scope':'same-host OS-private owner processes; real public-profile identities and FROST DKG; no RPC or funds',
        'fresh_process_commands':count,'peer_private_root_denied':True,
        'both_quote_signatures_verified':True,'both_dkg_receipts_verified':True,
        'every_stage_replays_identically':True,'session_role_destination_and_missing_receipt_rejected':True,
        'authenticated_peer_equivocation_rejected':True,
        'legacy_spender_refuses_public_quote':True,'terminal_packets_redacted':True,
        'principal_zatoshi':verified['principal_zatoshi'],'eth_amount_wei':verified['eth_amount_wei'],
        'funding_authorized':False,'broadcast':False}


if __name__=='__main__':
    os.umask(0o077)
    print(json.dumps(check(Path(sys.argv[1]).resolve()),indent=2))
