#!/usr/bin/env python3
"""Actual public-profile C/R FROST signing, crash nonce refusal and saved replay.

Uses copies of an unfunded synthetic owner-review fixture. No node/RPC, source
signature, auxiliary signature, private scalar export or new proof generation.
"""
import copy
import json
import os
from pathlib import Path
import select
import shutil
import signal
import subprocess
import sys
from check_independent_operators import Operators
from regtest_node import ROOT
from regtest_wallet import save


def check(root,review):
    # Refuse copying a still-running review fixture; both owners must already
    # have atomically published their receipt and derived policy.
    for role in ('alice','bob'):
        for name in ('graph-review.json','reviewed-graph-packet.json','reviewed-graph-policy.json'):
            if not (review/role/name).is_file():
                raise RuntimeError('finish both owner reviews before copying the fixture')
    shutil.copytree(review,root)
    actors=Operators(root)
    binary=ROOT/'target/release/shielded-swap-native'
    def command(role):
        return actors.command(role,[str(binary),'testnet-owner-signer',str(root/role)])
    packet=json.loads((root/'alice/reviewed-graph-packet.json').read_text())
    if packet['graph']['input_binding']['synthetic'] is not True:
        raise RuntimeError('only unfunded synthetic review fixtures allowed')
    policy=json.loads((root/'alice/reviewed-graph-policy.json').read_text())
    token=os.urandom(32).hex()
    request={'command':'commit','policy':dict(policy,mode='claim',session=token),
        'pczt':packet['claim'],'adaptor_point':packet['destinations']['setup']['adaptor_point']}
    def start():
        p=subprocess.Popen(command('alice'),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        if not select.select([p.stdout],[],[],30)[0]:
            p.kill();p.wait();raise RuntimeError('signer startup timeout')
        hello=p.stdout.readline()
        if not hello:
            error=p.stderr.read();p.wait()
            save(root/'harness/signer-error.json',{'stderr':error})
            raise RuntimeError('signer startup failed')
        return p
    def send(p,value):
        p.stdin.write(json.dumps(value)+'\n');p.stdin.flush()
        if not select.select([p.stdout],[],[],15)[0]: raise RuntimeError('signer response timeout')
        return p.stdout.readline()
    p=start()
    try:
        changed=copy.deepcopy(request);changed['policy']['refund_lock']['value']+=1
        if send(p,changed) or p.wait(timeout=10)==0:
            raise RuntimeError('signer accepted an unreviewed refund policy')
    finally:
        if p.poll() is None:p.kill();p.wait()
    p=start()
    try:
        committed=json.loads(send(p,request))
        if 'commitment' not in committed:raise RuntimeError('no nonce commitment')
        os.kill(p.pid,signal.SIGKILL);p.wait(timeout=10)
    finally:
        if p.poll() is None:p.kill();p.wait()
    p=start()
    try:
        if send(p,request) or p.wait(timeout=10)==0:
            raise RuntimeError('killed nonce attempt reused')
    finally:
        if p.poll() is None:p.kill();p.wait()
    p=start()
    try:
        if send(p,{'command':'sign','ours':'00','theirs':'00'}) or p.wait(timeout=10)==0:
            raise RuntimeError('restart retained a signing nonce')
    finally:
        if p.poll() is None:p.kill();p.wait()
    commands=root/'harness/commands.json'
    save(commands,{role:command(role) for role in ('alice','bob')})
    output=root/'presigned'
    def prepare(config,out,reject=False):
        args=[sys.executable,str(ROOT/'scripts/presign_testnet_review.py'),
            str(root/'coordinator/review.json'),str(config),str(out)]
        p=subprocess.run(args,capture_output=True,text=True,timeout=120)
        if p.returncode != (1 if reject else 0):
            save(root/'harness/presign-error.json',{'stdout':p.stdout,'stderr':p.stderr})
            raise RuntimeError('unexpected public presigning result')
        return None if reject else json.loads(p.stdout)
    result=prepare(commands,output)
    before=(output/'exit-presignatures.json').read_bytes()
    dead=root/'harness/unavailable.json'
    save(dead,{role:['/usr/bin/false'] for role in ('alice','bob')})
    repeated=prepare(dead,output)
    if not repeated['reused_presignatures'] or (output/'exit-presignatures.json').read_bytes()!=before:
        raise RuntimeError('completed presignature replay changed')
    corrupt=root/'corrupt'
    corrupt.mkdir(mode=0o700)
    changed=json.loads(before);changed['refund_spend_signature']='00'*64
    save(corrupt/'exit-presignatures.json',changed)
    prepare(dead,corrupt,True)
    if result['refund_auxiliary_signed'] or result['recovery_bundle_complete'] or result['funding_authorized']:
        raise RuntimeError('partial authorization incorrectly promoted')
    consumed={role:len(list((root/role).glob('public-consumed-*.json'))) for role in ('alice','bob')}
    if consumed!={'alice':2,'bob':2}:
        raise RuntimeError('each owner must consume exactly two signing attempts')
    return {'scope':'real FROST/adaptor signatures over synthetic public-profile C/R; same-host private owner roots',
        'both_adaptor_presignatures_verified':True,'native_refund_spend_signature_verified':True,
        'unreviewed_policy_refused':True,'SIGKILL_after_commitment_burns_attempt':True,
        'restart_has_no_signing_nonce':True,'completed_replay_without_owner_processes':True,
        'corrupt_saved_signature_rejected':True,'consumed_attempts':consumed,
        'review_packet_digest':result['review_packet_digest'],
        'source_and_auxiliary_signatures_created':False,'funding_authorized':False,
        'recovery_bundle_complete':False,'broadcast':False}


if __name__=='__main__':
    os.umask(0o077)
    print(json.dumps(check(*(Path(p).resolve() for p in sys.argv[1:3])),indent=2))
