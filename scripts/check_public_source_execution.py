#!/usr/bin/env python3
"""Copied actual source F authorization plus explicit observation transcripts.

No public input, live positive preflight, network submission or new proof. This
checks the newly connected source/receipt/replay boundaries with real signatures.
"""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import time
import public_source as source
import public_source_release as release
import public_source_execute as execute
import public_native_execute as delivery
import public_source_guard as guard
import public_outgoing as out
from check_public_authority import refuses
from regtest_wallet import native, save
from testnet_wallet import read


def check(root, fixture):
    shutil.copytree(fixture,root)
    output=root/'execution-check';output.mkdir(mode=0o700)
    graph=root/'coordinator';wallet=graph/'synthetic-source';owner=root/'alice'
    agreement=read(graph/'conditional-proposal.json')['agreement'];consents=graph/'conditional-consents.json'
    refuses(lambda:execute.execute(owner,wallet,consents,'http://127.0.0.1:1',broadcast=True),'synthetic inputs')
    with source.locked(wallet) as fd:
        inspected=release.native_worker(wallet,graph,fd,synthetic=True,inspect=True)
        pinned=source.source_identity(wallet,agreement,released=True)
        refuses(lambda:guard.active_locked(wallet),'possible public source release')
        refuses(lambda:guard.cancel_locked(wallet),'possible public source release')
    assert inspected['private_source_authorization_saved'] and inspected['outgoing_record_present']
    raw=out.raw_bytes(wallet/'funding.hex')
    checked=dict(inspected['checked'],mode='funding',role='alice',genesis=agreement['native_genesis'],bundle_digest=agreement['bundle_digest'])
    decoded=native('inspect-transaction',wallet/'funding.hex')
    now=int(time.time());stamp=datetime.fromtimestamp(now,timezone.utc).isoformat()
    observation={'format':'latch-testnet-transaction-observation-v1','genesis':agreement['native_genesis'],
        'branch':agreement['native_branch'],'requested_txid':checked['txid'],'observed_at':stamp,
        'observed_tip':{'height':5000011,'hash':'22'*32,'timestamp':now},'announced_upgrade':{'height':0},
        'status':'mined','transaction':decoded,'mined_block':{'height':5000000,'hash':'11'*32,'timestamp':now-825},
        'transaction_index':1,'confirmations_by_provider':12}
    def query(txid,folder):
        assert txid==checked['txid'];folder.mkdir(mode=0o700)
        out.publish_raw(folder/'transaction.hex',raw)
        return observation
    seen=output/'observed';seen.mkdir(mode=0o700)
    assert execute.observe_funding(agreement,checked,raw,seen,query)=='confirmed-by-provider'
    altered=bytearray(raw);altered[-1]^=1
    bad=output/'changed';bad.mkdir(mode=0o700)
    refuses(lambda:execute.observe_funding(agreement,checked,bytes(altered),bad,query),'provider F differs')
    identity={'agreement_digest':read(wallet/'public-source-funding/intent.json')['agreement_digest'],
        'mode':'funding','txid':checked['txid'],'bytes_sha256':hashlib.sha256(raw).hexdigest()}
    journal=output/'delivery';assert not execute.previous_attempt(journal,identity)
    def fail(data,validity):raise OSError('explicit disconnected transport')
    with source.locked(wallet):
        sent=delivery.send_once(journal,identity,raw,lambda:int(time.time())+60,fail)
    assert sent['status']=='uncertain' and execute.previous_attempt(journal,identity)
    refuses(lambda:execute.previous_attempt(journal,dict(identity,bytes_sha256='33'*32)),'binding changed')
    result={'scope':'actual retained synthetic F proof/signature verification and explicit native observation/failed-transport transcripts',
        'actual_source_bytes_sha256':checked['bytes_sha256'],'actual_native_authorization_verified':True,
        'source_identity_revalidated_after_release':bool(pinned['source_wallet_and_owner_pins_bound']),
        'release_still_forbids_cancellation':True,'exact_provider_F_bytes_required':True,
        'durable_uncertain_attempt_selects_same_F_replay':True,'public_synthetic_send_refused':True,
        'public_rpc_calls':0,'native_node_submissions':0,'new_native_proofs':0,'funded_public_positive_path':False}
    save(output/'report.json',result);return result


if __name__=='__main__':
    os.umask(0o077)
    print(json.dumps(check(*(Path(p).resolve() for p in sys.argv[1:3])),indent=2))
