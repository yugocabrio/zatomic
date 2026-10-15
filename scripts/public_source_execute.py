#!/usr/bin/env python3
"""Deliver the one privately authorized F, with source and owner locks retained.

First submission repeats funding preflight. A retained attempt can only replay
the identical F, after fresh original-source/anchor, ETH and auxiliary checks;
it never replaces an input, extends a contract or releases its reservation.
Public positive execution remains untested; explicit testnet flag required.
"""
import argparse
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time
import uuid
import public_authority as authority
import public_evm_observation as eth
import public_native_execute as delivery
import public_native_reconcile as native_observer
import public_outgoing as out
import public_preflight as preflight
import public_recovery_decision as recovery
import public_source as source
import public_source_release as release
import probe_sepolia
import source_inputs
import timestamp_policy
from source_inputs import publish
from testnet_wallet import read


def previous_attempt(directory, identity):
    if not directory.exists() and not directory.is_symlink(): return False
    out.private_directory(directory)
    if read(directory/'binding.json') != identity: raise RuntimeError('source delivery binding changed')
    entries=[p for p in directory.iterdir() if p.name!='binding.json']
    if len(entries)>=128 or any(not re.fullmatch('[0-9a-f]{32}',p.name) for p in entries):
        raise RuntimeError('source send history bound/shape')
    for entry in entries:
        out.private_directory(entry)
        if (entry/'intent.json').exists() or (entry/'intent.json').is_symlink():
            intent=read(entry/'intent.json')
            if any(intent[k]!=v for k,v in identity.items()) or intent['may_have_reached_network'] is not True:
                raise RuntimeError('source send intent changed')
    return bool(entries) # a partial attempt is possible delivery, never a reset


def observe_funding(agreement, checked, raw, directory, query=native_observer.live_query):
    observation=query(checked['txid'],directory/'funding')
    actual=None
    if observation['status']!='not_found':
        received=out.raw_bytes(directory/'funding/transaction.hex')
        if received!=raw: raise RuntimeError('provider F differs from fully verified source bytes')
        actual=checked # exact equality carries the locally verified authorization/proof
    state=native_observer.classify(agreement,checked,observation,actual,int(time.time()))
    publish(directory/'funding-status.json',{'state':state,'observation':observation})
    return state


def replay_checks(owner, wallet, files, checked, directory, endpoint):
    """Called only after verifying the release/raw and a prior delivery attempt."""
    agreement=files['proposal']['agreement']
    context=source.prepare(wallet,owner/'public-native-recovery.json',agreement,checked,
        directory/'source',released=True,replay=True)
    ethereum=eth.observe_recovery(agreement,probe_sepolia.ReadOnlyRpc(endpoint),endpoint)
    publish(directory/'eth.json',ethereum)
    auxiliary_raw=recovery.observe_auxiliary(agreement,checked,directory)
    native_clock,source_status=source.observe(context,agreement)
    now=int(time.time())
    blockers=timestamp_policy.clock_blockers(agreement['execution_plan'],native_clock,ethereum['clock'],now)
    if blockers: raise RuntimeError('source replay observations stale or inconsistent')
    auxiliary=preflight.native_auxiliary(agreement,checked['native_auxiliary'],auxiliary_raw,now)
    report={'agreement_digest':checked['agreement_digest'],'phase':'same-F-replay',
        'native_source':source_status,'native_clock':native_clock,'eth_clock':ethereum['clock'],
        'native_auxiliary':auxiliary,'same_source_and_original_anchor_checked':True,
        'contract_deadlines_unchanged':True,'provider_trusted':True,'send_authorized':False}
    publish(directory/'report.json',report)
    return report


def execute(owner,wallet,consents,endpoint=probe_sepolia.ENDPOINT,broadcast=False):
    with authority.owner_locked(owner) as owner_fd:
        files,checked=authority.verified_files(owner/'public-native-recovery.json',owner/'public-consent-proposal.json',consents)
        caller=authority.bind_owner(owner,files,checked,'funding')
        if checked['synthetic_inputs'] is not False: raise RuntimeError('synthetic inputs cannot enter public source execution')
        agreement=files['proposal']['agreement']
        with source.locked(wallet) as source_fd:
            pinned=source.source_identity(wallet,agreement,released=True)
            retained=source_inputs.replay(wallet,agreement['execution_plan_digest'],agreement['native']['principal_zatoshi'])
            if retained is None: raise RuntimeError('existing source reservation required')
            package=Path(retained['file']).parent
            inspected=release.native_worker(wallet,package,source_fd,inspect=True)
            if not inspected['private_source_authorization_saved'] or not inspected['outgoing_record_present']:
                raise RuntimeError('complete source authorization and journal required')
            expected=dict(inspected['checked'],mode='funding',role='alice',genesis=agreement['native_genesis'],bundle_digest=checked['bundle_digest'])
            raw=out.raw_bytes(wallet/'funding.hex')
            if hashlib.sha256(raw).hexdigest()!=expected['bytes_sha256']: raise RuntimeError('source bytes changed')
            parent=wallet/'public-source-funding'
            if any(read(parent/(name+'.json'))!=files[name] for name in files): raise RuntimeError('source agreement changed')
            identity={'agreement_digest':checked['agreement_digest'],'mode':'funding','txid':expected['txid'],
                'bytes_sha256':expected['bytes_sha256']}
            replay=previous_attempt(parent/'delivery',identity)
            observations=parent/'delivery-observations';out.private_directory(observations)
            if len(list(observations.iterdir()))>=128: raise RuntimeError('source observation history full; preserve it')
            directory=observations/uuid.uuid4().hex;out.private_directory(directory)
            publish(directory/'intent.json',dict(identity,prior_delivery_possible=replay,broadcast=False))
            state=observe_funding(agreement,expected,raw,directory)
            if state in ('pending-by-provider','confirming-by-provider','confirmed-by-provider'):
                return {'action':'funding-observed-monitor-or-continue','state':state,'txid':expected['txid'],
                    'new_submission':False,'send_authorized':False}
            result={}
            def fresh_guard():
                folder=directory/('check-'+uuid.uuid4().hex)
                if replay:
                    out.private_directory(folder)
                    report=replay_checks(owner,wallet,files,checked,folder,endpoint)
                    clocks=[report['native_clock']['observed_at'],report['eth_clock']['observed_at'],report['native_auxiliary']['observed_at']]
                else:
                    report=preflight.observe_verified(owner/'public-native-recovery.json',agreement,checked,
                        'funding',folder,endpoint,wallet,source_released=True)
                    publish(folder/'report.json',report)
                    clocks=[read(folder/'native-clock.json')['observed_at'],read(folder/'eth.json')['clock']['observed_at'],
                        report['native_auxiliary']['observed_at']]
                if (source.source_identity(wallet,agreement,released=True)!=pinned
                        or authority.bind_owner(owner,files,checked,'funding')!=caller or read(consents)!=files['consents']
                        or out.raw_bytes(wallet/'funding.hex')!=raw):
                    raise RuntimeError('source/owner/bytes changed before F send')
                now=int(time.time());max_age=agreement['execution_plan']['policy']['observation_max_age_seconds']
                expiry=min(int(datetime.fromisoformat(s.replace('Z','+00:00')).timestamp()+max_age) for s in clocks)
                if not replay:
                    timestamp_policy.require_window(agreement['execution_plan'],'funding',now)
                    expiry=min(expiry,agreement['execution_plan']['fund_before'])
                if now>=expiry: raise RuntimeError('source checks expired before F send')
                result.update(action='ready-for-explicit-testnet-send',txid=expected['txid'],same_F_replay=replay,
                    observations_digest=eth.digest(report),provider_trusted=True,send_authorized=False,broadcast=False)
                return min(now+60,expiry)
            if not broadcast:
                fresh_guard();return dict(result,new_submission=False)
            submitted=delivery.send_once(parent/'delivery',identity,raw,fresh_guard,
                lambda data,validity:delivery.transport(data,validity,expected['txid'],[owner_fd,source_fd]))
            return dict(result,submission=submitted,new_submission=True,action='reconcile-exact-funding')


def main():
    os.umask(0o077);p=argparse.ArgumentParser(description=__doc__)
    for name in ('owner','wallet','consents'):p.add_argument(name,type=Path)
    p.add_argument('--eth-rpc',default=probe_sepolia.ENDPOINT)
    p.add_argument('--broadcast-testnet',action='store_true',help='explicit network side effect; user authorization required')
    a=p.parse_args()
    print(json.dumps(execute(a.owner,a.wallet,a.consents,a.eth_rpc,a.broadcast_testnet),indent=2));return 2


if __name__=='__main__':
    try:raise SystemExit(main())
    except (RuntimeError,OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError):
        raise SystemExit('Source execution stopped; preserve the reservation, authorization and all attempts. Reconcile F before retrying.') from None
