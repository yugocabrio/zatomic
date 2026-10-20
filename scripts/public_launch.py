#!/usr/bin/env python3
"""One-host public launch preparation and final verification, never broadcasting.

Existing owner CLIs do every signature/verification. Explicit private packets
connect the steps; no test fixture, synthetic source or custody shortcut exists.
Operators on separate hosts can exchange the same packets using the lower-level
CLIs. This convenience runner does not claim separate administration.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import uuid
import public_deploy
import public_authority as authority
import public_eth_delivery
import public_native_reconcile
import public_outgoing
import public_source
import public_source_guard
import public_recovery_watch
import plan_testnet
import timestamp_policy
import testnet_wallet
import testnet_owner
from otc_offer import units
from regtest_wallet import ROOT, NATIVE, native, save
from testnet_wallet import read


def command(script,*args):
    p=subprocess.run([sys.executable,str(ROOT/'scripts'/script),*map(str,args)],capture_output=True,text=True)
    if p.returncode:
        raise RuntimeError(f'{script} refused; inspect its private inputs and preserve all state')
    return json.loads(p.stdout)


def owner_action(root,role,action,packet=None):
    directory=root/role; exchange=root/'packets'; public_outgoing.private_directory(exchange)
    args=[action,directory,'--out',exchange/(role+'-'+action+'.json')]
    if packet is not None:
        incoming=directory/('launch-'+action+'.json'); save(incoming,packet); args+=['--packet',incoming]
    command('testnet_owner.py',*args)
    return read(exchange/(role+'-'+action+'.json'))


def owners(root,zec,eth):
    # The operator explicitly operates this local identity pair. Do not discover a
    # remote key or pretend these same-host pins authenticate another human.
    identities={r:read(root/r/'identity.json') for r in ('alice','bob')}
    for r in identities:
        testnet_owner.identity(identities[r],r)
        peer=identities['bob' if r=='alice' else 'alice']
        owner_action(root,r,'trust-peer',{'identity':peer,'expected_identity_sha256':testnet_owner.fingerprint(peer)})
    offer=owner_action(root,'alice','offer-create',{'zec_amount':zec,'eth_amount':eth})
    accepted=owner_action(root,'bob','offer-accept',offer)
    owner_action(root,'alice','offer-accept',accepted)
    previous={r:owner_action(root,r,'setup-start') for r in identities}
    for action in ('setup-round2','setup-finish','setup-agree'):
        previous={r:owner_action(root,r,action,previous['bob' if r=='alice' else 'alice']) for r in identities}
    if previous['alice']!=previous['bob']: raise RuntimeError('owners derived different destinations')
    packet=root/'packets'
    save(packet/'destinations.json',previous['alice']); save(packet/'owners.json',identities)
    with public_source.locked(root/'source'):
        public_source_guard.initialize_locked(root/'source',packet/'owners.json',testnet_owner.fingerprint(identities))
    return {'owner_setup_complete':True,'both_quote_signatures':True,'funding_authorized':False,
        'payout_zatoshi':units(zec,8,21_000_000*10**8-20_000),'eth_amount_wei':units(eth,18,10*10**18),
        'owner_pair_sha256':testnet_owner.fingerprint(identities),'public_transactions':0}


def prepare(root,endpoint,cap,escrow_version=1):
    packet=root/'packets'; source=root/'source'
    accepted=read(root/'alice/accepted-trade.json')
    if read(root/'bob/accepted-trade.json')!=accepted: raise RuntimeError('accepted owner quotes differ')
    # Do not start deadlines or reserve coins while deployment/funding is absent.
    deployed=public_deploy.execute(root/'deployment-owner',cap,endpoint,version=escrow_version)
    if deployed['state']!='finalized-by-provider': raise RuntimeError('exact deployment must be finalized before preparation')
    command('testnet_wallet.py','sync',source,'--batches',32)
    info,current=testnet_wallet.checkpoint(source)
    if current is None or not current['notes']: raise RuntimeError('funded Ironwood source note required')
    policy=root/'execution-policy'
    if not policy.exists(): plan_testnet.plan(policy,endpoint,cap)
    candidate=read(policy/'candidate.json'); plan=candidate['plan']
    if plan['fee_policy']['max_gas_price_wei']!=cap: raise RuntimeError('existing plan uses a different cap')
    timestamp_policy.require_window(plan,'funding',int(time.time()))
    # Every later action rechecks fresh observations, not this saved clock report.
    principal=accepted['offer']['payload']['payout_zatoshi']+10_000
    command('testnet_wallet.py','source',source,'--candidate',policy/'candidate.json','--principal-zatoshi',principal)
    reserved=source/read(source/'source-reservation.json')['package']
    command('testnet_wallet.py','graph',source,'--destinations',packet/'destinations.json')
    graph=reserved/read(reserved/'graph-draft.json')['directory']
    review_path=packet/'review.json'
    if review_path.exists():
        # Rerun: the saved review must be exactly what this graph exports now.
        again=packet/('review-check-'+uuid.uuid4().hex+'.json')
        native('testnet-export-review',graph,packet/'destinations.json',reserved/'plan.json',again)
        if read(again)!=read(review_path): raise RuntimeError('saved review differs from the reserved graph')
        again.unlink()
    else:
        native('testnet-export-review',graph,packet/'destinations.json',reserved/'plan.json',review_path)
    review=read(packet/'review.json')
    for r in ('alice','bob'): owner_action(root,r,'graph-review',review)
    save(packet/'signers.json',{r:[str(NATIVE),'testnet-owner-signer',str(root/r)] for r in ('alice','bob')})
    command('presign_testnet_review.py',packet/'review.json',packet/'signers.json',packet/'presignatures.json')
    # presign_testnet_review.py writes into an output directory (kept under this name).
    command('prepare_testnet_recovery.py',source,reserved,packet/'review.json',packet/'presignatures.json'/'exit-presignatures.json')
    bundle=read(reserved/'native-recovery-bundle.json'); save(packet/'native-recovery.json',bundle)
    receipts={r:owner_action(root,r,'recovery-accept',bundle) for r in ('alice','bob')}
    save(packet/'receipts.json',receipts)
    native('testnet-recovery-receipts',packet/'native-recovery.json',packet/'receipts.json')
    salt=packet/'salt.json'
    if not salt.exists(): save(salt,{'salt':'0x'+os.urandom(32).hex()})
    command('public_agreement.py',packet/'native-recovery.json',packet/'receipts.json',deployed['contract'],read(salt)['salt'],packet/'proposal.json',
        '--escrow-version',escrow_version)
    proposal=read(packet/'proposal.json')
    consents={r:owner_action(root,r,'consent',proposal) for r in ('alice','bob')}; save(packet/'consents.json',consents)
    checked=native('testnet-check-consents',packet/'native-recovery.json',packet/'proposal.json',packet/'consents.json')
    if checked['synthetic_inputs'] is not False: raise RuntimeError('real funded inputs required')
    # Set a durable birthday BEFORE F can be released. Recipient scanning uses
    # each owner's existing native wallet, while recovery watches only joint FVK.
    birthday=read(reserved/'current.json')['height']
    for r in ('alice','bob'):
        native('testnet-export-recovery',root/r,root/(r+'-portable'))
        native('testnet-recovery-watch',root/(r+'-portable'),root/(r+'-watch'),birthday)
        with public_source.locked(root/r/'native'):
            if not (root/r/'native/head.json').exists():
                testnet_wallet.head(root/r/'native',{'genesis':testnet_wallet.GENESIS,'birthday':birthday,'checkpoint':None})
            elif read(root/r/'native/head.json')['birthday']!=birthday:
                raise RuntimeError('recipient birthday changed')
    return dict(checked,prepared=True,broadcast=False,public_swap_succeeded=False)


def native_exit(root,role):
    watch=root/(role+'-watch'); portable=root/(role+'-portable'); owner=root/role
    work=root/('exit-'+role+'-'+uuid.uuid4().hex); public_outgoing.private_directory(work)
    public_recovery_watch.observe(watch,work/'observation',32)
    args=[watch,work/'observation/anchor.json',work/'observation/current.json',work/'proof']
    if role=='bob': args.append(owner/'public-observed-opening/opening.json')
    native('testnet-recovery-prove',*args)
    # Stage and later send independently; this function never invokes transport.
    staged=command('public_outgoing.py','stage',owner,portable,work/'proof/transaction.hex',root/'packets/consents.json')
    return dict(staged,broadcast=False)


def verify(root,version,endpoint):
    consents=root/'packets/consents.json'
    command('testnet_wallet.py','sync',root/'bob/native','--batches',32)
    _,snapshot=testnet_wallet.checkpoint(root/'bob/native')
    proposal=read(root/'packets/proposal.json'); agreement=proposal['agreement']
    seen=public_native_reconcile.observe(root/'bob',version)
    if seen['native_state']!='confirmed-by-provider': raise RuntimeError('native claim not confirmed')
    amount=read(root/'bob/accepted-trade.json')['offer']['payload']['payout_zatoshi']
    if snapshot is None or sum(n['value'] for n in snapshot['notes'] if n['txid']==seen['txid'])!=amount:
        raise RuntimeError('Bob did not decrypt the exact received payout')
    with authority.owner_locked(root/'alice'):
        ethereum=public_eth_delivery.observe_locked(root/'alice',consents,'withdraw',endpoint)
    if ethereum['state']!='confirmed-by-provider' or ethereum.get('withdrawal_verified') is not True:
        raise RuntimeError('Alice ETH withdrawal not finalized')
    result={'scope':'public testnet swap, trusted RPC observations; not a consensus proof',
        'public_swap_succeeded':True,'native_claim_txid':seen['txid'],
        'native_confirmations':seen['confirmations_by_provider'],'recipient_decrypted_zatoshi':amount,
        'eth_withdrawal_txid':ethereum['txid'],'eth_amount_wei':agreement['amount_wei'],
        'agreement_digest':seen['agreement_digest'],'broadcast_in_this_command':False}
    save(root/('verified-'+uuid.uuid4().hex+'.json'),result)
    return result


def main():
    os.umask(0o077)
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('action',choices=('owners','prepare','native-exit','verify'));p.add_argument('root',type=Path)
    p.add_argument('--eth-rpc',default='https://sepolia.gateway.tenderly.co');p.add_argument('--gas-cap-wei',type=int,default=100_000_000)
    p.add_argument('--zec-amount',default='0.001');p.add_argument('--eth-amount',default='0.001')
    p.add_argument('--role',choices=('alice','bob'),default='bob');p.add_argument('--version')
    p.add_argument('--escrow-version',type=int,choices=(1,2),default=1)
    a=p.parse_args(); root=a.root.resolve()
    with authority.owner_locked(root):
        if a.action=='owners': result=owners(root,a.zec_amount,a.eth_amount)
        elif a.action=='prepare': result=prepare(root,a.eth_rpc,a.gas_cap_wei,a.escrow_version)
        elif a.action=='native-exit': result=native_exit(root,a.role)
        else:
            if not a.version: p.error('--version required for verify')
            result=verify(root,a.version,a.eth_rpc)
    print(json.dumps(result,indent=2))


if __name__=='__main__':
    try: main()
    except (RuntimeError,OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError) as e:
        raise SystemExit(f'Public preparation/verification stopped: {e}. No transaction sent by this command.') from None
