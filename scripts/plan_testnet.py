#!/usr/bin/env python3
"""Create a bounded timestamp/fee candidate from fresh read-only observations.

No wallet, key, signing, deployment or send capability. This prepares policy
inputs for future final consent; it does not create that consent or authorize it.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import time
import probe_sepolia
from regtest_wallet import ROOT, save
import timestamp_policy
import fee_policy


def plan(directory, endpoint=probe_sepolia.ENDPOINT, gas_cap=100_000_000):
    if type(gas_cap) is not int or not 0 < gas_cap <= fee_policy.DEFAULT['max_gas_price_wei']:
        raise ValueError('positive gas ceiling within the supported policy required')
    directory.mkdir(mode=0o700)
    output=subprocess.run(['node',str(ROOT/'scripts/probe_testnet.mjs')],capture_output=True,text=True,timeout=60,check=True)
    zcash=json.loads(output.stdout)
    save(directory/'native-clock.json',zcash)
    rpc=probe_sepolia.ReadOnlyRpc(endpoint)
    eth=probe_sepolia.observe(rpc, endpoint)
    eth['gas_price_wei']=probe_sepolia.quantity(rpc('eth_gasPrice'))
    save(directory/'eth-clock.json',eth)
    now=int(time.time())
    candidate=timestamp_policy.build(now)
    candidate['fee_policy']['max_gas_price_wei']=gas_cap
    arithmetic=timestamp_policy.validate(candidate)
    blockers=timestamp_policy.clock_blockers(candidate,zcash,eth,now)
    if max(eth['gas_price_wei'], eth['latest']['base_fee_wei']+eth['suggested_priority_fee_wei']) > gas_cap:
        blockers.append('observed-eth-fee-exceeds-selected-ceiling')
    remaining=['explicit-human-public-execution-authorization',
        'funded-canonical-source-note-and-exact-auxiliary',
        'finalized-exact-escrow-deployment', 'owner-accepted-graph-recovery-and-final-consents',
        'fresh-action-preflights-and-funded-public-end-to-end-verification']
    result={'scope':'candidate public timing policy, not executable public swap authorization',
        'plan_digest':timestamp_policy.digest(candidate),'plan':candidate,'arithmetic':arithmetic,
        'clock_blockers':blockers,'remaining_execution_gates':remaining,
        'execution_enabled':False,'funding_authorized':False,'reveal_authorized':False,
        'broadcast':False,'deployment':False,'keys_or_addresses_sent':False,
        'assumptions':['Independent bounded clocks, bounded monitoring/proof/inclusion and reorg recovery are required.',
            'Source inputs/usable anchors and the assumed confirmed funding must survive; deeper forks are outside these bounds.',
            'RPC observations and fee inclusion are trusted/conditional, not cross-chain consensus proofs.',
            'This plan is for the explicit public clients; the isolated height-lock profile is separate.']}
    save(directory/'candidate.json',result)
    return result


if __name__=='__main__':
    os.umask(0o077)
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('directory',type=Path)
    p.add_argument('--eth-rpc',default=probe_sepolia.ENDPOINT)
    p.add_argument('--gas-cap-wei',type=int,default=100_000_000)
    a=p.parse_args()
    try:
        result=plan(a.directory.resolve(),a.eth_rpc,a.gas_cap_wei);print(json.dumps(result,indent=2))
        raise SystemExit(2) # A prepared plan is never completed settlement.
    except (RuntimeError,OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError):
        raise SystemExit('Candidate preparation failed; observations retained, no execution authorized.') from None
