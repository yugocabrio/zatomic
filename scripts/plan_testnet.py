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


def plan(directory):
    directory.mkdir(mode=0o700)
    output=subprocess.run(['node',str(ROOT/'scripts/probe_testnet.mjs')],capture_output=True,text=True,timeout=60,check=True)
    zcash=json.loads(output.stdout)
    save(directory/'native-clock.json',zcash)
    eth=probe_sepolia.observe()
    save(directory/'eth-clock.json',eth)
    now=int(time.time())
    candidate=timestamp_policy.build(now)
    arithmetic=timestamp_policy.validate(candidate)
    blockers=timestamp_policy.clock_blockers(candidate,zcash,eth,now)
    remaining=['public-source-and-owner-adapter-disabled','final-native-graph-and-both-consents-missing',
        'public-escrow-and-fee-inclusion-strategy-unverified','funded-public-wallet-and-reservation-unverified',
        'public-confirmation-and-reorg-thresholds-unimplemented']
    result={'scope':'candidate public timing policy, not executable public swap authorization',
        'plan_digest':timestamp_policy.digest(candidate),'plan':candidate,'arithmetic':arithmetic,
        'clock_blockers':blockers,'remaining_execution_gates':remaining,
        'execution_enabled':False,'funding_authorized':False,'reveal_authorized':False,
        'broadcast':False,'deployment':False,'keys_or_addresses_sent':False,
        'assumptions':['Independent bounded clocks, bounded monitoring/proof/inclusion and reorg recovery are required.',
            'Source inputs/usable anchors and the assumed confirmed funding must survive; deeper forks are outside these bounds.',
            'RPC observations and fee inclusion are trusted/conditional, not cross-chain consensus proofs.',
            'This plan is not accepted by the current controlled-height owner/source clients.']}
    save(directory/'candidate.json',result)
    return result


if __name__=='__main__':
    os.umask(0o077)
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('directory',type=Path);a=p.parse_args()
    try:
        result=plan(a.directory.resolve());print(json.dumps(result,indent=2))
        raise SystemExit(2) # Always incomplete until the send integration gates exist.
    except (RuntimeError,OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError):
        raise SystemExit('Candidate preparation failed; observations retained, no execution authorized.') from None
