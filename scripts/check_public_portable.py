#!/usr/bin/env python3
"""Export each accepted native bundle; validate with ALL original roots denied.

This checks saved authorization/proving data, not live witness acquisition or
on-chain recovery. No private signing keys, original fixture mutation or RPC.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
from check_independent_operators import Operators
from regtest_node import ROOT
from regtest_wallet import save


def check(root,fixture):
    root.mkdir(mode=0o700)
    binary=ROOT/'target/release/shielded-swap-native'
    actors=Operators(fixture)
    reports={}
    def run(command,reject=False):
        p=subprocess.run(command,capture_output=True,text=True,timeout=180)
        if (p.returncode!=0)!=reject:
            save(root/'error.json',{'stderr':p.stderr,'stdout':p.stdout})
            raise RuntimeError('unexpected portable recovery result')
        return None if reject else json.loads(p.stdout)
    for role in ('alice','bob'):
        output=root/role
        command=actors.command(role,[str(binary),'testnet-export-recovery',str(fixture/role),str(output)])
        reports[role]=run(command)
        before={p.name:p.read_bytes() for p in output.iterdir()}
        if set(before)!={'native-recovery.json','owner-receipt.json','recovery-ready.json'}:
            raise RuntimeError('unexpected export member')
        if run(command)!=reports[role] or {p.name:p.read_bytes() for p in output.iterdir()}!=before:
            raise RuntimeError('portable export replay changed')
        other=root/('bob' if role=='alice' else 'alice')
        policy='(version 1)(allow default)'+''.join(
            '(deny file-read* file-write* (subpath '+json.dumps(str(p))+'))' for p in (fixture,other))
        # Read only a non-secret marker to establish denial.
        probe=[sys.executable,'-c','from pathlib import Path; import sys\ntry: Path(sys.argv[1]).read_bytes()\n'
            'except PermissionError: sys.exit(0)\nelse: sys.exit(9)',str(fixture/role/'graph-review.json')]
        if subprocess.run(['/usr/bin/sandbox-exec','-p',policy,*probe],capture_output=True).returncode:
            raise RuntimeError('original root denial ineffective')
        isolated=['/usr/bin/sandbox-exec','-p',policy,str(binary),'testnet-inspect-recovery',str(output)]
        if run(isolated)!=reports[role]:raise RuntimeError('self-contained verification changed')
    if reports['alice']['bundle_digest']!=reports['bob']['bundle_digest']:
        raise RuntimeError('different accepted bundles')
    return {'scope':'offline portable public-profile native bundles; synthetic nonexistent inputs',
        'bundle_digest':reports['alice']['bundle_digest'],
        'both_portable_exports_verified':True,'original_source_and_both_owner_roots_denied':True,
        'export_contains_only_bundle_receipt_and_report':True,'idempotent_export':True,
        'spending_keys_exported':False,'live_witness_or_reproving_executed':False,
        'funding_authorized':False,'broadcast':False}


if __name__=='__main__':
    os.umask(0o077)
    print(json.dumps(check(*(Path(p).resolve() for p in sys.argv[1:3])),indent=2))
