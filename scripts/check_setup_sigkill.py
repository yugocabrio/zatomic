#!/usr/bin/env python3
"""Kill the actual setup parent after DKG; reap owned workers, then cancel.

Requires an existing unspent success-only fixture bank. No native transaction
is broadcast. Checks only children of the exact process started here; signals
only that parent, never discovered worker PIDs.
"""
import argparse
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import time
from regtest_node import ROOT, status, rpc
from regtest_wallet import NATIVE, save
from check_recovery_sigkill import wait_free
from check_setup_cancellation import check as cancel_check


def children(parent):
    rows = []
    for line in subprocess.check_output(['ps','-axo','pid=,ppid=,command='],text=True).splitlines():
        values = line.strip().split(None,2)
        if len(values) == 3:
            rows.append((int(values[0]),int(values[1]),values[2]))
    owned = {parent}
    while True:
        extra = {pid for pid,ppid,_ in rows if ppid in owned} - owned
        if not extra: break
        owned.update(extra)
    return [(pid,command) for pid,_,command in rows if pid in owned and pid != parent]


def check(directory, bank):
    if directory.exists(): raise RuntimeError('requires a fresh private fixture directory')
    before, pool = status()['tip'], rpc('getrawmempool')
    log_path = directory.with_name(directory.name+'-parent-kill.log')
    args = [sys.executable,str(ROOT/'scripts/prefunding_swap.py'),'success',str(directory),
            '--existing-bank',str(bank)]
    with log_path.open('x') as log:
        process = subprocess.Popen(args,stdout=log,stderr=log,
            env=dict(os.environ,RAYON_NUM_THREADS='2'))
        try:
            deadline = time.monotonic()+180
            while not (directory/'swap/joint-fvk.bin').exists():
                if process.poll() is not None or time.monotonic()>deadline:
                    raise RuntimeError('native DKG boundary not reached; inspect private log')
                time.sleep(.05)
            observed = children(process.pid)
            native = [pid for pid,command in observed if command.startswith(str(NATIVE)+' regtest-stage ')]
            # macOS ps may show Python.app's real executable instead of the
            # Homebrew launcher used in argv[0]. Match the script argument.
            servers = [pid for pid,command in observed
                if len(command.split(None,1))==2
                and command.split(None,1)[1].startswith(str(ROOT/'scripts/signer_transport.py')+' serve ')]
            if len(native)!=1 or len(servers)!=2:
                raise RuntimeError(f'expected one native worker and two TLS servers; found {len(native)}, {len(servers)}')
            process.kill(); process.wait(timeout=10)
            if process.returncode != -signal.SIGKILL:
                raise RuntimeError('setup parent was not SIGKILLed')
        finally:
            if process.poll() is None: process.kill(); process.wait(timeout=10)
    wait_free()
    for port in (18641,18642):
        with socket.socket() as probe:
            probe.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
            probe.bind(('127.0.0.1',port))
    # The lease may drop just before a guardian's final process exit.
    deadline = time.monotonic()+5
    remaining = {pid for pid,_ in observed}
    while remaining:
        for pid in list(remaining):
            try: os.kill(pid,0)
            except ProcessLookupError: remaining.remove(pid)
        if remaining and time.monotonic()>deadline:
            raise RuntimeError('owned descendants survived setup parent death')
        time.sleep(.02)
    if before!=status()['tip'] or pool!=rpc('getrawmempool'):
        raise RuntimeError('setup crash changed the native chain')
    cancellation = cancel_check(directory)
    result = {'scope':'actual TLS DKG and native preparation on one host, parent SIGKILL',
        'parent_sigkill':True,'native_stage_worker_reaped':True,'both_tls_services_reaped':True,
        'all_observed_descendants_reaped':True,'tls_ports_released':True,
        'chain_lease_released_after_cleanup':True,'cancellation':cancellation}
    save(directory/'setup-sigkill-checks.json',result)
    return result


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('directory',type=Path); p.add_argument('--existing-bank',type=Path,required=True)
    a=p.parse_args(); os.umask(0o077)
    print(json.dumps(check(a.directory.resolve(),a.existing_bank.resolve()),indent=2))
