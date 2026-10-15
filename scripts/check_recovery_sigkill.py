#!/usr/bin/env python3
"""Actually kill recovery before, during and after a real native exit.

Use an existing current-driver fixture paused at eth-claimed / eth-locked.
Kills only the subprocess this checker launched; guardians clean their owned
workers. No process-name kills and no rollback of the native chain.
"""
import argparse
import fcntl
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import time
from regtest_node import ROOT, status, rpc
from regtest_wallet import save
import run_native_evm_gate as evm


def busy():
    with (ROOT/'.local/chain-driver.lock').open('a') as handle:
        try: fcntl.flock(handle,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError: return True
        return False


def wait_free():
    deadline=time.monotonic()+20
    while busy():
        if time.monotonic()>deadline: raise RuntimeError('chain lease survived cleanup timeout')
        time.sleep(.05)
    with socket.socket() as probe:
        probe.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        probe.bind(('127.0.0.1',evm.PORT))


def native_worker(directory):
    # Read exact child command identity, but never retain its witness argv.
    listing=subprocess.check_output(['ps','-axo','pid=,command='],text=True)
    prefix=str(ROOT/'target/release/shielded-swap-native')+' regtest-finish '
    for line in listing.splitlines():
        parts=line.strip().split(None,1)
        if len(parts)!=2:continue
        pid,command=parts
        if command.startswith(prefix) and str(directory/'owners') in command:
            return int(pid)
    return None


def check(directory):
    if (directory/'08-complete.json').exists():raise RuntimeError('requires interrupted fixture')
    mode=json.loads((directory/'setup.json').read_text())['mode']
    peer='alice' if mode=='success' else 'bob'
    observations=[]
    for phase in ['native-peer-offline','native-proof-active','native-exit-confirmed']:
        progress = directory / f'sigkill-phase-{phase}.json'
        if progress.exists():
            observations.append(json.loads(progress.read_text()))
            continue
        args=[sys.executable,str(ROOT/'scripts/prefunding_swap.py'),'recover',str(directory)]
        if phase!='native-proof-active':args+=['--fault-after',phase]
        before=status()['tip']; pool=rpc('getrawmempool')
        worker=None
        with (directory/f'kill-{phase}.log').open('w') as log:
            process=subprocess.Popen(args,stdout=log,stderr=log,env=dict(os.environ,RAYON_NUM_THREADS='2'))
            try:
                if phase=='native-proof-active':
                    deadline=time.monotonic()+120
                    while worker is None:
                        if process.poll() is not None or time.monotonic()>deadline:
                            raise RuntimeError('real native proof did not become active')
                        worker=native_worker(directory)
                        time.sleep(.05)
                    process.kill()
                process.wait(timeout=240)
                if process.returncode!=-signal.SIGKILL:
                    raise RuntimeError('recovery did not stop with SIGKILL: '+phase)
            finally:
                if process.poll() is None:
                    process.kill();process.wait(timeout=10)
        wait_free()
        if worker:
            try: os.kill(worker,0)
            except ProcessLookupError: pass
            else: raise RuntimeError('native prover survived parent death')
        if not (directory/'peer-offline.json').is_file() or (directory/'owners'/peer).exists() or not (directory/'owners'/(peer+'-offline')).is_dir():
            raise RuntimeError('peer directory was not offline at crash')
        if (phase=='native-proof-active' or phase=='native-peer-offline' and mode=='success') and (before!=status()['tip'] or pool!=rpc('getrawmempool')):
            raise RuntimeError('pre-exit crash unexpectedly changed native chain')
        observation = {'phase':phase,'sigkill':True,'peer_directory_offline':True,
            'owned_evm_port_released':True,'chain_lease_released_after_cleanup':True,
            'native_worker_reaped':True if worker else None}
        save(progress,observation)
        observations.append(observation)
    values=[]
    for attempt in range(2):
        result=subprocess.run([sys.executable,str(ROOT/'scripts/prefunding_swap.py'),'recover',str(directory)],
            capture_output=True,text=True,env=dict(os.environ,RAYON_NUM_THREADS='2'),timeout=180)
        (directory/f'sigkill-resume-{attempt+1}.log').write_text(result.stdout+'\n'+result.stderr)
        if result.returncode:raise RuntimeError('recovery after SIGKILL failed; private diagnostics retained')
        value=json.loads(result.stdout);values.append(value)
        if value['new_native_transactions']!=0:raise RuntimeError('confirmed exit was resubmitted')
    if values[-1]['new_evm_transactions']!=0:raise RuntimeError('repeat recovery duplicated ETH action')
    if not all((directory/'owners'/role).is_dir() for role in ('alice','bob')) or (directory/'peer-offline.json').exists():
        raise RuntimeError('owner layout not restored after recovery')
    outcome={'scope':'actual local chain recovery SIGKILL; owned guardians remain alive',
        'mode':mode,'stops':observations,'first_recovery':values[0],'repeat':values[1],
        'owner_layout_restored':True,'public_testnet':False}
    save(directory/'sigkill-checks.json',outcome)
    return outcome


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('directory',type=Path)
    a=p.parse_args();os.umask(0o077)
    print(json.dumps(check(a.directory.resolve()),indent=2))
