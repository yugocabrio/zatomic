#!/usr/bin/env python3
"""Kill a parent while a nested worker lives; check cleanup and chain lease."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
from regtest_node import ROOT

CHILD = '''
import os, signal, time
from pathlib import Path
from owned_process import popen
code = "import os,signal,time;from pathlib import Path;signal.signal(signal.SIGTERM,lambda *_: (time.sleep(2),exit(0)));Path(%r).write_text(str(os.getpid()));time.sleep(60)" % str(Path(os.environ['CHECK_DIR'])/'grandchild.pid')
with popen([os.sys.executable,'-c',code]):
    time.sleep(60)
'''
PARENT = '''
import os,time
from pathlib import Path
from owned_process import popen
from owner_swap import chain_lock
with chain_lock(), popen([os.sys.executable,'-c',os.environ['CHECK_CHILD']]):
    time.sleep(60)
'''


def busy():
    with (ROOT/'.local/chain-driver.lock').open('a') as handle:
        try:
            fcntl.flock(handle,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:
            return True
        return False


def wait(predicate, seconds=10):
    deadline=time.monotonic()+seconds
    while not predicate():
        if time.monotonic()>deadline:
            raise RuntimeError('owned cleanup did not reach expected state')
        time.sleep(.02)


def check(directory):
    if busy(): raise RuntimeError('another chain operation is active')
    directory.mkdir(mode=0o700)
    foreign=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)'])
    parent=subprocess.Popen([sys.executable,'-c',PARENT],env=dict(os.environ,
        PYTHONPATH=str(ROOT/'scripts'),CHECK_DIR=str(directory),CHECK_CHILD=CHILD))
    try:
        wait(lambda:(directory/'grandchild.pid').exists())
        assert busy()
        parent.kill();parent.wait(timeout=5)
        assert parent.returncode==-signal.SIGKILL
        # Delayed child SIGTERM cleanup must still own the shared chain lease.
        time.sleep(.2)
        if not busy(): raise RuntimeError('chain lease released before nested cleanup')
        wait(lambda:not busy())
        if foreign.poll() is not None: raise RuntimeError('unrelated test process was stopped')
        pid=int((directory/'grandchild.pid').read_text())
        try: os.kill(pid,0)
        except ProcessLookupError: pass
        else: raise RuntimeError('nested worker survived parent death')
        return {'parent_sigkill':True,'nested_worker_reaped':True,
            'chain_lock_held_through_cleanup':True,'unrelated_owned_sentinel_untouched':True,
            'scope':'synthetic local process tree; guardian survives parent death'}
    finally:
        if parent.poll() is None:parent.kill();parent.wait(timeout=5)
        foreign.terminate();foreign.wait(timeout=5)


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('directory',type=Path)
    a=p.parse_args();os.umask(0o077)
    print(json.dumps(check(a.directory.resolve()),indent=2))
