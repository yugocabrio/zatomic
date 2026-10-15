#!/usr/bin/env python3
"""SIGKILL immutable journal writers immediately before/after publication."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from regtest_node import ROOT
from regtest_wallet import save

CHILD = '''
import os, sys, time
from pathlib import Path
from regtest_wallet import save
root, phase = Path(sys.argv[1]), sys.argv[2]
def stopped(*args, **kwargs):
    (root / (phase + '-waiting')).touch(mode=0o600)
    time.sleep(60)
if phase == 'before': os.link = stopped
else: os.unlink = stopped
save(root / (phase + '.json'), {'complete': True, 'padding': 'x' * 100000})
'''


def check(directory):
    directory.mkdir(mode=0o700)
    for phase in ('before','after'):
        process = subprocess.Popen([sys.executable,'-c',CHILD,str(directory),phase],
            env=dict(os.environ,PYTHONPATH=str(ROOT/'scripts')))
        try:
            deadline = time.monotonic() + 10
            while not (directory / (phase+'-waiting')).exists():
                if process.poll() is not None or time.monotonic() > deadline:
                    raise RuntimeError('writer did not reach crash boundary')
                time.sleep(.01)
            process.kill()
            process.wait(timeout=5)
        finally:
            if process.poll() is None:
                process.kill(); process.wait(timeout=5)
        target = directory / (phase+'.json')
        if phase == 'before' and target.exists():
            raise RuntimeError('unpublished destination became visible')
        value = {'complete':True,'padding':'x'*100000}
        if phase == 'after' and json.loads(target.read_text()) != value:
            raise RuntimeError('published destination truncated')
        save(target,value)
        before = target.read_bytes()
        try:
            save(target,{'different':True})
        except RuntimeError:
            pass
        else:
            raise RuntimeError('immutable journal replaced')
        if target.read_bytes() != before or target.stat().st_mode & 0o077:
            raise RuntimeError('private journal bytes or permissions changed')
    return {'real_sigkill_before_publication':True,'real_sigkill_after_publication':True,
        'destination_absent_or_complete':True,'replay_unchanged':True,'conflicting_write_rejected':True,
        'private_permissions_checked':True,'scope':'synthetic local journals; not full power-loss proof'}


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory',type=Path)
    args=parser.parse_args(); os.umask(0o077)
    print(json.dumps(check(args.directory.resolve()),indent=2))
