#!/usr/bin/env python3
"""Check peer-move reconciliation against copied public identity metadata only.

No spending keys, native proof/signature files, or ETH signed transactions copied.
Fixture agreement metadata remains private under .local.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
from peer_workspace import identity, reconcile
from regtest_wallet import save


def fixture(source, root):
    root.mkdir(mode=0o700)
    for name in ['agreement.json','owner-flow.json']:
        shutil.copyfile(source/name,root/name)
    for role in ('alice','bob'):
        target=root/'owners'/role
        (target/'recovery').mkdir(mode=0o700,parents=True)
        for name in ['identity.json','eth-agreement.json','eth-acceptance.json','recovery/recovery-ready.json']:
            shutil.copyfile(source/'owners'/role/name,target/name)
    entry={'version':1,'role':'alice','id':'synthetic-test',
        'binding':identity(root,root/'owners/alice','alice')}
    save(root/'peer-offline.json',entry)
    (root/'owners/alice').rename(root/'owners/alice-offline')


def change(path, mutate):
    v=json.loads(path.read_text());mutate(v);path.write_text(json.dumps(v))


def check(source,directory):
    directory.mkdir(mode=0o700)
    cases={
      'missing_move_journal':lambda d:(d/'peer-offline.json').unlink(),
      'duplicate_workspaces':lambda d:shutil.copytree(d/'owners/alice-offline',d/'owners/alice'),
      'invalid_role':lambda d:change(d/'peer-offline.json',lambda v:v.update(role='../bob')),
      'changed_identity':lambda d:change(d/'owners/alice-offline/identity.json',lambda v:v.update(address='0x'+'00'*20)),
      'changed_acceptance':lambda d:change(d/'owners/alice-offline/eth-acceptance.json',lambda v:v.update(agreement_digest='00'*32)),
      'changed_recovery_role':lambda d:change(d/'owners/alice-offline/recovery/recovery-ready.json',lambda v:v.update(mode='claim')),
      'changed_binding':lambda d:change(d/'peer-offline.json',lambda v:v['binding'].update(agreement_digest='00'*32)),
    }
    for name,mutate in cases.items():
        root=directory/name;fixture(source,root);mutate(root)
        names=sorted(str(p.relative_to(root)) for p in root.rglob('*'))
        try:reconcile(root)
        except RuntimeError:pass
        else:raise RuntimeError('changed peer metadata accepted: '+name)
        if names!=sorted(str(p.relative_to(root)) for p in root.rglob('*')):
            raise RuntimeError('rejected peer metadata changed workspace paths')
    restored=[]
    for phase in ['after-rename','before-rename-or-after-restore']:
        root=directory/phase;fixture(source,root)
        if phase!='after-rename':(root/'owners/alice-offline').rename(root/'owners/alice')
        result=reconcile(root)
        if result['directory_restored']!=(phase=='after-rename') or reconcile(root) is not None:
            raise RuntimeError('peer move replay mismatch')
        restored.append(phase)
    return {'scope':'copied identity/acceptance metadata, no keys or signed transactions',
        'rejected':list(cases),'successful_reconciliation':restored,'replay_noop':True,
        'rejected_cases_do_not_move_directories':True}


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('source',type=Path);p.add_argument('directory',type=Path)
    a=p.parse_args();os.umask(0o077)
    print(json.dumps(check(a.source.resolve(),a.directory.resolve()),indent=2))
