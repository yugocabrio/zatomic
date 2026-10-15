#!/usr/bin/env python3
"""Reject changed withdrawal history using copied signed fixture calls only.

No keys, wallet, PCZT or native bundle is copied; no transaction is broadcast.
Signed calls remain private under .local, including the already-revealed claim
used to check action substitution. Only rejection names are returned.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
from evm_participant import withdrawal_attempts


def read(path):return json.loads(path.read_text())


def change(path, mutate):
    value=read(path);mutate(value);path.write_text(json.dumps(value))


def check(source,directory):
    owner=source/'owners/alice'
    agreement=read(source/'agreement.json')
    address=read(owner/'identity.json')['address']
    if len(withdrawal_attempts(owner,agreement,address))!=2:
        raise RuntimeError('requires original and one valid additional attempt')
    directory.mkdir(mode=0o700)
    def extra(root):return root/'eth-withdraw-attempts/000001.json'
    def duplicate_nonce(root):
        original=read(root/'eth-intent-withdraw.json')
        original['withdrawal_predecessor']=original['txid']
        extra(root).write_text(json.dumps(original))
    def wrong_action(root):
        claim=read(owner/'eth-intent-claim.json')
        claim['withdrawal_predecessor']=read(root/'eth-intent-withdraw.json')['txid']
        extra(root).write_text(json.dumps(claim))
    def symlink_folder(root):
        folder=root/'eth-withdraw-attempts';folder.rename(root/'hidden')
        folder.symlink_to(root/'hidden',target_is_directory=True)
    cases={
        'missing_original':lambda r:(r/'eth-intent-withdraw.json').unlink(),
        'missing_sequence':lambda r:extra(r).rename(r/'eth-withdraw-attempts/000002.json'),
        'changed_predecessor':lambda r:change(extra(r),lambda v:v.update(withdrawal_predecessor='0x'+'00'*32)),
        'duplicated_nonce':duplicate_nonce,
        'signed_claim_substituted_for_withdrawal':wrong_action,
        'signed_payload_metadata_changed':lambda r:change(extra(r),lambda v:v['transaction'].update(value='0x1')),
        'changed_signed_hash':lambda r:change(extra(r),lambda v:v.update(txid='0x'+'00'*32)),
        'symlink_history_directory':symlink_folder,
    }
    for name,mutate in cases.items():
        root=directory/name;root.mkdir(mode=0o700)
        shutil.copyfile(owner/'eth-intent-withdraw.json',root/'eth-intent-withdraw.json')
        (root/'eth-withdraw-attempts').mkdir(mode=0o700)
        shutil.copyfile(owner/'eth-withdraw-attempts/000001.json',extra(root))
        mutate(root)
        try:withdrawal_attempts(root,agreement,address)
        except (RuntimeError,ValueError,KeyError):pass
        else:raise RuntimeError('changed withdrawal history accepted: '+name)
    return {'scope':'actual signed fixture calls, offline validation only',
        'valid_original_and_attempt_accepted':True,'rejected':list(cases),
        'no_keys_copied':True,'no_transactions_sent':True}


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('source',type=Path);p.add_argument('directory',type=Path)
    a=p.parse_args();os.umask(0o077)
    print(json.dumps(check(a.source.resolve(),a.directory.resolve()),indent=2))
