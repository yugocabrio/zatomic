#!/usr/bin/env python3
"""Rebuild unsigned F and signed exits from retained real regtest inputs.

Copies a completed fixture's keys into a fresh private root; original state is
read-only. Does not mine, send, fund, or call Ethereum. Historical validity is
not live source spendability. Permanently cancels the new source guard at end.
"""
import json
import os
from pathlib import Path
import shutil
import sys
from regtest_wallet import native, save
from regtest_node import GENESIS
from run_client_swap import client


def check(root, original, scan):
    native('regtest-setup-init',root)
    bank=root/'bank';bank.mkdir(mode=0o700)
    for name in ('spending-key.bin','aux-key.bin','aux-source-compact.json'):
        if (original/name).exists():  # Newer banks hold no transparent coin.
            shutil.copyfile(original/name,bank/name);os.chmod(bank/name,0o600)
    save(bank/'network.json',{'genesis':GENESIS})
    pins={}
    for role in ('alice','bob'):
        owner=root/role;owner.mkdir(mode=0o700)
        pins[role]=client('key-init',owner,role=role)
    save(root/'pins.json',pins)
    terms=native('regtest-stage',bank,scan,root/'swap',root/'pins.json')
    assert terms['exit_circuits_verified_before_funding']
    assert terms['refund_proof_and_shielded_signatures_verified_before_funding']
    assert terms['refund_auxiliary_signature_verified_before_funding']
    assert terms['participant_bundles_acknowledged_before_funding']
    assert (root/'swap/unsigned-funding.pczt').exists()
    assert not (root/'swap/funding.hex').exists()
    cancelled=native('regtest-cancel-setup',root)
    return {'scope':'existing real regtest note/auxiliary history; no live spendability claim',
        'native_exit_proofs_verified':True,'refund_native_and_auxiliary_signatures_verified':True,
        'both_signers_acknowledged':True,'funding_signature_withheld':True,
        'source_cancelled':cancelled,'broadcast':False,'new_blocks':0,'ethereum_rpc':False}


if __name__=='__main__':
    os.umask(0o077)
    print(json.dumps(check(*[Path(p).resolve() for p in sys.argv[1:]]),indent=2))
