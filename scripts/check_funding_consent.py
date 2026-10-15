#!/usr/bin/env python3
"""Adversarial release gate against an actual, still-unfunded signed fixture."""
import argparse
import copy
import json
import os
from pathlib import Path
import subprocess
import run_native_evm_gate as evm
import owner_swap as owners
from funding_wallet import authorize
from regtest_wallet import native, save, NATIVE
from run_client_swap import client


def run(directory):
    staged = directory / 'coordinator-native-offline'
    packet = owners.read(directory / 'consent-packet.json')
    if (staged / 'funding.hex').exists():
        raise RuntimeError('requires an unreleased signed offer')
    bank = owners.read(directory / 'setup.json')['bank']
    cases = []
    def changed(name, mutate):
        value = copy.deepcopy(packet)
        mutate(value)
        cases.append((name,value))
    changed('missing_bob_signature', lambda p: p['consents'].pop('bob'))
    for field, value in [('amount_wei',10**16+1), ('eth_expiry',packet['agreement']['eth_expiry']+1),
                         ('eth_chain_id',1), ('eth_salt','0x'+'ff'*32),
                         ('recipient',packet['agreement']['maker'])]:
        changed('changed_'+field, lambda p,f=field,v=value: p['agreement'].__setitem__(f,v))
    changed('changed_native_funding',lambda p:p['agreement']['native'].__setitem__('funding_txid','00'*32))
    changed('changed_native_bundle',lambda p:p['consents']['bob']['payload'].__setitem__('bundle_digest','00'*32))
    changed('wrong_owner_signature',lambda p:p['consents']['bob'].__setitem__('signature',p['consents']['alice']['signature']))
    changed('invalid_signature',lambda p:p['consents']['bob']['signature'].__setitem__('r','00'*32))
    changed('invalid_recovery_parity',lambda p:p['consents']['bob']['signature'].__setitem__('parity',2))
    changed('role_replay',lambda p:p['consents']['bob']['payload'].__setitem__('role','alice'))
    secp_order = int('fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141',16)
    changed('high_s_signature',lambda p:p['consents']['bob']['signature'].__setitem__('s',
        f"{secp_order-int(p['consents']['bob']['signature']['s'],16):064x}"))
    checks = directory / 'consent-negative-cases'
    checks.mkdir(mode=0o700)
    with owners.chain_lock(), owners.node(directory,restore=True):
        verified = native('regtest-check-consent',staged,directory / 'consent-packet.json')
        for name, value in cases:
            path = checks / f'{name}.json'
            save(path,value)
            result = subprocess.run([str(NATIVE),'regtest-authorize-funding',bank,str(staged),str(path)],
                capture_output=True,text=True,env=dict(os.environ,RAYON_NUM_THREADS='2'))
            if result.returncode == 0 or result.stdout or (staged / 'funding.hex').exists() or (directory / 'source-release.json').exists():
                raise RuntimeError('source authorization mutation did not fail before release: '+name)
        client('lock',directory / 'owners/bob',{'salt':packet['agreement']['eth_salt']},reject=True)
        evm.rpc('evm_setNextBlockTimestamp',[packet['agreement']['eth_expiry']])
        evm.rpc('evm_mine')
        try:
            authorize(Path(bank),staged,directory / 'consent-packet.json')
        except RuntimeError as exc:
            if 'expired funding window' not in str(exc):
                raise
        else:
            raise RuntimeError('source wallet released stale signed offer')
        if (staged / 'funding.hex').exists() or (directory / 'source-release.json').exists():
            raise RuntimeError('negative gates exposed funding or committed release')
    return {'scope':'actual staged native graph and signed owner offer; no swap funding broadcast',
        'both_owner_signatures_verified':verified['both_owner_signatures_verified'],
        'source_release_rejections':[name for name,_ in cases],
        'owner_lock_before_native_funding_rejected':True,'stale_source_release_rejected':True,
        'broadcastable_funding_file_absent':True,'node_checkpoint_preserved':True}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory',type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    print(json.dumps(run(args.directory.resolve()),indent=2))
