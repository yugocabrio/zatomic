#!/usr/bin/env python3
"""Offline public-testnet owner setup; no RPC, funding, or transaction signing.

Run separately on each owner's machine. Authenticate identity fingerprints out
of band. Exchange all setup files privately over an authenticated encrypted
channel: round2 contains secret DKG material and FVKs disclose viewing access.
This CLI writes packets to private files, never to the terminal.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import evm_wallet
import otc_offer
import timestamp_policy
from regtest_wallet import native, save

CHAIN = 11155111
ACTIONS = ('init','identity','trust-peer','offer-create','offer-review','offer-accept',
    'setup-start','setup-round2','setup-finish','setup-agree','verify-destinations','graph-review')


def fingerprint(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()


def identity(value, role):
    if set(value) != {'role','chain_id','public_key','address'} or value['role'] != role or role not in ('alice','bob') or type(value['chain_id']) is not int or value['chain_id'] != CHAIN:
        raise RuntimeError('public-testnet identity schema/role/chain mismatch')
    public = bytes.fromhex(value['public_key'])
    if len(public) != 65 or public[0] != 4 or public.hex() != value['public_key']:
        raise RuntimeError('canonical uncompressed identity key required')
    prime = 2**256-2**32-977
    x,y = int.from_bytes(public[1:33]),int.from_bytes(public[33:])
    if x >= prime or y >= prime or (y*y-x*x*x-7)%prime:
        raise RuntimeError('identity key not on secp256k1')
    if value['address'] != '0x'+evm_wallet.keccak(public[1:])[-20:].hex():
        raise RuntimeError('identity address does not match its key')
    return value


def execute(directory, action, packet, role=None, incoming=None):
    if action == 'init':
        if role not in ('alice','bob'):
            raise RuntimeError('owner role required')
        public = native('evm-key-init',directory/'ethereum')['public_key']
        own = {'role':role,'chain_id':CHAIN,'public_key':public,
            'address':'0x'+evm_wallet.keccak(bytes.fromhex(public)[1:])[-20:].hex()}
        identity(own,role)
        save(directory/'identity.json',own)
        return {'identity':own,'identity_sha256':fingerprint(own)}
    own = otc_offer.read(directory/'identity.json')
    identity(own,own['role'])
    peer = 'bob' if own['role']=='alice' else 'alice'
    if action == 'identity':
        return {'identity':own,'identity_sha256':fingerprint(own)}
    if action == 'trust-peer':
        candidate = identity(packet['identity'],peer)
        if packet['expected_identity_sha256'] != fingerprint(candidate):
            raise RuntimeError('peer fingerprint differs from independently authenticated input')
        if candidate['public_key'] == own['public_key']:
            raise RuntimeError('distinct owners required')
        save(directory/'trusted-peer.json',{'identity':candidate})
        return {'trusted_peer':peer,'identity_sha256':fingerprint(candidate)}
    trusted = otc_offer.read(directory/'trusted-peer.json')['identity']
    identity(trusted,peer)
    if action.startswith('offer-'):
        return otc_offer.execute(directory,action,packet)
    # Verify the local accepted quote and pinned identities before native DKG.
    # The native state machine independently repeats this verification.
    accepted = otc_offer.read(directory/'accepted-trade.json')
    otc_offer.verify(directory,accepted,True)
    if action == 'graph-review':
        timestamp_policy.validate(packet['plan'])
        result = native('testnet-owner-review',directory,incoming)
        return dict(result, candidate_clock_bounds_validated=True,
            live_clock_or_chain_checked=False)
    if action == 'verify-destinations':
        if packet['trade'] != accepted:
            raise RuntimeError('destinations belong to another accepted quote')
        return native('testnet-setup-verify',incoming)
    if action.startswith('setup-'):
        args = ['testnet-owner-setup',directory,action.removeprefix('setup-')]
        if action != 'setup-start':
            args.append(incoming)
        return native(*args)
    raise RuntimeError('unsupported owner setup action')


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('action',choices=ACTIONS)
    p.add_argument('directory',type=Path)
    p.add_argument('--role',choices=('alice','bob'))
    p.add_argument('--packet',type=Path)
    p.add_argument('--out',type=Path,required=True)
    a=p.parse_args()
    os.umask(0o077)
    directory=a.directory.absolute()
    if a.action=='init':
        directory.mkdir(mode=0o700)
    meta=directory.lstat()
    if not stat.S_ISDIR(meta.st_mode) or meta.st_mode & 0o077:
        raise RuntimeError('private owner directory required')
    fd=os.open(directory/'operator.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    try:
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        incoming=a.packet.absolute() if a.packet else None
        packet=otc_offer.read(incoming) if incoming else {}
        result=execute(directory,a.action,packet,a.role,incoming)
        if a.out.is_symlink() or (a.out.exists() and otc_offer.read(a.out)!=result):
            raise RuntimeError('output already contains another message')
        parent=a.out.absolute().parent
        if parent.is_symlink() or parent.stat().st_mode & 0o077:
            raise RuntimeError('output must be in a private directory')
        save(a.out,result)
        print(json.dumps({'file':str(a.out.absolute()),'action':a.action,
            'packet_sha256':fingerprint(result),'funding_authorized':False,'broadcast':False}))
    finally:
        os.close(fd)


if __name__=='__main__':
    try:
        main()
    except (OSError,RuntimeError,ValueError,KeyError,TypeError,subprocess.SubprocessError):
        print('Owner setup rejected; private state retained.',file=sys.stderr)
        sys.exit(1)
