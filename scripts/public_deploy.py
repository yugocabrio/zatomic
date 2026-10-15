#!/usr/bin/env python3
"""Pinned nonce-zero Sepolia deployment with exact-byte restart and receipts.

Check-only by default. --broadcast-testnet explicitly signs/submits; requires
human authorization. No swap secret, owner key or claim calldata is used here.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time
import uuid
import evm_wallet as wallet
import probe_sepolia as rpcmod
from public_agreement import validate_policy
from public_authority import owner_locked
from public_outgoing import private_directory, immutable, publish_raw, raw_bytes
from public_eth_execute import send_raw
from regtest_wallet import ROOT
from source_inputs import publish
from testnet_wallet import read

GAS = 1_000_000


def specification(owner, gas_cap):
    policy = validate_policy()
    if type(gas_cap) is not int or not 0 < gas_cap <= policy['fee_policy']['max_gas_price_wei']:
        raise RuntimeError('unsupported deployment fee ceiling')
    identity = read(owner/'identity.json')
    public = bytes.fromhex(identity['public_key'])
    sender = '0x'+wallet.keccak(public[1:])[-20:].hex()
    if len(public) != 65 or public[0] != 4 or identity['chain_id'] != rpcmod.CHAIN_ID or identity['address'] != sender:
        raise RuntimeError('dedicated Sepolia deployer identity required')
    artifact = json.loads((ROOT/'.local/forge-out/PointEscrow.sol/PointEscrow.json').read_text())
    code = bytes.fromhex(artifact['bytecode']['object'].removeprefix('0x'))
    runtime = bytes.fromhex(artifact['deployedBytecode']['object'].removeprefix('0x'))
    for name, data in [('creation_code_hash', code), ('runtime_code_hash', runtime)]:
        if '0x'+wallet.keccak(data).hex() != policy['escrow'][name]:
            raise RuntimeError('compiled escrow differs from pinned code')
    address = '0x'+wallet.keccak(wallet.rlp([bytes.fromhex(sender[2:]), 0]))[-20:].hex()
    return {'format': 'latch-sepolia-deployment-v1', 'chain_id': rpcmod.CHAIN_ID,
        'genesis': rpcmod.GENESIS, 'sender': sender, 'nonce': 0, 'gas': GAS,
        'gas_price_wei': gas_cap, 'value_wei': 0, 'contract': address,
        'creation_code_hash': policy['escrow']['creation_code_hash'],
        'runtime_code_hash': policy['escrow']['runtime_code_hash']}, code


def verify_raw(raw, spec, code):
    p = subprocess.run(['cast', 'decode-transaction', '--json'], input='0x'+raw.hex()+'\n',
        text=True, capture_output=True, check=True, timeout=15)
    tx = json.loads(p.stdout)
    expected = {'type': 0, 'chainId': spec['chain_id'], 'nonce': 0, 'value': 0,
        'gas': spec['gas'], 'gasPrice': spec['gas_price_wei']}
    if (any(rpcmod.quantity(tx[k]) != v for k,v in expected.items()) or tx['to'] is not None
            or tx['signer'].lower() != spec['sender'] or tx['input'].lower() != '0x'+code.hex()
            or tx['hash'].lower() != '0x'+wallet.keccak(raw).hex()):
        raise RuntimeError('retained deployment differs from exact pinned transaction')
    return tx['hash'].lower()


def sign(owner, spec, code):
    fields = [0, spec['gas_price_wei'], spec['gas'], b'', 0, code]
    s = wallet.sign_digest(owner, wallet.keccak(wallet.rlp(fields+[spec['chain_id'],0,0])))
    if s['parity'] not in (0,1): raise RuntimeError('invalid signing parity')
    raw = wallet.rlp(fields+[2*spec['chain_id']+35+s['parity'],int(s['r'],16),int(s['s'],16)])
    verify_raw(raw, spec, code)
    return raw


def receipt(spec, code, txid, rpc, blocks):
    tx = rpc('eth_getTransactionByHash',[txid])
    got = rpc('eth_getTransactionReceipt',[txid])
    if tx is None:
        if got is not None: raise RuntimeError('receipt without exact transaction')
        return {'state': 'unobserved', 'txid': txid}
    expected = {'type':0,'chainId':spec['chain_id'],'nonce':0,'value':0,'gas':spec['gas'],'gasPrice':spec['gas_price_wei']}
    if (tx['hash'] != txid or tx['from'] != spec['sender'] or tx['to'] is not None
            or tx['input'] != '0x'+code.hex() or any(rpcmod.quantity(tx[k])!=v for k,v in expected.items())):
        raise RuntimeError('provider deployment transaction mismatch')
    if got is None:
        if tx['blockHash'] is not None: raise RuntimeError('mined transaction receipt unavailable')
        return {'state':'pending','txid':txid}
    height = rpcmod.quantity(got['blockNumber']); index = rpcmod.quantity(got['transactionIndex'])
    block = rpc('eth_getBlockByNumber',[hex(height),False])
    status = rpcmod.quantity(got['status'])
    if (status not in (0,1) or got['transactionHash'] != txid or got['from'] != spec['sender']
            or got['to'] is not None or got['blockHash'] != tx['blockHash']
            or got['blockNumber'] != tx['blockNumber'] or got['transactionIndex'] != tx['transactionIndex']
            or not block or block['hash'] != got['blockHash'] or block['number'] != hex(height)
            or height > blocks['latest']['height'] or index >= len(block['transactions'])
            or block['transactions'][index] != txid or rpcmod.quantity(got['gasUsed']) > spec['gas']
            or rpcmod.quantity(got['effectiveGasPrice']) != spec['gas_price_wei']):
        raise RuntimeError('deployment receipt not canonical/exact')
    if status:
        if got['contractAddress'] != spec['contract']: raise RuntimeError('unexpected CREATE address')
        for tag in ({'blockHash': block['hash'], 'requireCanonical': True}, 'latest'):
            runtime = rpc('eth_getCode',[spec['contract'],tag])
            if not re.fullmatch(r'0x(?:[0-9a-f]{2}){1,24576}',runtime) or '0x'+wallet.keccak(bytes.fromhex(runtime[2:])).hex()!=spec['runtime_code_hash']:
                raise RuntimeError('deployed runtime hash mismatch')
    if rpc('eth_getBlockByNumber',[hex(height),False]) != block:
        raise RuntimeError('deployment block changed')
    return {'state': ('finalized-by-provider' if height<=blocks['provider_finalized']['height'] else 'confirming') if status else 'reverted',
        'txid':txid,'contract':spec['contract'],'height':height,'block_hash':block['hash'],
        'gas_used':rpcmod.quantity(got['gasUsed']),'runtime_verified':bool(status), 'provider_trusted':True}


def fresh_unsigned(spec, rpc, blocks):
    tag={'blockHash':blocks['latest']['hash'],'requireCanonical':True}
    for state in (tag, 'pending'):
        if rpcmod.quantity(rpc('eth_getTransactionCount',[spec['sender'],state])) != 0:
            raise RuntimeError('deployer nonce is used/pending; reconcile exact existing transaction')
        if rpcmod.quantity(rpc('eth_getBalance',[spec['sender'],state])) < spec['gas']*spec['gas_price_wei']:
            raise RuntimeError('insufficient deployer gas reserve')
    if max(rpcmod.quantity(rpc('eth_gasPrice')),blocks['latest']['base_fee_wei']+blocks['suggested_priority_fee_wei']) > spec['gas_price_wei']:
        raise RuntimeError('current fee exceeds deployment ceiling')
    if rpc('eth_getCode',[spec['contract'],tag]) != '0x': raise RuntimeError('expected CREATE address already contains code')
    for key in ('latest','provider_finalized'):
        if rpcmod.block(hex(blocks[key]['height']),rpc) != blocks[key]: raise RuntimeError('canonical deployment context changed')
    if not -60 <= int(time.time())-blocks['latest']['timestamp'] <= 120:
        raise RuntimeError('stale deployment context')


def execute(owner, gas_cap, endpoint, broadcast=False):
    with owner_locked(owner):
        spec, code = specification(owner,gas_cap)
        folder=owner/'deployment'; private_directory(folder)
        if (folder/'intent.json').exists(): immutable(folder/'intent.json',spec)
        raw=None; txid=None
        if (folder/'transaction.hex').exists():
            if not (folder/'intent.json').exists(): raise RuntimeError('raw deployment without retained intent')
            raw=raw_bytes(folder/'transaction.hex'); txid=verify_raw(raw,spec,code)
        rpc=rpcmod.ReadOnlyRpc(endpoint); blocks=rpcmod.observe(rpc,endpoint)
        if not blocks['rpc_genesis_verified']: raise RuntimeError('Sepolia genesis observation incomplete')
        if txid:
            observed=receipt(spec,code,txid,rpc,blocks)
            publish(folder/('receipt-'+uuid.uuid4().hex+'.json'),observed)
            if observed['state'] != 'unobserved': return observed
        fresh_unsigned(spec,rpc,blocks)
        result=dict(spec,state='ready-for-explicit-testnet-deployment',broadcast=False,required_balance_wei=GAS*gas_cap)
        if not broadcast: return result
        immutable(folder/'intent.json',spec) # Durable before signing, immutable on retry.
        if raw is None:
            raw=sign(owner,spec,code); publish_raw(folder/'transaction.hex',raw)
            txid=verify_raw(raw,spec,code)
        # Revalidate even on a signed-byte restart; no automatic fee/nonce change.
        fresh_unsigned(spec,rpc,blocks)
        attempt=folder/('attempt-'+uuid.uuid4().hex); private_directory(attempt)
        publish(attempt/'intent.json',{'txid':txid,'bytes_sha256':hashlib.sha256(raw).hexdigest(),'may_have_reached_network':True})
        try:
            if send_raw(endpoint,'0x'+raw.hex()) != txid: raise RuntimeError('unexpected hash')
            result={'state':'submitted','txid':txid,'receipt_required':True}
        except Exception:
            result={'state':'uncertain','txid':txid,'receipt_required':True}
        publish(attempt/'result.json',result)
        return result


def main():
    os.umask(0o077)
    p=argparse.ArgumentParser(description=__doc__); p.add_argument('owner',type=Path)
    p.add_argument('--eth-rpc',required=True); p.add_argument('--gas-cap-wei',type=int,default=1_000_000_000)
    p.add_argument('--broadcast-testnet',action='store_true')
    a=p.parse_args(); result=execute(a.owner.resolve(),a.gas_cap_wei,a.eth_rpc,a.broadcast_testnet)
    print(json.dumps(result,indent=2))
    return 0 if result['state']=='finalized-by-provider' else 2


if __name__=='__main__':
    try: raise SystemExit(main())
    except (RuntimeError,OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError):
        raise SystemExit('Deployment stopped. Preserve private intent/bytes; reconcile their exact hash before retrying.') from None
