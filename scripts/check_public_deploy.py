#!/usr/bin/env python3
"""Real deployment/signature/receipt check on an owned ephemeral Anvil only."""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import urllib.request
import evm_wallet
import owned_process
import probe_sepolia as sepolia
import public_deploy as deploy
from regtest_wallet import save


def check(root):
    root.mkdir(mode=0o700)
    owner=root/'deployer'; identity=evm_wallet.initialize(owner)
    identity['chain_id']=sepolia.CHAIN_ID
    (owner/'identity.json').write_text(json.dumps(identity))
    spec,code=deploy.specification(owner,1_000_000_000)
    raw=deploy.sign(owner,spec,code); txid=deploy.verify_raw(raw,spec,code)
    folder=owner/'deployment'; deploy.private_directory(folder)
    deploy.immutable(folder/'intent.json',spec); deploy.publish_raw(folder/'transaction.hex',raw)
    assert deploy.verify_raw(deploy.raw_bytes(folder/'transaction.hex'),spec,code)==txid
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',0)); port=sock.getsockname()[1]
    def rpc(method,params=None):
        req=urllib.request.Request(f'http://127.0.0.1:{port}',json.dumps({'jsonrpc':'2.0','id':1,'method':method,'params':params or []}).encode(),{'Content-Type':'application/json'})
        with urllib.request.urlopen(req,timeout=5) as response: result=json.load(response)
        if 'error' in result: raise RuntimeError('isolated RPC error')
        return result['result']
    with (root/'anvil.log').open('w') as log, owned_process.popen(['anvil','--port',str(port),'--chain-id',str(sepolia.CHAIN_ID),'--silent'],stdout=log,stderr=log) as process:
        try:
            for _ in range(100):
                try: rpc('eth_chainId'); break
                except OSError: time.sleep(.1)
            else: raise RuntimeError('owned Anvil did not start')
            rpc('anvil_setBalance',[spec['sender'],hex(10**18)])
            estimate=sepolia.quantity(rpc('eth_estimateGas',[{'from':spec['sender'],'data':'0x'+code.hex(),'value':'0x0'}]))
            assert rpc('eth_sendRawTransaction',['0x'+raw.hex()])==txid
            for _ in range(100):
                if rpc('eth_getTransactionReceipt',[txid]) is not None: break
                time.sleep(.05)
            b=sepolia.block('latest',rpc)
            observed=deploy.receipt(spec,code,txid,rpc,{'latest':b,'provider_finalized':b})
            assert observed['state']=='finalized-by-provider' and observed['runtime_verified']
            assert deploy.receipt(spec,code,txid,rpc,{'latest':b,'provider_finalized':b})==observed
            assert rpc('eth_getTransactionCount',[spec['sender'],'latest'])=='0x1'
            for field,value in [('gas_price_wei',2_000_000_000),('sender','0x'+'11'*20)]:
                try: deploy.verify_raw(raw,dict(spec,**{field:value}),code)
                except RuntimeError: pass
                else: raise RuntimeError('changed signed deployment accepted')
            return {'scope':'actual deployment on isolated Anvil with Sepolia chain ID; finality modeled, public chain not used',
                'creation_code_hash':spec['creation_code_hash'],'runtime_code_hash':spec['runtime_code_hash'],
                'gas_estimate':estimate,'gas_used':observed['gas_used'],'gas_limit':spec['gas'],
                'exact_signature_and_runtime_verified':True,'retained_bytes_and_receipt_replay':True,
                'changed_fee_or_signer_rejected':True,'public_deployment':False,'public_transactions':0}
        finally:
            process.terminate(); process.wait(timeout=10)


if __name__=='__main__':
    os.umask(0o077)
    result=check(Path(sys.argv[1]).resolve())
    print(json.dumps(result,indent=2))
