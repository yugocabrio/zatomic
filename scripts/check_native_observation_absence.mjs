#!/usr/bin/env node
// Explicit provider transcripts; no network and no claims about consensus.
import assert from 'node:assert/strict';
import {GENESIS, GrpcError, fields, integer, requireGrpcSuccess} from './lightwallet_rpc.mjs';
import {observeTransaction} from './testnet_observation.mjs';
const txid='01'.repeat(32), tip='02'.repeat(32), height=4505000;
const map=entries=>new Map(entries.map(([key,value])=>[key,[typeof value==='number'?BigInt(value):Buffer.from(value)]]));
const hash=s=>Buffer.from(s,'hex').reverse();
requireGrpcSuccess('GetTransaction',200,'application/grpc+proto','0');
assert.throws(()=>requireGrpcSuccess('GetTransaction',200,'application/grpc','5'),
  e=>e instanceof GrpcError && e.code===5 && e.method==='GetTransaction');
for(const [status,type,code] of [[503,'application/grpc','5'],[200,'text/html','5'],
  [200,'application/grpc-bogus','5'],[200,'application/grpc',undefined],[200,'application/grpc','05']]) {
  assert.throws(()=>requireGrpcSuccess('GetTransaction',status,type,code),e=>!(e instanceof GrpcError));
}
function provider(error=new GrpcError('GetTransaction',5),reorg=false,positive=false) {
  let tipReads=0;
  const call=async(method,request)=>{
    if(method==='GetLightdInfo')return map([[4,'test'],[6,'77190ad9'],[18,'v0.5.0']]);
    if(method==='GetLatestBlock')return map([[1,height],[2,hash(tip)]]);
    if(method==='GetTransaction') {
      if(positive)return map([[1,Buffer.from([1])],[2,0]]);
      throw error;
    }
    if(method==='GetBlock') {
      const h=integer(fields(request),1);
      if(h===1)return map([[2,1],[4,hash(GENESIS)]]);
      assert.equal(h,height);tipReads++;
      return map([[2,height],[3,hash(reorg&&tipReads>1?'03'.repeat(32):tip)],[5,Math.floor(Date.now()/1000)]]);
    }
    throw Error('unexpected provider method');
  };
  return {call,tipReads:()=>tipReads};
}
const p=provider();
const noDecode=()=>{throw Error('negative result must not decode bytes');};
const observation=await observeTransaction(txid,noDecode,p.call);
assert.equal(p.tipReads(),2);
assert.equal(observation.status,'not_found');
assert.equal(observation.requested_txid,txid);
assert.equal(observation.transaction,null);
assert.equal(observation.confirmations_by_provider,0);
for(const error of [new Error('timeout'),new GrpcError('GetTransaction',14),new GrpcError('GetBlock',5),
  Object.assign(new Error('untyped status'),{code:5})]) {
  await assert.rejects(observeTransaction(txid,noDecode,provider(error).call));
}
await assert.rejects(observeTransaction(txid,noDecode,provider(undefined,true).call));
await assert.rejects(observeTransaction(txid,()=>{throw new GrpcError('GetTransaction',5);},provider(null,false,true).call));
console.log(JSON.stringify({passed:true,scope:'provider transcript / transport boundary; no network',
  typed_not_found_only:true,negative_tip_rechecked:true,decoder_errors_not_absence:true}));
