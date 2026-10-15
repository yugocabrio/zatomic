#!/usr/bin/env node
// UTXO-index response checks, no network or spending.
import assert from 'node:assert/strict';
import {GENESIS, fields, varint} from './lightwallet_rpc.mjs';
import {decodeUtxos,utxoRequest,verifyOrigin} from './testnet_auxiliary.mjs';
const v=(field,n)=>Buffer.concat([varint(field*8),varint(n)]);
const b=(field,data)=>Buffer.concat([varint(field*8+2),varint(data.length),data]);
const receiver={genesis:GENESIS,aux_address:'tm'+'1'.repeat(33),aux_script:'76a914'+'ab'.repeat(20)+'88ac'};
const entry=(changes={})=>{
  const o={address:receiver.aux_address,txid:Buffer.alloc(32,1),index:0,script:receiver.aux_script,value:20000,height:4500000,...changes};
  return b(1,Buffer.concat([b(1,o.txid),v(2,o.index),b(3,Buffer.from(o.script,'hex')),v(4,o.value),v(5,o.height),b(6,Buffer.from(o.address))]));
};
assert.equal(decodeUtxos(fields(entry()),receiver,4500010)[0].value_zatoshi,20000);
assert.equal(decodeUtxos(fields(Buffer.alloc(0)),receiver,4500010).length,0);
for(const changes of [{address:'tm'+'2'.repeat(33)},{script:'51'},{index:0x100000000n},{value:0},{value:2100000000000001},{height:4500011},{height:1},{txid:Buffer.alloc(31)}]) {
  assert.throws(()=>decodeUtxos(fields(entry(changes)),receiver,4500010));
}
assert.throws(()=>decodeUtxos(fields(Buffer.concat([entry(),entry()])),receiver,4500010));
assert.throws(()=>decodeUtxos(fields(Buffer.concat(Array(9).fill(entry()))),receiver,4500010));
assert.throws(()=>utxoRequest({...receiver,genesis:'00'.repeat(32)}));
assert.throws(()=>utxoRequest({...receiver,aux_address:'t1'+'1'.repeat(33)}));
assert.equal(Number(fields(utxoRequest(receiver)).get(3)[0]),9);
const coin=decodeUtxos(fields(entry()),receiver,4500010)[0];
const origin={status:'mined',mined_block:{height:coin.height},transaction:{txid:coin.txid,transparent_outputs:[{script:coin.script,value_zatoshi:coin.value_zatoshi}]}};
verifyOrigin(coin,origin);
assert.throws(()=>verifyOrigin(coin,{status:'not_found',transaction:null,mined_block:null}));
for(const alter of [o=>{o.status='mempool';o.mined_block=null;},o=>{o.mined_block.height--;},o=>{o.transaction.txid='00'.repeat(32);},o=>{o.transaction.transparent_outputs[0].value_zatoshi++;},o=>{o.transaction.transparent_outputs[0].script='51';}]) {
  const changed=structuredClone(origin);alter(changed);assert.throws(()=>verifyOrigin(coin,changed));
}
console.log(JSON.stringify({passed:true,scope:'UTXO ownership/range/duplicate/truncation and testnet request boundaries, no RPC'}));
