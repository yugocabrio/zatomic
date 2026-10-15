#!/usr/bin/env node
// Adversarial untrusted-response boundaries; does not simulate a funded swap.
import assert from 'node:assert/strict';
import {fields, varint, rpc} from './lightwallet_rpc.mjs';
import {transactionHeight, transactionRequest, compactMembership} from './testnet_observation.mjs';
const v = (field, value) => Buffer.concat([varint(field * 8), varint(value)]);
const b = (field, value) => Buffer.concat([varint(field * 8 + 2), varint(value.length), value]);
assert.deepEqual(transactionHeight(fields(Buffer.alloc(0))), {status:'mempool', height:null});
assert.deepEqual(transactionHeight(fields(v(2, 0xffffffffffffffffn))), {status:'orphaned', height:null});
assert.deepEqual(transactionHeight(fields(v(2, 4500000))), {status:'mined', height:4500000});
for (const data of [v(2, 1), v(2, 0x100000000n), b(2, Buffer.from([1])), Buffer.concat([v(2, 4500000),v(2,4500000)])]) {
  assert.throws(() => transactionHeight(fields(data)));
}
const id = 'ab'.repeat(31) + 'cd';
assert.equal(transactionRequest(id).subarray(2).toString('hex'), 'cd' + 'ab'.repeat(31));
assert.throws(() => transactionRequest(id.toUpperCase()));
const action = Buffer.concat([b(1,Buffer.alloc(32,1)),b(2,Buffer.alloc(32,2)),b(3,Buffer.alloc(32,3)),b(4,Buffer.alloc(52,4))]);
const entry = Buffer.concat([v(1,1),b(2,Buffer.from(id,'hex').reverse()),b(9,action)]);
const block = fields(b(7,entry));
const parsed = {txid:id,ironwood_actions:[{nullifier:'01'.repeat(32),cmx:'02'.repeat(32),ephemeral_key:'03'.repeat(32),ciphertext:'04'.repeat(52)}],transparent_inputs:[],transparent_outputs:[]};
assert.equal(compactMembership(block,parsed),1);
for (const alter of [p=>{p.txid='00'.repeat(32);},p=>{p.ironwood_actions[0].cmx='00'.repeat(32);},p=>{p.ironwood_actions[0].ciphertext='00'.repeat(52);},p=>{p.transparent_inputs.push({txid:id,index:0});},p=>{p.transparent_outputs.push({value_zatoshi:1,script:'51'});}]) {
  const corrupted=structuredClone(parsed);alter(corrupted);assert.throws(()=>compactMembership(block,corrupted));
}
assert.throws(()=>compactMembership(fields(Buffer.concat([b(7,entry),b(7,entry)])),parsed));
assert.throws(()=>compactMembership(fields(Buffer.alloc(0)),parsed));
await assert.rejects(rpc('SendTransaction'));
console.log(JSON.stringify({passed:true,scope:'pending/orphan sentinels, byte order, compact/full mismatch and ambiguity; no RPC or funding'}));
