#!/usr/bin/env node
// Offline validation of the explicit writer's boundary, never a send call.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import crypto from 'node:crypto';
import {validate, identify} from './send_testnet_transaction.mjs';
import {GENESIS, NU7_HEIGHT, rpc, fields, varint} from './lightwallet_rpc.mjs';

const folder=process.argv[2];
fs.mkdirSync(folder,{mode:0o700});
const fd=fs.openSync(folder+'/test.lock','wx',0o600),meta=fs.fstatSync(fd);
const raw=Buffer.alloc(1024,1), now=Math.floor(Date.now()/1000);
const request={raw_hex:raw.toString('hex'),sha256:crypto.createHash('sha256').update(raw).digest('hex'),
  txid:'11'.repeat(32),valid_until:now+60,lock_fds:[{fd,dev:meta.dev,ino:meta.ino}]};
assert.deepEqual(validate(request,now),raw);
for (const changed of [{...request,valid_until:now},{...request,valid_until:now+121},
  {...request,raw_hex:'01'},{...request,sha256:'22'.repeat(32)},
  {...request,lock_fds:[{fd:1,dev:meta.dev,ino:meta.ino}]},
  {...request,lock_fds:[{fd,dev:meta.dev,ino:meta.ino+1}]}]) assert.throws(()=>validate(changed,now));
fs.closeSync(fd); assert.throws(()=>validate(request,now));
// These are explicit protocol-field transcripts, not public identity evidence.
const text=(field,value)=>Buffer.concat([varint(field*8+2),varint(Buffer.byteLength(value)),Buffer.from(value)]);
const num=(field,value)=>Buffer.concat([varint(field*8),varint(value)]);
const info=fields(Buffer.concat([text(4,'test'),text(6,'77190ad9'),text(18,'v0.5.0')]));
const first=new Map([[2,[1n]],[4,[Buffer.from(GENESIS,'hex').reverse()]]]);
const tip=fields(num(1,NU7_HEIGHT));
const values={GetLightdInfo:info,GetBlock:first,GetLatestBlock:tip};
await identify(async method=>values[method]);
for (const field of [4,6,18,17]) {
  const bad=new Map(info); bad.set(field,[field===17?1n:Buffer.from('wrong')]);
  await assert.rejects(identify(async method=>method==='GetLightdInfo'?bad:values[method]));
}
await assert.rejects(identify(async method=>method==='GetBlock'?new Map([[2,[1n]],[4,[Buffer.alloc(32)]]]):values[method]));
await assert.rejects(rpc('SendTransaction')); // unchanged read-only allowlist
console.log(JSON.stringify({passed:true,scope:'offline writer envelope, inherited-fd identity and explicit network-identity transcripts',
  raw_digest_and_validity_checked:true,closed_or_wrong_lock_refused:true,wrong_network_upgrade_genesis_refused:true,
  readonly_rpc_cannot_send:true,rpc_calls:0,native_node_acceptance:false}));
