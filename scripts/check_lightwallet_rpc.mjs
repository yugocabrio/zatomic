#!/usr/bin/env node
// Bounds/ambiguity checks on data supplied by a network peer, without RPC.
import assert from 'node:assert/strict';
import {fields, integer, bytes, messages, rpc} from './lightwallet_rpc.mjs';
const frame = b => { const h = Buffer.alloc(5);h.writeUInt32BE(b.length,1);return Buffer.concat([h,b]); };
const payload = Buffer.from([8,1]);
assert.equal(integer(messages(frame(payload)),1),1);
assert.equal(messages(Buffer.concat([frame(payload),frame(payload)]),true).length,2);
assert.throws(()=>messages(Buffer.concat([frame(payload),frame(payload)])));
assert.throws(()=>messages(frame(payload).subarray(0,6)));
assert.throws(()=>messages(Buffer.from([1,0,0,0,0])));
assert.throws(()=>messages(Buffer.concat(Array(257).fill(frame(payload))),true));
assert.throws(()=>integer(fields(Buffer.from([8,1,8,2])),1));
assert.throws(()=>bytes(fields(Buffer.from([8,1])),1));
assert.throws(()=>fields(Buffer.from([0])));
assert.throws(()=>fields(Buffer.from([10,10,0])));
assert.throws(()=>fields(Buffer.from([8,255,255,255,255,255,255,255,255,255,2])));
assert.throws(()=>fields(Buffer.concat(Array(200001).fill(payload))));
await assert.rejects(rpc('SendTransaction'));
console.log(JSON.stringify({passed:true,scope:'bounded protobuf/gRPC decoding and read-only method allowlist; no network requests'}));
