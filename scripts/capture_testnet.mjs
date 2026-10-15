#!/usr/bin/env node
// Bounded, read-only Ironwood compact capture. No wallet material enters RPC.
import fs from 'node:fs';
import path from 'node:path';
import {ENDPOINT, GENESIS, NU7_HEIGHT, rpc, fields, integer, bytes, string, hash, blockRequest, varint} from './lightwallet_rpc.mjs';

function uint(m, key) { return m.has(key) ? integer(m, key) : 0; }
function fixed(m, key, n) { const b = bytes(m, key); if (b.length !== n) throw new Error(`field ${key} size`); return b.toString('hex'); }
function nested(m, key) { return (m.get(key) || []).map(b => { if (!Buffer.isBuffer(b)) throw new Error('message wire type'); return fields(b); }); }
function compact(m) {
  return {height:integer(m,2), hash:hash(m,3), previousblockhash:hash(m,4), time:uint(m,5),
    tree_size:uint(fields(bytes(m,8)),3), transactions:nested(m,7).map(tx => ({
      index:uint(tx,1), txid:hash(tx,2), actions:nested(tx,9).map(a => ({
        nullifier:fixed(a,1,32), cmx:fixed(a,2,32), ephemeral_key:fixed(a,3,32), ciphertext:fixed(a,4,52)
      }))
    }))};
}
function tree(m, height, tip) {
  if (string(m,1) !== 'test' || integer(m,2) !== height || string(m,3).toLowerCase() !== tip) throw new Error('tree identity mismatch/reorg');
  const encoded = string(m,7).toLowerCase();
  if (!/^(?:[0-9a-f]{2})+$/.test(encoded) || encoded.length > 16384) throw new Error('Ironwood tree encoding');
  return encoded;
}
async function main() {
  const [startArg, countArg, out, expected] = process.argv.slice(2);
  const start = Number(startArg), count = Number(countArg);
  if (!Number.isSafeInteger(start) || start < NU7_HEIGHT || start > 0xffffffff || !Number.isSafeInteger(count) || count < 1 || count > 256 || !out || (expected && !/^[0-9a-f]{64}$/.test(expected))) throw new Error('usage: capture_testnet.mjs START_HEIGHT COUNT_1_TO_256 OUTPUT [EXPECTED_START_HASH]');
  const info = await rpc('GetLightdInfo');
  if (string(info,4) !== 'test' || string(info,6).replace(/^0x/,'').toLowerCase() !== '77190ad9') throw new Error('public testnet NU7 required');
  const first = await rpc('GetBlock',blockRequest(1));
  if (integer(first,2) !== 1 || hash(first,4) !== GENESIS) throw new Error('testnet genesis mismatch');
  const latest = await rpc('GetLatestBlock');
  const end = Math.min(start + count, integer(latest,1));
  if (end < start) throw new Error('checkpoint ahead of provider');
  const initial = await rpc('GetBlock',blockRequest(start));
  const initialHash = hash(initial,3);
  if (integer(initial,2) !== start || (expected && expected !== initialHash)) throw new Error('checkpoint no longer canonical according to provider; keep state, review reorg');
  const initialTree = tree(await rpc('GetTreeState',blockRequest(start)), start, initialHash);
  let blocks = [];
  if (end > start) {
    const from = blockRequest(start+1), to = blockRequest(end);
    const request = Buffer.concat([Buffer.from([10]),varint(from.length),from,Buffer.from([18]),varint(to.length),to]);
    blocks = (await rpc('GetBlockRange',request)).map(compact);
  }
  if (blocks.length !== end-start) throw new Error('incomplete block range');
  let tip = initialHash;
  for (let i=0;i<blocks.length;i++) {
    if (blocks[i].height !== start+i+1 || blocks[i].previousblockhash !== tip) throw new Error('discontinuous block range');
    tip = blocks[i].hash;
  }
  const finalTree = tree(await rpc('GetTreeState',blockRequest(end)),end,tip);
  const check = await rpc('GetBlock',blockRequest(end));
  if (integer(check,2) !== end || hash(check,3) !== tip) throw new Error('provider tip changed during capture');
  const capture = {format:'latch-ironwood-compact-v1',genesis:GENESIS,branch:'77190ad9',
    initial_height:start,initial_hash:initialHash,initial_tree:initialTree,height:end,tip,final_tree:finalTree,blocks,
    observation:{endpoint:ENDPOINT,observed_at:new Date().toISOString(),provider_trusted:true,provider_tip:integer(latest,1),keys_or_addresses_sent:false,broadcast:false}};
  const fd = fs.openSync(out,'wx',0o600);
  try { fs.writeFileSync(fd,JSON.stringify(capture)); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  const parent = fs.openSync(path.dirname(path.resolve(out)),'r'); try { fs.fsyncSync(parent); } finally { fs.closeSync(parent); }
  console.log(JSON.stringify({file:path.resolve(out),height:end,tip,blocks:blocks.length,provider_tip:integer(latest,1),broadcast:false}));
}
main().catch(e => {console.error(e.message);process.exitCode=1;});
