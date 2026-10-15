#!/usr/bin/env node
// Read-only identification through the bounded TLS lightwallet client.
import {ENDPOINT, GENESIS, NU7_HEIGHT, rpc, fields, integer, bytes, string, hash, blockRequest} from './lightwallet_rpc.mjs';

try {
  const info = await rpc('GetLightdInfo');
  if (string(info, 4) !== 'test') throw new Error('non-test server; no further requests');
  const first = await rpc('GetBlock', blockRequest(1));
  if (integer(first, 2) !== 1 || hash(first, 4) !== GENESIS) throw new Error('public testnet genesis mismatch');
  const latest = await rpc('GetLatestBlock');
  const height = integer(latest, 1), tip = hash(latest, 2);
  const branch = string(info, 6).replace(/^0x/, '').toLowerCase();
  if (height < NU7_HEIGHT || branch !== '77190ad9') throw new Error('NU7 not active or branch inconsistent');
  const tree = await rpc('GetTreeState', blockRequest(height));
  const compact = await rpc('GetBlock', blockRequest(height));
  if (string(tree, 1) !== 'test' || integer(tree, 2) !== height || string(tree, 3).toLowerCase() !== tip || integer(compact, 2) !== height || hash(compact, 3) !== tip) throw new Error('provider tip changed/inconsistent; retry later');
  const encoded = string(tree, 7);
  if (!/^(?:[0-9a-fA-F]{2})+$/.test(encoded)) throw new Error('missing/invalid Ironwood tree');
  const metadata = fields(bytes(compact, 8));
  console.log(JSON.stringify({scope:'Read-only TLS lightwalletd observation; provider trusted, no consensus validation',
    observed_at: new Date().toISOString(), endpoint: ENDPOINT, network:'Zcash public testnet', genesis:GENESIS,
    tip_height:height, tip_hash:tip, branch_id:branch, nu7_activation_height:NU7_HEIGHT,
    provider_header_timestamp:integer(compact,5),
    header_age_seconds_by_local_clock:Math.floor(Date.now()/1000)-integer(compact,5),
    announced_upgrade:{name:info.has(16)?string(info,16):null,height:info.has(17)?integer(info,17):0},
    lightwalletd_version:string(info,1), lightwallet_protocol_version:string(info,18),
    ironwood_tree_encoding_bytes:encoded.length/2, ironwood_tree_size_reported:integer(metadata,3),
    funded_swap:false, broadcast:false, keys_or_addresses_sent:false,
    remaining:['testnet wallet funding and witness synchronization','public chain timing/confirmation/reorg policy','EVM testnet integration','independent operator authentication']}, null, 2));
} catch (error) { console.error(error.message); process.exitCode = 1; }
