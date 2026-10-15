#!/usr/bin/env node
// Internal explicit writer: private stdin, inherited locks, strict public test
// identity, bounded validity. It is not an independent cross-chain policy gate.
import fs from 'node:fs';
import crypto from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {rpc, submitTransaction, GENESIS, NU7_HEIGHT, string, integer, hash, blockRequest} from './lightwallet_rpc.mjs';

export function validate(input, now=Math.floor(Date.now()/1000)) {
  if (Object.keys(input).sort().join(',') !== 'lock_fds,raw_hex,sha256,txid,valid_until'
      || typeof input.raw_hex!=='string' || input.raw_hex.length<40 || input.raw_hex.length>4_000_000
      || input.raw_hex.length%2 || !/^[0-9a-f]+$/.test(input.raw_hex)
      || !/^[0-9a-f]{64}$/.test(input.sha256) || !/^[0-9a-f]{64}$/.test(input.txid)
      || !Number.isSafeInteger(input.valid_until) || now >= input.valid_until || input.valid_until > now+120
      || !Array.isArray(input.lock_fds) || input.lock_fds.length < 1 || input.lock_fds.length > 2) throw new Error('invalid native delivery envelope');
  const raw=Buffer.from(input.raw_hex,'hex');
  if (crypto.createHash('sha256').update(raw).digest('hex') !== input.sha256) throw new Error('retained native bytes changed');
  for (const lock of input.lock_fds) {
    if (Object.keys(lock).sort().join(',') !== 'dev,fd,ino' || !Number.isInteger(lock.fd) || lock.fd < 3) throw new Error('inherited owner/source lock required');
    const meta=fs.fstatSync(lock.fd);
    if (!meta.isFile() || (meta.mode & 0o077) || meta.dev !== lock.dev || meta.ino !== lock.ino) throw new Error('inherited lock identity changed');
  }
  return raw;
}

export async function identify(call=rpc) {
  const info=await call('GetLightdInfo');
  if (string(info,4)!=='test' || string(info,6).replace(/^0x/,'').toLowerCase()!=='77190ad9'
      || string(info,18)!=='v0.5.0' || (info.has(17) && integer(info,17)!==0)) throw new Error('testnet branch/protocol/upgrade mismatch');
  const first=await call('GetBlock',blockRequest(1));
  if (integer(first,2)!==1 || hash(first,4)!==GENESIS) throw new Error('testnet genesis mismatch');
  const tip=await call('GetLatestBlock');
  if (integer(tip,1)<NU7_HEIGHT) throw new Error('native tip before required upgrade');
}

async function main() {
  if (process.argv.slice(2).join(' ')!=='--broadcast-testnet') throw new Error('explicit testnet broadcast flag required');
  const chunks=[]; let size=0;
  for await (const chunk of process.stdin) {
    size+=chunk.length; if (size>4_100_000) throw new Error('delivery input bound'); chunks.push(chunk);
  }
  const input=JSON.parse(Buffer.concat(chunks).toString('utf8'));
  validate(input);
  await identify();
  // Also keeps/rechecks inherited descriptors if the Python parent has died.
  const raw=validate(input);
  const result=await submitTransaction(raw);
  console.log(JSON.stringify({...result,txid:input.txid,bytes_sha256:input.sha256,provider_trusted:true}));
}
if (process.argv[1] && fileURLToPath(import.meta.url)===process.argv[1]) {
  main().catch(()=>{console.error('Native submission uncertain; preserve intent and reconcile exact bytes.');process.exitCode=1;});
}
