#!/usr/bin/env node
// Read-only network identification, using Node's TLS-validated HTTP/2 client.
// Minimal bounded protobuf decoder for the observed lightwallet-protocol fields.
// Field numbers checked against librustzcash 9c5705f's pinned walletrpc/*.proto.
// This is NOT consensus/SPV verification and NEVER sends a transaction or key.
import http2 from 'node:http2';

const ENDPOINT = 'https://testnet.zec.rocks:443';
const GENESIS = '05a60a92d99d85997cce3b87616c089f6124d7342af37106edc76126334a2c38';
const NU7_HEIGHT = 4465026;
const ALLOWED = new Set(['GetLightdInfo', 'GetBlock', 'GetLatestBlock', 'GetTreeState']);
function varint(value) {
  let n = BigInt(value); const result = [];
  if (n < 0n) throw new Error('negative varint');
  do { result.push(Number(n & 127n) | (n > 127n ? 128 : 0)); n >>= 7n; } while (n);
  return Buffer.from(result);
}
function fields(data) {
  const result = new Map(); let offset = 0;
  const read = () => {
    let n = 0n;
    for (let i = 0; i < 10; i++) {
      if (offset >= data.length) throw new Error('truncated protobuf varint');
      const b = data[offset++];
      if (i === 9 && b > 1) throw new Error('protobuf integer overflow');
      n |= BigInt(b & 127) << BigInt(7 * i);
      if (!(b & 128)) return n;
    }
    throw new Error('oversized protobuf varint');
  };
  while (offset < data.length) {
    const tag = read(), wire = Number(tag & 7n), field = Number(tag >> 3n);
    if (!field || field > 536870911) throw new Error('invalid protobuf field');
    let value;
    if (wire === 0) value = read();
    else if ([1, 2, 5].includes(wire)) {
      const size = wire === 2 ? Number(read()) : wire === 1 ? 8 : 4;
      if (!Number.isSafeInteger(size) || size < 0 || offset + size > data.length) throw new Error('truncated protobuf field');
      value = data.subarray(offset, offset + size); offset += size;
    } else throw new Error('unsupported protobuf wire type');
    result.set(field, [...(result.get(field) || []), value]);
  }
  return result;
}
function one(map, key) {
  const items = map.get(key);
  if (!items || items.length !== 1) throw new Error(`missing/duplicate field ${key}`);
  return items[0];
}
function integer(map, key) {
  const n = one(map, key);
  if (typeof n !== 'bigint' || n > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('invalid integer field');
  return Number(n);
}
function bytes(map, key) { const b = one(map, key); if (!Buffer.isBuffer(b)) throw new Error('invalid bytes field'); return b; }
function string(map, key) { return bytes(map, key).toString('utf8'); }
function hash(map, key) { const b = bytes(map, key); if (b.length !== 32) throw new Error('invalid hash length'); return Buffer.from(b).reverse().toString('hex'); }
const blockRequest = height => Buffer.concat([Buffer.from([8]), varint(height)]);
async function rpc(method, message = Buffer.alloc(0)) {
  if (!ALLOWED.has(method)) throw new Error('read-only method required');
  return new Promise((resolve, reject) => {
    const client = http2.connect(ENDPOINT, {rejectUnauthorized: true});
    let stream, done = false, total = 0, status, grpcStatus, contentType;
    const chunks = [];
    const finish = (error, value) => {
      if (done) return; done = true; clearTimeout(timer);
      stream?.close(); client.destroy();
      error ? reject(error) : resolve(value);
    };
    const timer = setTimeout(() => finish(new Error(`${method} timeout`)), 15000);
    client.once('error', error => finish(error));
    client.once('connect', () => {
      stream = client.request({':method': 'POST', ':path': `/cash.z.wallet.sdk.rpc.CompactTxStreamer/${method}`,
        'content-type': 'application/grpc', 'te': 'trailers', 'grpc-timeout': '12S'});
      stream.on('response', h => { status = h[':status']; contentType = h['content-type']; if (h['grpc-status'] !== undefined) grpcStatus = h['grpc-status']; });
      stream.on('trailers', h => { grpcStatus = h['grpc-status']; });
      stream.on('error', error => finish(error));
      stream.on('data', chunk => {
        total += chunk.length;
        if (total > 2_000_000) return finish(new Error('gRPC response size bound'));
        chunks.push(chunk);
      });
      stream.on('end', () => {
        try {
          if (status !== 200 || !String(contentType).startsWith('application/grpc') || String(grpcStatus) !== '0') throw new Error(`${method} non-success gRPC status`);
          const raw = Buffer.concat(chunks);
          if (raw.length < 5 || raw[0] !== 0 || raw.readUInt32BE(1) !== raw.length - 5) throw new Error('expected one uncompressed gRPC message');
          finish(null, fields(raw.subarray(5)));
        } catch (error) { finish(error); }
      });
      const frame = Buffer.alloc(5); frame.writeUInt32BE(message.length, 1);
      stream.end(Buffer.concat([frame, message]));
    });
  });
}

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
    lightwalletd_version:string(info,1), lightwallet_protocol_version:string(info,18),
    ironwood_tree_encoding_bytes:encoded.length/2, ironwood_tree_size_reported:integer(metadata,3),
    funded_swap:false, broadcast:false, keys_or_addresses_sent:false,
    remaining:['testnet wallet funding and witness synchronization','public chain timing/confirmation/reorg policy','EVM testnet integration','independent operator authentication']}, null, 2));
} catch (error) { console.error(error.message); process.exitCode = 1; }
