#!/usr/bin/env node
// Read-only network identification, using Node's TLS-validated HTTP/2 client.
// Minimal bounded protobuf decoder for the observed lightwallet-protocol fields.
// Field numbers checked against librustzcash 9c5705f's pinned walletrpc/*.proto.
// This is NOT consensus/SPV verification and NEVER sends a transaction or key.
import http2 from 'node:http2';

export const ENDPOINT = 'https://testnet.zec.rocks:443';
export const GENESIS = '05a60a92d99d85997cce3b87616c089f6124d7342af37106edc76126334a2c38';
export const NU7_HEIGHT = 4465026;
const ALLOWED = new Set(['GetLightdInfo', 'GetBlock', 'GetLatestBlock', 'GetTreeState', 'GetBlockRange']);
export function messages(raw, streaming = false) {
  const result = []; let offset = 0;
  if (raw.length > (streaming ? 8_000_000 : 2_000_000)) throw new Error('gRPC response size bound');
  while (offset < raw.length) {
    if (raw.length - offset < 5 || raw[offset] !== 0) throw new Error('uncompressed gRPC frame required');
    const size = raw.readUInt32BE(offset + 1); offset += 5;
    if (size > 2_000_000 || offset + size > raw.length || result.length >= 256) throw new Error('gRPC frame bound');
    result.push(fields(raw.subarray(offset, offset + size))); offset += size;
  }
  if (!streaming && result.length !== 1) throw new Error('expected unary response');
  return streaming ? result : result[0];
}
export function varint(value) {
  let n = BigInt(value); const result = [];
  if (n < 0n) throw new Error('negative varint');
  do { result.push(Number(n & 127n) | (n > 127n ? 128 : 0)); n >>= 7n; } while (n);
  return Buffer.from(result);
}
export function fields(data) {
  const result = new Map(); let offset = 0, count = 0;
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
    if (++count > 200_000) throw new Error('protobuf field count bound');
    const tag = read(), wire = Number(tag & 7n), field = Number(tag >> 3n);
    if (!field || field > 536870911) throw new Error('invalid protobuf field');
    let value;
    if (wire === 0) value = read();
    else if ([1, 2, 5].includes(wire)) {
      const size = wire === 2 ? Number(read()) : wire === 1 ? 8 : 4;
      if (!Number.isSafeInteger(size) || size < 0 || offset + size > data.length) throw new Error('truncated protobuf field');
      value = data.subarray(offset, offset + size); offset += size;
    } else throw new Error('unsupported protobuf wire type');
    if (!result.has(field)) result.set(field, []);
    result.get(field).push(value);
  }
  return result;
}
export function one(map, key) {
  const items = map.get(key);
  if (!items || items.length !== 1) throw new Error(`missing/duplicate field ${key}`);
  return items[0];
}
export function integer(map, key) {
  const n = one(map, key);
  if (typeof n !== 'bigint' || n > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('invalid integer field');
  return Number(n);
}
export function bytes(map, key) { const b = one(map, key); if (!Buffer.isBuffer(b)) throw new Error('invalid bytes field'); return b; }
export function string(map, key) { return bytes(map, key).toString('utf8'); }
export function hash(map, key) { const b = bytes(map, key); if (b.length !== 32) throw new Error('invalid hash length'); return Buffer.from(b).reverse().toString('hex'); }
export const blockRequest = height => Buffer.concat([Buffer.from([8]), varint(height)]);
export async function rpc(method, message = Buffer.alloc(0)) {
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
    const timer = setTimeout(() => finish(new Error(`${method} timeout`)), 45000);
    client.once('error', error => finish(error));
    client.once('connect', () => {
      stream = client.request({':method': 'POST', ':path': `/cash.z.wallet.sdk.rpc.CompactTxStreamer/${method}`,
        'content-type': 'application/grpc', 'te': 'trailers', 'grpc-timeout': '40S'});
      stream.on('response', h => { status = h[':status']; contentType = h['content-type']; if (h['grpc-status'] !== undefined) grpcStatus = h['grpc-status']; });
      stream.on('trailers', h => { grpcStatus = h['grpc-status']; });
      stream.on('error', error => finish(error));
      stream.on('data', chunk => {
        total += chunk.length;
        if (total > (method === 'GetBlockRange' ? 8_000_000 : 2_000_000)) return finish(new Error('gRPC response size bound'));
        chunks.push(chunk);
      });
      stream.on('end', () => {
        try {
          if (status !== 200 || !String(contentType).startsWith('application/grpc') || String(grpcStatus) !== '0') throw new Error(`${method} non-success gRPC status`);
          const raw = Buffer.concat(chunks);
          finish(null, messages(raw, method === 'GetBlockRange'));
        } catch (error) { finish(error); }
      });
      const frame = Buffer.alloc(5); frame.writeUInt32BE(message.length, 1);
      stream.end(Buffer.concat([frame, message]));
    });
  });
}
