// Provider-trusted observations, kept separate from every transaction sender.
import {GENESIS, NU7_HEIGHT, rpc, GrpcError, fields, one, integer, bytes, string, hash, blockRequest} from './lightwallet_rpc.mjs';

const uint = (m, k) => m.has(k) ? integer(m, k) : 0;
const nested = (m, k) => (m.get(k) || []).map(b => {
  if (!Buffer.isBuffer(b)) throw new Error('nested protobuf wire type');
  return fields(b);
});
function fixed(m, k, length) {
  const b = bytes(m, k);
  if (b.length !== length) throw new Error('compact field length');
  return b.toString('hex');
}

export function transactionRequest(txid) {
  if (!/^[0-9a-f]{64}$/.test(txid)) throw new Error('canonical transaction ID required');
  return Buffer.concat([Buffer.from([26, 32]), Buffer.from(txid, 'hex').reverse()]);
}

export function transactionHeight(message) {
  const n = message.has(2) ? one(message, 2) : 0n;
  if (typeof n !== 'bigint') throw new Error('transaction height wire type');
  if (n === 0n) return {status: 'mempool', height: null};
  if (n === 0xffffffffffffffffn) return {status: 'orphaned', height: null};
  if (n < BigInt(NU7_HEIGHT) || n > 0xffffffffn) throw new Error('transaction height outside NU7 profile');
  return {status: 'mined', height: Number(n)};
}

export function compactMembership(block, tx) {
  let previous = -1;
  const matches = nested(block, 7).filter(t => {
    const index = uint(t, 1);
    if (index <= previous) throw new Error('compact transaction order/duplicate index');
    previous = index;
    return hash(t, 2) === tx.txid;
  });
  if (matches.length !== 1) throw new Error('transaction absent/duplicated in provider block');
  const compact = matches[0], index = uint(compact, 1);
  const actions = nested(compact, 9).map(a => ({nullifier: fixed(a, 1, 32), cmx: fixed(a, 2, 32),
    ephemeral_key: fixed(a, 3, 32), ciphertext: fixed(a, 4, 52)}));
  const inputs = nested(compact, 7).map(i => ({txid: hash(i, 1), index: uint(i, 2)}));
  const outputs = nested(compact, 8).map(o => ({value_zatoshi: uint(o, 1), script: o.has(2) ? bytes(o, 2).toString('hex') : ''}));
  // Compact blocks omit the null coinbase input. Coinbase is never swap funding.
  if (index === 0) throw new Error('coinbase is not a swap transaction observation');
  const equal = (a, b) => JSON.stringify(a) === JSON.stringify(b);
  // Rust serde_json orders map keys; normalize explicitly rather than comparing
  // arbitrary input object serialization/order.
  const ordered = (items, keys) => items.map(item => keys.map(key => item[key]));
  if (!equal(ordered(actions, ['nullifier','cmx','ephemeral_key','ciphertext']),
             ordered(tx.ironwood_actions, ['nullifier','cmx','ephemeral_key','ciphertext']))
      || !equal(ordered(inputs, ['txid','index']), ordered(tx.transparent_inputs, ['txid','index']))
      || !equal(ordered(outputs, ['value_zatoshi','script']), ordered(tx.transparent_outputs, ['value_zatoshi','script']))) {
    throw new Error('full transaction differs from provider compact effects');
  }
  return index;
}

function blockIdentity(block, height, expectedHash) {
  if (integer(block, 2) !== height || (expectedHash && hash(block, 3) !== expectedHash)) {
    throw new Error('provider canonical block changed/inconsistent');
  }
  return {height, hash: hash(block, 3), timestamp: integer(block, 5)};
}

export async function observeTransaction(txid, decode, call=rpc) {
  transactionRequest(txid);
  const started = performance.now();
  const info = await call('GetLightdInfo');
  if (string(info, 4) !== 'test' || string(info, 6).replace(/^0x/, '').toLowerCase() !== '77190ad9'
      || string(info, 18) !== 'v0.5.0') throw new Error('testnet NU7/protocol v0.5.0 required');
  const first = await call('GetBlock', blockRequest(1));
  if (integer(first, 2) !== 1 || hash(first, 4) !== GENESIS) throw new Error('public testnet genesis mismatch');
  const latest = await call('GetLatestBlock');
  const tipHeight = integer(latest, 1), tipHash = hash(latest, 2);
  if (tipHeight < NU7_HEIGHT || tipHeight > 0xffffffff) throw new Error('tip outside NU7 profile');
  const tip = blockIdentity(await call('GetBlock', blockRequest(tipHeight)), tipHeight, tipHash);
  let state, received, decoded = null;
  try {
    received = await call('GetTransaction', transactionRequest(txid));
  } catch (error) {
    // Only an authenticated, well-formed NOT_FOUND from this exact method is
    // an index absence. Timeout, HTTP, malformed and other gRPC errors propagate.
    if (!(error instanceof GrpcError) || error.method !== 'GetTransaction' || error.code !== 5) throw error;
    state = {status:'not_found', height:null};
  }
  if (received !== undefined) {
    state = transactionHeight(received);
    const raw = bytes(received, 1);
    if (!raw.length || raw.length > 2_000_000) throw new Error('transaction size bound');
    decoded = await decode(raw);
    if (decoded.txid !== txid || decoded.version !== 6 || decoded.branch !== '77190ad9'
        || decoded.format !== 'latch-observed-transaction-v1') throw new Error('decoded transaction identity/version mismatch');
  }
  let mined = null, index = null;
  if (state.status === 'mined') {
    if (state.height > tipHeight) throw new Error('transaction mined after observed tip; retry later');
    const block = await call('GetBlock', blockRequest(state.height));
    mined = blockIdentity(block, state.height);
    index = compactMembership(block, decoded);
    blockIdentity(await call('GetBlock', blockRequest(state.height)), state.height, mined.hash);
  }
  // Recheck the original tip, allowing normal forward growth but not an observed
  // replacement of the pinned branch. This still trusts the provider's index.
  blockIdentity(await call('GetBlock', blockRequest(tipHeight)), tipHeight, tipHash);
  const elapsed = (performance.now() - started) / 1000;
  if (elapsed > 120) throw new Error('observation duration bound');
  return {format: 'latch-testnet-transaction-observation-v1', genesis: GENESIS, branch: '77190ad9',
    observed_at: new Date().toISOString(), elapsed_seconds: Math.round(elapsed * 1000) / 1000,
    provider_trusted: true, requested_txid: txid, status: state.status, transaction: decoded, mined_block: mined,
    transaction_index: index, observed_tip: tip,
    confirmations_by_provider: mined ? tipHeight - mined.height + 1 : 0,
    header_age_seconds_by_local_clock: Math.floor(Date.now()/1000) - tip.timestamp,
    announced_upgrade: {name: info.has(16) ? string(info, 16) : null, height: uint(info, 17)},
    txid_disclosed_to_provider: true, keys_or_addresses_sent: false,
    broadcast: false, funding_authorized: false, reveal_authorized: false,
    limitations: ['Provider canonical membership and confirmations are not PoW/consensus/finality proofs.',
      'Transaction parsing checks encoding and txid, not spend signatures or zero-knowledge proofs.',
      'This observation does not check unspent notes/auxiliary inputs, clock safety, fees or counter-chain state.',
      'NOT_FOUND is only this provider index response, not evidence that bytes were never exposed or can be replaced.',
      'Negative or stale observations must never erase a durable secret-exposure intent.']};
}
