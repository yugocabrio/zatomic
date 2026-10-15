// Read-only transparent auxiliary index. Unlike shielded sync, this explicitly
// discloses the dedicated TESTNET transparent address to the TLS provider.
import {GENESIS, NU7_HEIGHT, rpc, fields, integer, bytes, string, hash, blockRequest, varint} from './lightwallet_rpc.mjs';
import {observeTransaction} from './testnet_observation.mjs';

const MAX_UTXOS = 8;
const uint = (m,k) => m.has(k) ? integer(m,k) : 0;
export function utxoRequest(receiver) {
  if (receiver.genesis !== GENESIS || !/^tm[1-9A-HJ-NP-Za-km-z]{33}$/.test(receiver.aux_address)
      || !/^76a914[0-9a-f]{40}88ac$/.test(receiver.aux_script)) throw new Error('dedicated testnet P2PKH receiver required');
  const address = Buffer.from(receiver.aux_address,'utf8');
  return Buffer.concat([Buffer.from([10]),varint(address.length),address,Buffer.from([24]),varint(MAX_UTXOS+1)]);
}
export function decodeUtxos(reply, receiver, tip) {
  const values = reply.get(1) || [];
  if (values.length > MAX_UTXOS) throw new Error('auxiliary result limit reached; refuse truncated balance');
  const seen = new Set();
  const entries = values.map(value => {
    if (!Buffer.isBuffer(value)) throw new Error('UTXO message wire type');
    const item = fields(value);
    const parsed = {txid:hash(item,1),index:uint(item,2),script:bytes(item,3).toString('hex'),
      value_zatoshi:uint(item,4),height:uint(item,5)};
    const key = parsed.txid+':'+parsed.index;
    if (string(item,6) !== receiver.aux_address || parsed.script !== receiver.aux_script
        || parsed.index > 0xffffffff || parsed.value_zatoshi < 1 || parsed.value_zatoshi > 2_100_000_000_000_000
        || parsed.height < NU7_HEIGHT || parsed.height > tip || seen.has(key)) {
      throw new Error('UTXO ownership/domain/range/duplicate mismatch');
    }
    seen.add(key);
    return parsed;
  });
  return entries.sort((a,b) => a.txid.localeCompare(b.txid) || a.index-b.index);
}

export function verifyOrigin(entry, origin) {
  if (origin.status !== 'mined' || !origin.transaction || !origin.mined_block) {
    throw new Error('auxiliary origin is not a mined transaction');
  }
  const out = origin.transaction.transparent_outputs[entry.index];
  if (origin.transaction.txid !== entry.txid || origin.status !== 'mined'
      || origin.mined_block.height !== entry.height
      || !out || out.script !== entry.script || out.value_zatoshi !== entry.value_zatoshi) {
    throw new Error('auxiliary index differs from decoded canonical origin transaction');
  }
}

export async function observeAuxiliary(receiver, decode) {
  const request = utxoRequest(receiver); // Reject before network/address disclosure.
  const started = performance.now();
  const info = await rpc('GetLightdInfo');
  if (string(info,4) !== 'test' || string(info,6).replace(/^0x/,'').toLowerCase() !== '77190ad9'
      || string(info,18) !== 'v0.5.0' || uint(info,3) !== 1) throw new Error('testnet NU7 transparent RPC support required');
  const first = await rpc('GetBlock',blockRequest(1));
  if (integer(first,2) !== 1 || hash(first,4) !== GENESIS) throw new Error('testnet genesis mismatch');
  const latest = await rpc('GetLatestBlock');
  const tipHeight = integer(latest,1), tipHash = hash(latest,2);
  if (tipHeight < NU7_HEIGHT || tipHeight > 0xffffffff) throw new Error('testnet tip range');
  const entries = decodeUtxos(await rpc('GetAddressUtxos',request),receiver,tipHeight);
  const origins = new Map();
  for (const entry of entries) {
    if (!origins.has(entry.txid)) origins.set(entry.txid,await observeTransaction(entry.txid,raw=>decode(entry.txid,raw)));
    verifyOrigin(entry,origins.get(entry.txid));
  }
  const after = decodeUtxos(await rpc('GetAddressUtxos',request),receiver,tipHeight);
  if (JSON.stringify(after) !== JSON.stringify(entries)) throw new Error('auxiliary index changed during observation');
  const pinned = await rpc('GetBlock',blockRequest(tipHeight));
  if (integer(pinned,2) !== tipHeight || hash(pinned,3) !== tipHash) throw new Error('auxiliary observation tip orphaned/inconsistent');
  const elapsed = (performance.now()-started)/1000;
  if (elapsed > 120) throw new Error('auxiliary observation duration bound');
  return {format:'latch-testnet-auxiliary-observation-v1',genesis:GENESIS,
    observed_at:new Date().toISOString(),elapsed_seconds:Math.round(elapsed*1000)/1000,
    observed_tip:{height:tipHeight,hash:tipHash,timestamp:integer(pinned,5)},
    auxiliary_address:receiver.aux_address,auxiliary_script:receiver.aux_script,
    utxos:entries.map(e=>({...e,confirmations_by_provider:tipHeight-e.height+1})),
    dedicated_value_candidates:entries.filter(e=>e.value_zatoshi===20000).length,
    provider_trusted:true,transparent_address_disclosed:true,shielded_address_disclosed:false,
    keys_sent:false,broadcast:false,funding_authorized:false,
    limitations:['UTXO index is a trusted provider assertion and may lag or omit mempool conflicts.',
      'No exclusive coin reservation, transaction signing, broadcast or fee/timing authorization.',
      'Empty results are not cryptographic proof of no funds; retain wallet keys and checkpoints.',
      'Every nonempty result must match its decoded non-coinbase v6/NU7 origin transaction.']};
}
