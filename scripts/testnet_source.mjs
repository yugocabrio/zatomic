// Canonicality checks for a private, already scanned source snapshot. The
// provider sees only public block heights, never the selected note or witness.
import {GENESIS, NU7_HEIGHT, rpc, integer, string, hash, blockRequest} from './lightwallet_rpc.mjs';

export async function observeSource(source, call=rpc) {
  const started=performance.now();
  if (source.genesis!==GENESIS || source.branch!=='77190ad9'
      || !Number.isSafeInteger(source.height) || source.height>0xffffffff
      || !Number.isSafeInteger(source.anchor_height) || source.anchor_height<NU7_HEIGHT
      || source.height-source.anchor_height+1<12
      || !/^[0-9a-f]{64}$/.test(source.tip) || !/^[0-9a-f]{64}$/.test(source.anchor_tip)
      || !/^(?:[0-9a-f]{2}){1,8192}$/.test(source.tree)
      || !/^(?:[0-9a-f]{2}){1,8192}$/.test(source.anchor_tree)) throw new Error('source snapshot domain/anchor bounds');
  const info=await call('GetLightdInfo');
  if (string(info,4)!=='test' || string(info,6).replace(/^0x/,'').toLowerCase()!=='77190ad9'
      || string(info,18)!=='v0.5.0'
      || (info.has(17) && integer(info,17)!==0)) throw new Error('source NU7 domain or announced upgrade changed');
  const first=await call('GetBlock',blockRequest(1));
  if (integer(first,2)!==1 || hash(first,4)!==GENESIS) throw new Error('source provider genesis mismatch');
  function latest(block) {
    if (integer(block,1)!==source.height || hash(block,2)!==source.tip)
      throw new Error('wallet must be synchronized to the current provider tip');
  }
  latest(await call('GetLatestBlock'));
  let timestamp;
  for (const [height,tip,encoded] of [[source.anchor_height,source.anchor_tip,source.anchor_tree],
      [source.height,source.tip,source.tree]]) {
    const b=await call('GetBlock',blockRequest(height));
    const tree=await call('GetTreeState',blockRequest(height));
    if (integer(b,2)!==height || hash(b,3)!==tip || string(tree,1)!=='test'
        || integer(tree,2)!==height || string(tree,3).toLowerCase()!==tip
        || string(tree,7).toLowerCase()!==encoded) throw new Error('source anchor/tip/tree no longer canonical');
    timestamp=integer(b,5);
  }
  // Recheck both identities after all tree reads, then the latest block. A tip
  // advance requires another compact scan so no observed nullifiers are skipped.
  for (const [height,tip] of [[source.anchor_height,source.anchor_tip],[source.height,source.tip]]) {
    const block=await call('GetBlock',blockRequest(height));
    if (integer(block,2)!==height || hash(block,3)!==tip) throw new Error('source observation reorganized');
  }
  latest(await call('GetLatestBlock'));
  const elapsed=(performance.now()-started)/1000, now=Math.floor(Date.now()/1000);
  if (elapsed>120 || now-timestamp>600 || timestamp-now>7200+60) throw new Error('source observation freshness/clock bound');
  return {format:'latch-testnet-source-observation-v1',genesis:GENESIS,branch:'77190ad9',
    observed_at:new Date().toISOString(),elapsed_seconds:elapsed,
    observed_tip:{height:source.height,hash:source.tip,timestamp},
    anchor:{height:source.anchor_height,hash:source.anchor_tip,confirmations:source.height-source.anchor_height+1},
    provider_trusted:true,keys_or_addresses_sent:false,broadcast:false,funding_authorized:false,
    limitations:['Canonical blocks and nullifiers are trusted TLS-provider statements, not SPV/finality proofs.',
      'Twelve confirmations are a candidate input-selection rule, not a public swap finality policy.',
      'No mempool conflict exclusion or protection against spending the same keys outside this wallet.']};
}
