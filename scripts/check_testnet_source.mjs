#!/usr/bin/env node
// Isolated RPC-boundary fixtures; these are not network/finality evidence.
import assert from 'node:assert/strict';
import {GENESIS,fields,integer} from './lightwallet_rpc.mjs';
import {observeSource} from './testnet_source.mjs';
const source={genesis:GENESIS,branch:'77190ad9',height:4505000,anchor_height:4504989,
  tip:'01'.repeat(32),anchor_tip:'02'.repeat(32),tree:'0100',anchor_tree:'0000'};
const map=entries=>new Map(entries.map(([key,value])=>[key,[typeof value==='number'?BigInt(value):Buffer.from(value)]]));
const hash=s=>Buffer.from(s,'hex').reverse();
function provider(mode='valid') {
  let latest=0,oldReads=0;
  return async(method,request)=>{
    if(method==='GetLightdInfo')return map([[4,'test'],[6,'77190ad9'],[17,mode==='upgrade'?4505001:0],[18,'v0.5.0']]);
    if(method==='GetLatestBlock'){
      latest++;
      return map([[1,source.height+(mode==='tip-advance'&&latest>1?1:0)],[2,hash(source.tip)]]);
    }
    const height=integer(fields(request),1);
    if(height===1)return map([[2,1],[4,hash(GENESIS)]]);
    const old=height===source.anchor_height;
    const tip=old?source.anchor_tip:source.tip;
    if(method==='GetBlock') {
      if(old)oldReads++;
      return map([[2,height],[3,hash(mode==='reorg'&&old&&oldReads>1?'03'.repeat(32):tip)],
        [5,Math.floor(Date.now()/1000)-(mode==='stale-tip'?601:0)]]);
    }
    if(method==='GetTreeState')return map([[1,'test'],[2,height],[3,tip],
      [7,mode==='wrong-tree'?'ffff':old?source.anchor_tree:source.tree]]);
    throw Error('unexpected RPC');
  };
}
assert.equal((await observeSource(source,provider())).anchor.confirmations,12);
for(const mode of ['upgrade','tip-advance','reorg','stale-tip','wrong-tree']) {
  await assert.rejects(observeSource(source,provider(mode)));
}
await assert.rejects(observeSource({...source,anchor_height:source.height-10},provider()));
await assert.rejects(observeSource({...source,genesis:'00'.repeat(32)},provider()));
console.log(JSON.stringify({passed:true,scope:'isolated source RPC boundary fixtures; no network or funds',
  rejected:['eleven-confirmation-anchor','wrong-network','announced-upgrade','tip-advance','anchor-reorg','stale-tip','wrong-tree']}));
