#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {execFileSync} from 'node:child_process';
import {observeAuxiliary} from './testnet_auxiliary.mjs';

async function main() {
  const args=process.argv.slice(2), fromReceiver=args[0]==='--receiver';
  const [wallet,folder,...extra]=fromReceiver?args.slice(1):args;
  if (!wallet || !folder || extra.length) throw new Error('usage: observe_testnet_auxiliary.mjs [--receiver] TESTNET_WALLET_OR_PRIVATE_RECEIVER NEW_PRIVATE_DIRECTORY');
  const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
  const native=(...args)=>JSON.parse(execFileSync(path.join(root,'target/release/shielded-swap-native'),args,
    {encoding:'utf8',timeout:30000,maxBuffer:4_000_000}));
  let receiver;
  if (fromReceiver) {
    // The owner preflight obtains this from the fully verified signed refund.
    // No source wallet/key access is needed. Direct observer callers must bind
    // it to their own agreement; this observer never authorizes a transaction.
    const fd=fs.openSync(wallet,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);
    try {
      const stat=fs.fstatSync(fd);
      if (!stat.isFile() || stat.mode&0o077 || stat.size>4096) throw new Error('private bounded receiver file required');
      receiver=JSON.parse(fs.readFileSync(fd,'utf8'));
    } finally {fs.closeSync(fd);}
  } else {
    // Legacy source-wallet receiving metadata; no key enters RPC.
    receiver=native('testnet-wallet-receivers',path.resolve(wallet));
  }
  const directory=path.resolve(folder);
  fs.mkdirSync(directory,{mode:0o700});
  const result=await observeAuxiliary(receiver,async(txid,raw)=>{
    const file=path.join(directory,txid+'.hex');
    fs.writeFileSync(file,raw.toString('hex'),{flag:'wx',mode:0o600});
    return native('inspect-transaction',file);
  });
  const file=path.join(directory,'observation.json');
  const fd=fs.openSync(file,'wx',0o600);
  try {fs.writeFileSync(fd,JSON.stringify(result,null,2));fs.fsyncSync(fd);} finally {fs.closeSync(fd);}
  const parent=fs.openSync(directory,'r');try {fs.fsyncSync(parent);} finally {fs.closeSync(parent);}
  console.log(JSON.stringify({file,utxos:result.utxos.length,dedicated_value_candidates:result.dedicated_value_candidates,
    transparent_address_disclosed:true,keys_sent:false,broadcast:false,funding_authorized:false}));
}
main().catch(error=>{console.error(error.message);process.exitCode=1;});
