#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {execFileSync} from 'node:child_process';
import {observeAuxiliary} from './testnet_auxiliary.mjs';

async function main() {
  const [wallet,folder,...extra]=process.argv.slice(2);
  if (!wallet || !folder || extra.length) throw new Error('usage: observe_testnet_auxiliary.mjs TESTNET_WALLET NEW_PRIVATE_DIRECTORY');
  const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
  const native=(...args)=>JSON.parse(execFileSync(path.join(root,'target/release/shielded-swap-native'),args,
    {encoding:'utf8',timeout:30000,maxBuffer:4_000_000}));
  // This local operation derives only receiving metadata. No key enters RPC.
  const receiver=native('testnet-wallet-receivers',path.resolve(wallet));
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
