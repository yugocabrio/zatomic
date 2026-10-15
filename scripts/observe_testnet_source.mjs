#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import {observeSource} from './testnet_source.mjs';

try {
  const [input,output,...extra]=process.argv.slice(2);
  if (!input || !output || extra.length) throw new Error('usage: observe_testnet_source.mjs PRIVATE_SOURCE_SNAPSHOT NEW_PRIVATE_OUTPUT');
  const fd=fs.openSync(input,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);
  let source;
  try {
    const stat=fs.fstatSync(fd);
    if (!stat.isFile() || stat.mode&0o077 || stat.size>50_000_000) throw new Error('bounded private source file required');
    source=JSON.parse(fs.readFileSync(fd,'utf8'));
  } finally { fs.closeSync(fd); }
  const result=await observeSource(source);
  const out=fs.openSync(output,'wx',0o600);
  try { fs.writeFileSync(out,JSON.stringify(result,null,2));fs.fsyncSync(out); } finally { fs.closeSync(out); }
  const parent=fs.openSync(path.dirname(path.resolve(output)),'r');
  try {fs.fsyncSync(parent);} finally {fs.closeSync(parent);}
  console.log(JSON.stringify({file:path.resolve(output),height:source.height,broadcast:false,funding_authorized:false}));
} catch (error) {console.error(error.message);process.exitCode=1;}
