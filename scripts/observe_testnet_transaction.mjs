#!/usr/bin/env node
// Creates a fresh private observation folder; no keys, signing or broadcasting.
import fs from 'node:fs';
import path from 'node:path';
import {execFileSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {observeTransaction, transactionRequest} from './testnet_observation.mjs';

async function main() {
  const [txid, folder, ...extra] = process.argv.slice(2);
  if (!folder || extra.length) throw new Error('usage: observe_testnet_transaction.mjs TXID NEW_PRIVATE_DIRECTORY');
  transactionRequest(txid);
  const directory = path.resolve(folder);
  fs.mkdirSync(directory, {mode: 0o700}); // Never overwrite a previous observation.
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
  const result = await observeTransaction(txid, async raw => {
    const file = path.join(directory, 'transaction.hex');
    fs.writeFileSync(file, raw.toString('hex'), {flag: 'wx', mode: 0o600});
    return JSON.parse(execFileSync(path.join(root, 'target/release/shielded-swap-native'),
      ['inspect-transaction', file], {encoding: 'utf8', timeout: 30000, maxBuffer: 4_000_000}));
  });
  const file = path.join(directory, 'observation.json');
  const fd = fs.openSync(file, 'wx', 0o600);
  try {fs.writeFileSync(fd, JSON.stringify(result, null, 2)); fs.fsyncSync(fd);} finally {fs.closeSync(fd);}
  const parent = fs.openSync(directory, 'r'); try {fs.fsyncSync(parent);} finally {fs.closeSync(parent);}
  console.log(JSON.stringify({file, txid, status: result.status, mined_block: result.mined_block,
    confirmations_by_provider: result.confirmations_by_provider, provider_trusted: true,
    broadcast: false, funding_authorized: false, reveal_authorized: false}));
}
main().catch(error => {console.error(error.message); process.exitCode = 1;});
