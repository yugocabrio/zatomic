#!/usr/bin/env node
// Foundry-compatible standard-JSON frontend to pinned solc-js.
const solc = require('solc');
if (process.argv.includes('--version')) {
  process.stdout.write(`solc, the solidity compiler commandline interface\nVersion: ${solc.version()}\n`);
} else {
  let input = '';
  process.stdin.setEncoding('utf8');
  process.stdin.on('data', chunk => input += chunk);
  process.stdin.on('end', () => {
    try { process.stdout.write(solc.compile(input)); }
    catch (err) { process.stderr.write(String(err)); process.exitCode = 1; }
  });
}
