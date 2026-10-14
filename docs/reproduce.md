# Reproduce the local chain gates

Prerequisites: Rust 1.93, Node.js + npm, Python 3.11+, Foundry 1.3.1, and Docker.
The current node bootstrap targets Apple Silicon / Linux ARM64. No public
endpoint, wallet seed, faucet, paid service or mainnet funds are used.

```sh
npm ci --ignore-scripts --no-audit --no-fund
cargo build --locked --release -j 2 -p shielded-swap-native
forge test -vv
cargo test --locked -j 2
python3 scripts/check_swap_model.py
python3 scripts/regtest_node.py start
python3 scripts/regtest_node.py mine 2
python3 scripts/run_regtest_swap.py success .local/my-success
python3 scripts/run_regtest_swap.py refund .local/my-refund
```

The first node setup downloads a SHA-256-pinned official Zebra 7.0.0-rc.0 binary
and a digest-pinned Ubuntu image. Its container is `shielded-swap-zebra-nu7`;
RPC is loopback port 30342. Each test launches and terminates its own Anvil child
on loopback 18545, chain ID 31338. A busy port is an error; another process is
never terminated. Use a fresh output directory each time. State is retained.

The two `mine` blocks activate the configured NU7 rules on a new chain. Already
initialized chains need no activation mining. History is bounded to 2,000 blocks
after height 2; this fixture scanner is not a general wallet synchronizer.

Success observes actual EVM `Claimed` data, makes Alice's directory unavailable,
then proves and broadcasts Bob's native claim in a new process. A later competing
native refund must reject as a double spend. Abort never reveals the witness;
both owners recover their original asset, less native fees, with the peer's
files unavailable. Both runs require actual node rejection of premature refund,
two controlled confirmations, and receiver decryption of the expected note.

These are real transactions on **isolated chains**. They do not establish public
network finality or timing bounds. Setup currently executes both DKG roles in one
process. ETH accounts are disposable Anvil accounts. The dedicated auxiliary
coin is an Alice-owned regtest coinbase, returned less its incremental fee; its
public amount and outpoint are visible on refund. The exchange principal never
becomes a transparent Zcash output.

Private `.local` data includes spending keys, note witnesses, PCZTs and recovery
files. It must not be published. `evidence` contains only selected public results
and explicit scope. Do not replace a failed run's directory or delete its state;
inspect the preserved stage files. A narrow `--resume-setup` option recovers a
run after confirmed ZEC funding and before ETH locking. General restart recovery
is still being implemented.

For the earlier synthetic compatibility gate (not a chain swap):

```sh
python3 scripts/run_native_evm_gate.py .local/my-synthetic-gate
```

To stop only this project's node, retaining its state:

```sh
python3 scripts/regtest_node.py stop
```
