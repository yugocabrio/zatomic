# Reproduce the local chain gates

Prerequisites: Rust 1.93, Node.js + npm, Python 3.11+, Foundry 1.3.1, and Docker.
Use `make doctor` to check prerequisites and `make demo` to build/start the
local browser demo at http://127.0.0.1:8787.
The current node bootstrap targets Apple Silicon / Linux ARM64. No public
endpoint, wallet seed, faucet, paid service or mainnet funds are used.

The current release was rebuilt and executed from a fresh checkout of
`9b978e3b635bdbfdd03b985089fc4ec30903d280`, with fresh wallets and a separately
namespaced node. Setup, verification, actual exchange, interrupted refund and
zero-new-payment replay passed. See [the execution record](../evidence/2026-10-15-clean-reproduction.json).
This used the same machine and installed toolchain/package caches; no existing
private state, node database or build outputs were copied. The original node
remained unchanged, and the reproduction node was stopped with its data retained.

The commands below reproduce the older native-funding-first fixtures. New
browser runs use signed cross-chain consent before native source authorization;
use [the current consent/recovery guide](evidence-index.md) for that driver.
Each saved browser job selects its own matching recovery command.

For the current operator-isolation gate, use
[separate operator commands](evidence-index.md). It exercises real TLS
preparation and settlement under OS private-directory denials. Its coordinator
never migrates another owner's files. The macOS checker has its own `recover`
command and fixture layout; it is separate from the older runners below.

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

The container's bind mounts must belong to this exact checkout. A second clone
on the same host intentionally refuses to adopt, start, stop or mine the first
clone's container, even if its project label matches. For a fresh second clone
on the same host, select a separate name and unused loopback port before setup:

```sh
export LATCH_REGTEST_NAMESPACE=release-reproduction
export LATCH_REGTEST_PORT=30343
make setup
make verify
python3 scripts/prefunding_swap.py success .local/fresh-success
python3 scripts/prefunding_swap.py recover .local/fresh-success
python3 scripts/prefunding_swap.py refund .local/fresh-refund --fault-after eth-locked
# Expected exit 75 at the stop; then:
python3 scripts/prefunding_swap.py recover .local/fresh-refund
python3 scripts/prefunding_swap.py recover .local/fresh-refund
make stop-node
```

Keep the same environment for every command, including recovery and stopping.
The first setup pins name/port to that checkout's private node directory. A changed
scope or an existing unpinned state directory refuses. Bind mounts and exact
loopback port are checked before RPC. This isolates chain/wallet/build state;
it is **not** an independently administered machine. The Anvil port remains18545,
so chain drivers across checkouts must be run serially. Do not delete an existing
container or its wallet state to make a name available. `make doctor` checks
prerequisites only and does not establish clean-checkout settlement.

The two `mine` blocks activate the configured NU7 rules on a new chain. Already
initialized chains need no activation mining. History is bounded to 10,000 blocks
after height 2, with a separate 50 MB capture-file limit; this fixture scanner
is not a general wallet synchronizer. New swap setup checks room for source
maturation and the full refund path before mining or funding (v3 reserves 133
blocks for a fresh bank, 29 for an existing bank, including up to six blocks of
waiting for the older funding anchor; legacy runners reserve 127/23). It refuses rather than resetting a node
that may contain recovery evidence. `check_capture_capacity.py BANK DIRECTORY`
checks actual history beyond the original 2,000-block cap and rejects malformed
continuity/excessive input; it only advances the owned node when all recorded
funded runs are resolved.

Success observes actual EVM `Claimed` data, makes Alice's directory unavailable,
then proves and broadcasts Bob's native claim in a new process. A later competing
native refund must reject as a double spend. Abort never reveals the witness;
both owners recover their original asset, less native fees, with the peer's
files unavailable. Both runs require actual node rejection of premature refund,
two controlled confirmations, and receiver decryption of the expected note.

These are real transactions on **isolated chains**. They do not establish public
network finality or timing bounds. Setup runs each DKG/signing role in a separate subprocess with its own
private directory; all still run on the same host. ETH accounts are disposable Anvil accounts. The dedicated auxiliary
coin is 20,000 zatoshi, split from an Alice-owned matured regtest coinbase before
swap setup. Refund returns 15,000 zatoshi after its 5,000-zatoshi incremental fee; its
public amount and outpoint are visible on refund. The exchange principal never
becomes a transparent Zcash output.

Private `.local` data includes spending keys, note witnesses, PCZTs and recovery
files. It must not be published. `evidence` contains only selected public results
and explicit scope. Do not replace a failed run's directory or delete its state;
inspect the preserved stage files. A narrow `--resume-setup` option recovers a
run after confirmed ZEC funding and before ETH locking. For a deliberate durable-checkpoint interruption:

```sh
python3 scripts/run_regtest_swap.py success .local/my-interrupted --fault-after eth-claimed
# Exit 75 above is the intentional stop. No further signature from Alice:
python3 scripts/recover_regtest_swap.py .local/my-interrupted
# Repeat: reconciles confirmation, sends no second payment.
python3 scripts/recover_regtest_swap.py .local/my-interrupted
```

Use `refund` and `--fault-after eth-locked` for no-reveal recovery. Recovery
restores only this runner's local Anvil checkpoint; it never restores a public
chain. Do not run another fixture while a swap still has an open timing window.
A process lock serializes all chain drivers. Before funding, the runner reserves
its auxiliary coin and refuses one reserved by an unfinished run.

```sh
python3 scripts/check_participant_recovery.py .local/my-success/swap
```

This kills/restarts actual signers and checks durable nonce replay rejection,
recipient/note/point substitution and companion-refund deadline changes. It
burns fresh test attempts but never broadcasts another transaction.

For the earlier synthetic compatibility gate (not a chain swap):

```sh
python3 scripts/run_native_evm_gate.py .local/my-synthetic-gate
```

To stop only this project's node, retaining its state:

```sh
python3 scripts/regtest_node.py stop
```

For an interruption between native broadcast and its confirmation journal:

```sh
python3 scripts/run_regtest_swap.py success .local/my-funding-stop --fault-after zec-broadcast
python3 scripts/recover_regtest_swap.py .local/my-funding-stop
```

The recovery driver finds the already-submitted funding on the owned node and
refunds it after the deadline. It does not submit new funding or start ETH setup.
It refuses this path if ETH setup artifacts indicate an uncertain external
outcome. The demonstrated checkpoint cases are not a claim of recovery from
every instruction boundary or from public-network reorgs.

The more severe send/checkpoint gaps can be reproduced with
`--fault-after eth-lock-broadcast` (refund mode) or
`--fault-after eth-claim-broadcast` (success mode), followed by the same recovery
command. The outgoing signed bytes are persisted privately before broadcast.
Recovery validates their actual signer and method, then replays the identical
transaction if absent from the restored owned node. A potentially exposed claim
outside its bounded window stops without treating the secret as unrevealed.

`python3 scripts/check_evm_journal.py .local/my-success` checks actual signed
intents offline and rejects relabeling, metadata corruption and invalid encoding.
Raw intents contain the claim secret before broadcast and must remain private.

For the authenticated signer-channel variant, see
[signer transport](evidence-index.md). `run_tls_swap.py` runs the same actual
native/EVM graph with both signer conversations carried over mutual TLS. Its
certificate fixtures and wallet paths are still on one host.

For receipt withholding, bundle corruption and recovery with the entire
original native setup directory unavailable, see
[participant-owned recovery bundles](evidence-index.md). These gates exercise
actual preparation and native chain recovery; no substitute signature or mock
settlement is used. New signer checks require a fixture prepared by the current
code: old authorized-F policies intentionally fail the new preview boundary.

For a coordinator that never reads Alice's unrevealed scalar or either ETH key,
and a live mempool test where a competing relayer mines first, use the separate
[owner client gates](evidence-index.md). The CLI gate layout has per-owner ETH journals and should not be passed to
the legacy recovery driver. New browser runs use `prefunding_swap.py recover` (which delegates after the
owner ETH lock intent); unreleased v3 setup is permanently cancelled. See
[setup recovery](evidence-index.md). Meanwhile
`run_client_swap.py` remains the standalone adversarial integration gate.

For SIGKILL during actual native claim/refund or during TLS preparation, use
the [process recovery gates](evidence-index.md). They verify cleanup, durable
peer-directory restoration and repeated recovery without duplicate payments.
