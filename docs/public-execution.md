# Public testnet execution checklist

**The funded success path ran once on 2026-10-18**
([record](../evidence/2026-10-18-public-testnet-swap.json)): deployment, F, lock,
claim, C and withdrawal, with the final `verify` passing. **The funded no-reveal
refund ran once on 2026-10-20** ([record](../evidence/2026-10-20-public-testnet-refund.json)): F, lock, Bob's
refund and withdrawal, then Alice's A and time-locked R (see "If either
participant stops" below; the steps there are the ones that ran). The previous isolated release remains reproducible. This checklist connects the existing public owner, source,
observation, signing and recovery clients; none of the commands below silently
substitutes a local chain or synthetic inputs. The convenience preparation
runner controls two owners on one host, not independently administered hosts.

**Public deployment, faucet requests and every public transfer need the
human's authorization.** Read-only observations are permitted.

Practical notes from the run: Zcash testnet blocks arrived faster than the
nominal 75 seconds, so steps that check the exact provider tip may need a rerun
(the source preflight now rescans by itself). Tenderly's free gateway can return
HTTP 429 on sends; the exact retained bytes can be resubmitted elsewhere because
the hash is fixed.

**Signer version (2026-10-17):** both owners must run a native binary that
includes the share-release fix ([review S1](review-2026-10-17.md)). Rebuild with
`cargo build --locked --release -p shielded-swap-native` and run
`scripts/check_share_release.py` on a synthetic review fixture before presigning.
The new coordinator asks Bob first and passes his share to Alice. A new Alice
signer refuses coordinators that skip this step.

## Funding and exact deployment

The current workspace is `.local/public-launch-002` (address-only v2 owner setup,
2026-10-17). Its funding table is the private `launch-plan.md` in that directory.
`public-launch-001` is retired, because its v1 setup shared receiving viewing
keys; do not fund it. Keep all keys and protocol packets private. Trade:
**0.001 test ZEC for 0.001 Sepolia ETH**.

| Account | Minimum balance at the 0.1 gwei ceiling | Funded (2026-10-18) | Reason |
|---|---:|---:|---|
| Alice | 0.00012 Sepolia ETH | 0.0464 | 1,000,000 claim + 200,000 withdrawal gas |
| Bob | 0.00114 Sepolia ETH | 0.0021 | 0.001 trade + 1,000,000 lock + 200,000 refund + 200,000 withdrawal gas |
| Dedicated deployer | 0.00065 Sepolia ETH | 0.001 | 6,500,000 deployment gas |
| Native source | **one Ironwood note of at least 0.0016 test ZEC** | 0.125 TAZ | Principal 0.0011, F fee 0.0001; the change keeps 0.00035 for the refund auxiliary |

No transparent coin is funded. New source reservations (v2) select only the
shielded note: the selector requires a single note strictly larger than 0.00155
ZEC. At release the source signer also signs Alice's private auxiliary
transaction A, which spends F's change and creates the refund's 20,000-zatoshi
coin. A is sent only on the no-reveal refund path (see below), so a settled
swap leaves no transparent output and never discloses the auxiliary address to
the provider. Do **not** send anything to the wallet's transparent address.

**Gas, re-measured on 2026-10-18.** Sepolia now charges heavily for creating
state: a plain transfer to a new account took 204,600 gas, and two funding
transfers sent with the old 21,000 limit failed out of gas (fee only, retried
successfully). The escrow was simulated on current Sepolia rules with
`eth_simulateV1` (`scripts/measure_sepolia_gas.py`, read-only, test scalars):

| Operation | Gas on current Sepolia | Signed limit | Earlier local Anvil |
|---|---:|---:|---:|
| Deploy | 5,090,645 | 6,500,000 (was 1,000,000) | 735,311 |
| Lock | 799,459 | 1,000,000 (was 700,000) | 183,719 |
| Claim, worst-case scalar 2^254−1 | 768,210 | 1,000,000 | 508,771 |
| Claim, random scalars | 579,956–609,879 | | |
| Refund | 143,831 | 200,000 | 54,611 |
| Withdraw | 31,216 | 200,000 | 30,719 |

The new limits are the `bounded-legacy-eth-v2` fee profile; agreements signed
under v1 keep verifying with their own limits. The check fails unless every
limit keeps 15% headroom; **run it again right before deployment**, because
testnet gas schedules change. The default price ceiling falls from 1 gwei to
0.1 gwei so that the funded deployer covers 6.5 million gas. At 2026-10-18
the observed Sepolia gas price was about 121,000 wei (0.00012 gwei), so the
ceiling is roughly 800 times the quote. At 0.1 gwei the measured deploy, lock,
worst-case claim and withdrawal would cost about 0.00067 ETH in total. This is
an illustration from simulation, not a guaranteed cost.

Every action checks current
fees/balances again; **stop if the ceiling no longer suffices**. After signing,
never silently raise a cap, replace a nonce or reuse the plan for another trade.
Initial reserve arithmetic assumes bounded inclusion of the retained transaction,
not an unlimited budget of failed/reverted transactions. Keep unused balances for
recovery; no automatic sweeps. Incoming funding fees are paid by the funder.

Zcash network: public testnet, genesis `05a60a92d99d85997cce3b87616c089f6124d7342af37106edc76126334a2c38`,
branch `77190ad9`, v6 Ironwood, `testnet.zec.rocks:443`.
Ethereum: Sepolia 11155111, genesis
`0x25a5cc106eea7138acab33231d7160d69cb777ee0c2c553fcddf5138993e6dd9`.
Explicit RPC: `https://sepolia.gateway.tenderly.co`; no automatic provider fallback.
On 2026-10-18 dRPC's free plan stopped serving Sepolia, and publicnode has
pruned the genesis block that the clients verify; Tenderly's public gateway
passed the read-only genesis and finality probe.

Shipped escrow: PointEscrowV2 (`--escrow-version 2`, pinned in
`config/public-agreement-policy-v2.json`), no constructor arguments/value. Its
constructor creates the comb table contract at CREATE nonce 1 and pins its code
hash. Deploy limit 8,500,000 gas.

- Creation Keccak: `0x48a31442fd020004759491cab577aeed81aebf116c7541accfbc515c13db3221`.
- Runtime Keccak: `0x031f9898eaec991f176d9bd5aac1cb97252ec9e9b92a6de8684f8b6c38557c8e`.
- Table runtime Keccak: `0x3e3813213a5519b8c68bf7eb007136799c2aac064e57fe0515bc52752c1a5a0e`.
- Deployed on 2026-10-21 at `0x468170aee858eec2a445c1a37970de28adea4e3b`
  (7,100,182 gas). Receipts from its two runs: lock 139,146, claim 112,528,
  refund 32,981, withdrawal 43,562 to 43,586
  ([record](../evidence/2026-10-21-public-testnet-v2.json)).

The first PointEscrow (v1 agreements, `config/public-agreement-policy-v1.json`)
still verifies; its simulated gas is the table above:

- Creation Keccak: `0x3d5bdd90ec5db993616ce4af134cff0f8fbed34c250c5039e3fd6d949ebe1113`.
- Runtime Keccak: `0x6267f59be4896a2d311e0eb7bdf9bfb5ada76fcecb140ac6589aaee8a85b569a`.
- Dedicated deployer nonce zero; exact CREATE address is in the private manifest.
- `public_deploy.py` verifies actual compiled hashes, sender, domain, nonce,
  reserve and fees; persists intent and signed bytes before transport; and
  reconciles exact canonical transaction membership, runtime and provider finality.
  Check-only neither signs nor broadcasts. Uncertain delivery retains the hash.

Funding methods checked on 2026-10-15:

- [Fauzec](https://fauzec.com/) advertises a 1 TAZ shielded UA drip and a 24-hour
  cooldown. Its site explicitly does **not** support transparent recipients.
  [ZecDev's migration resources](https://www.zecdev.org/zcash-z3) list Ironwood
  support, but actual receipt/decryption with this wallet remains to be verified.
  A 1 TAZ faucet note exceeds our minimum; change remains in the source wallet.
- No transparent funding is needed (since 2026-10-17): the refund's coin comes
  from the source note's own change, through Alice's auxiliary transaction.
- [Ethereum's network guide](https://ethereum.org/developers/docs/networks/)
  lists Sepolia faucets, including [Chainlink](https://faucets.chain.link/sepolia).
  Eligibility/account/human checks vary; no faucet request or login was made.
  Existing Sepolia test balances may also fund the three addresses directly.
- The separate [Valar Ironwood test network](https://github.com/valargroup/ironwood-testnet/blob/main/docs/integrating.md)
  is isolated regtest with a different genesis; its coins cannot fund this run.

## Commands, in execution order

Run from the repository. Use a private terminal, not a shared log. `LATCH_RUN`
is the prepared one-host workspace; distinct operators may instead use the same
lower-level CLIs and authenticated private packet exchange. Never copy a peer's
key to make a missing step pass.

```sh
LATCH_RUN="$PWD/.local/public-launch-002"
LATCH_RPC='https://sepolia.gateway.tenderly.co'
LATCH_CONSENTS="$LATCH_RUN/packets/consents.json"

# Already executed; idempotently verifies the existing quote and real DKG.
python3 scripts/public_launch.py owners "$LATCH_RUN"
# Read-only sync. Retain a checkpoint after incoming funds, then another at
# least 11 blocks later. Source/auxiliary/anchor each need 12 confirmations.
python3 scripts/testnet_wallet.py sync "$LATCH_RUN/source" --batches 32

# Read-only: every gas limit must keep 15% headroom on current Sepolia rules.
python3 scripts/measure_sepolia_gas.py
# Check only.
python3 scripts/public_deploy.py "$LATCH_RUN/deployment-owner" --eth-rpc "$LATCH_RPC"
# ONLY AFTER human public-execution authorization and funding:
python3 scripts/public_deploy.py "$LATCH_RUN/deployment-owner" --eth-rpc "$LATCH_RPC" --broadcast-testnet
# Repeat WITHOUT broadcast until finalized-by-provider; never deploy twice.
python3 scripts/public_deploy.py "$LATCH_RUN/deployment-owner" --eth-rpc "$LATCH_RPC"

# Start deadlines only after funded inputs and finalized deployment exist.
# Real source reservation, signed owner review, C/R, recovery receipts, final
# consents, portable exports, watch wallets and recipient birthdays are connected.
python3 scripts/measure_sepolia_gas.py
python3 scripts/public_launch.py prepare "$LATCH_RUN" --eth-rpc "$LATCH_RPC" --gas-cap-wei 100000000
python3 scripts/public_eth_outgoing.py init "$LATCH_RUN/alice" "$LATCH_CONSENTS"
python3 scripts/public_eth_outgoing.py init "$LATCH_RUN/bob" "$LATCH_CONSENTS"
python3 scripts/public_source_release.py prepare "$LATCH_RUN/alice" "$LATCH_RUN/source" "$LATCH_CONSENTS" --eth-rpc "$LATCH_RPC"
python3 scripts/public_source_execute.py "$LATCH_RUN/alice" "$LATCH_RUN/source" "$LATCH_CONSENTS" --eth-rpc "$LATCH_RPC"
python3 scripts/public_source_execute.py "$LATCH_RUN/alice" "$LATCH_RUN/source" "$LATCH_CONSENTS" --eth-rpc "$LATCH_RPC" --broadcast-testnet
```

Check commands that return status 2 report an observation or an incomplete
milestone, **not** completed settlement. Read the JSON result. A refusal must be
resolved, never ignored by a blind shell loop. Prepare keeps an existing plan
immutable; an expired reserved graph is not automatically reset.

Wait for **12 canonical F confirmations**. Sync both `alice-watch` and `bob-watch`
now, and again at least 11 blocks later so a confirmed historical witness exists.
Native timestamps allow the documented 7,200-second early-header bound. Plan
creation sets ETH expiry at 6 hours, funding cutoff at 4 hours, first-reveal
cutoff at 5 hours, native refund at 30 hours. Observe both networks continuously
through settlement; the paused development automation is not a trade monitor.

```sh
python3 scripts/public_recovery_watch.py sync "$LATCH_RUN/bob-watch" --batches 32
python3 scripts/public_recovery_watch.py sync "$LATCH_RUN/alice-watch" --batches 32
python3 scripts/public_eth_outgoing.py prepare "$LATCH_RUN/bob" "$LATCH_CONSENTS" --action lock --eth-rpc "$LATCH_RPC"
python3 scripts/public_eth_execute.py "$LATCH_RUN/bob" "$LATCH_CONSENTS" lock --eth-rpc "$LATCH_RPC"
python3 scripts/public_eth_execute.py "$LATCH_RUN/bob" "$LATCH_CONSENTS" lock --eth-rpc "$LATCH_RPC" --broadcast-testnet
python3 scripts/public_eth_delivery.py "$LATCH_RUN/bob" "$LATCH_CONSENTS" lock --eth-rpc "$LATCH_RPC"
```

Wait for provider-finalized lock, exact code/order and fresh native checks. Before
claim preparation, initialize Bob's opening monitor with the deployment receipt
block height (from `public_deploy.py`), then supervise `poll --rounds 4096` in
another terminal. Set `LATCH_START_BLOCK` to that **observed decimal height**.
After Alice prepares her claim, deliver its exact hash to Bob **before sending**;
set `LATCH_CLAIM_HASH` from the prepare result. No opening is sent to estimation.

```sh
python3 scripts/public_opening_monitor.py init "$LATCH_RUN/bob" "$LATCH_CONSENTS" --from-block "$LATCH_START_BLOCK" --endpoint "$LATCH_RPC"
python3 scripts/public_opening_monitor.py poll "$LATCH_RUN/bob" "$LATCH_CONSENTS" --rounds 4096 --interval 20
# In Alice's terminal, after verifying monitor operation:
python3 scripts/public_eth_outgoing.py prepare "$LATCH_RUN/alice" "$LATCH_CONSENTS" --action claim --eth-rpc "$LATCH_RPC"
python3 scripts/public_opening_monitor.py add-hash "$LATCH_RUN/bob" "$LATCH_CONSENTS" --transaction "$LATCH_CLAIM_HASH"
python3 scripts/public_eth_execute.py "$LATCH_RUN/alice" "$LATCH_CONSENTS" claim --eth-rpc "$LATCH_RPC"
python3 scripts/public_eth_execute.py "$LATCH_RUN/alice" "$LATCH_CONSENTS" claim --eth-rpc "$LATCH_RPC" --broadcast-testnet
# Bob must act on the actual valid opening, even before EVM finality.
python3 scripts/public_launch.py native-exit "$LATCH_RUN" --role bob
```

Set `LATCH_VERSION` to the `bytes_sha256` of the complete staged native version
returned by that last command. Sending repeats all live checks after proving.

```sh
python3 scripts/public_native_execute.py "$LATCH_RUN/bob" "$LATCH_VERSION" "$LATCH_CONSENTS" --watch-wallet "$LATCH_RUN/bob-watch" --eth-rpc "$LATCH_RPC"
python3 scripts/public_native_execute.py "$LATCH_RUN/bob" "$LATCH_VERSION" "$LATCH_CONSENTS" --watch-wallet "$LATCH_RUN/bob-watch" --eth-rpc "$LATCH_RPC" --broadcast-testnet
# After finalized ETH claim, Alice withdraws her exact fixed credit.
python3 scripts/public_eth_outgoing.py prepare "$LATCH_RUN/alice" "$LATCH_CONSENTS" --action withdraw --eth-rpc "$LATCH_RPC"
python3 scripts/public_eth_execute.py "$LATCH_RUN/alice" "$LATCH_CONSENTS" withdraw --eth-rpc "$LATCH_RPC" --broadcast-testnet
# After native confirmations and finalized withdrawal, verify both real results.
python3 scripts/public_launch.py verify "$LATCH_RUN" --version "$LATCH_VERSION" --eth-rpc "$LATCH_RPC"
```

Expected public evidence: deployment/F/lock/claim/C/withdrawal hashes, canonical
block identities and counts, exact runtime hash, and recipient-decrypted payout.
`verify` demands fresh native proof/signature validation, Bob's actual note
receipt and Alice's finalized exact withdrawal event. Private packets, viewing
keys, proofs, witness, nonce material and recovery journals are never evidence
uploads. Public Zcash hashes alone do not publicly prove its private amount.

## If either participant stops

Preserve the entire private workspace. Restart check-only reconciliation first.
An ambiguous send keeps its original bytes/hash; never generate a new trade or
restore an old filesystem snapshot over current exposure history.

- **Before F release:** retain/cancel the source authority with
  `public_source_guard.py cancel "$LATCH_RUN/source"`; no principal was locked.
  Possible source intent/release blocks cancellation. Check F before deciding.
- **F uncertain:** use `public_source_release.py resume` with the same Alice,
  source and consents, then `public_source_execute.py` check-only. It needs the
  original source wallet and canonical old anchor. Reuse exact bytes only.
- **No claim exposure:** after ETH expiry Bob prepares/sends `refund`, then
  `withdraw` using the same outgoing/execute commands with `--action refund` or
  `--action withdraw`. Once the ETH order is stably refunded (or was never
  locked), Alice sends her auxiliary transaction A. It refuses if her own claim
  history may be exposed or the order is not stably empty/refunded:

  ```sh
  python3 scripts/public_auxiliary_execute.py "$LATCH_RUN/alice" "$LATCH_RUN/source" "$LATCH_CONSENTS" --eth-rpc "$LATCH_RPC"
  python3 scripts/public_auxiliary_execute.py "$LATCH_RUN/alice" "$LATCH_RUN/source" "$LATCH_CONSENTS" --eth-rpc "$LATCH_RPC" --broadcast-testnet
  ```

  Wait until A has 12 confirmations (repeat the check-only command; it reports
  the state). After native timestamp maturity Alice runs
  `public_launch.py native-exit ... --role alice`, then `public_native_execute.py`
  with Alice, her version and `alice-watch`. The sender checks the auxiliary
  coin, ETH state and sticky exposure; do not infer non-exposure from an absent
  RPC result.
- **Any possible claim exposure:** Bob resumes his opening monitor and claim.
  Alice must reconcile/rebroadcast the same claim within the allowed policy;
  later absence never authorizes a no-reveal refund fallback. Recovery can mean
  receiving the counter-asset, not both original assets.
  After an uncertain claim send, rerun `public_eth_execute.py ... claim
  --broadcast-testnet` at once: while the provider has no receipt it resends
  the same signed bytes. A first claim send must start before
  `first_reveal_before`; a resend of those bytes after a recorded attempt is
  accepted until `first_reveal_before + eth_retry_seconds` (10 minutes in both
  profiles), the retry time the reveal cutoff already reserves. Do not initiate
  at the end of the window: this execution checklist requires **30 minutes of
  additional operating margin** before its cutoff. A lost/dropped claim after
  the retry time needs manual reconciliation; there is no general late fee-bump
  rescue. A successful preparation check alone does not establish first
  exposure. On 2026-10-21 the V2 success run's first claim send through
  Tenderly came back uncertain and the run script did not retry it for 73
  minutes; the operator then resent the identical bytes through publicnode with
  curl, 9 seconds before `first_reveal_before`, and the claim was mined
  ([record](../evidence/2026-10-21-public-testnet-v2.json)).
- **Lost anchor, deep source rollback, censorship, depleted fee reserve or
  missed monitoring bound:** stop new commitments and preserve all data. These
  exceed the demonstrated conditional guarantees; no automatic reset is safe.

See [protocol](protocol.md) for assumptions and [public integration details](public-testnet.md)
for each command's exact validation boundary. The public positive flow can reveal
further integration defects; it is not certified by the isolated execution.
