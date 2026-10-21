# Gas optimization benchmark: claim verifier and order storage

**Update (2026-10-21): the comb + hash design shipped** as PointEscrowV2, at
width 4, after its own review ([review](review-escrow-v2.md)). Its Sepolia
receipts: deployment with table 7,100,182, lock 139,146, claim 112,528,
refund 32,981, withdrawal 43,562 to 43,586
([record](../evidence/2026-10-21-public-testnet-v2.json)). The text below is the
2026-10-18 benchmark, unchanged.

**Status: benchmark only (2026-10-18).** Nothing here is deployed or broadcast,
and the shipped contracts are unchanged. `contracts/src/Pallas.sol` and
`contracts/src/PointEscrow.sol` are untouched. After `forge build` the
PointEscrow runtime hash is still
`0x6267f59be4896a2d311e0eb7bdf9bfb5ada76fcecb140ac6589aaee8a85b569a`, the value
pinned in `config/public-agreement-policy-v1.json` and used by the public Sepolia
run. Every number below is a measurement, unless it is marked as arithmetic on
measured values. The new assembly has not had an independent review.

Two rule sets were measured, using the same contracts, scalars and order of
steps:

- **Standard rules (Prague).** Receipt `gasUsed` of real transactions on a
  private Anvil (Foundry 1.3.1, default hardfork Prague).
- **Current Sepolia rules.** Read-only `eth_simulateV1` against Sepolia block
  11,943,536 (2026-10-18 20:47:12 UTC), the same method as
  `scripts/measure_sepolia_gas.py`. Sepolia runs Glamsterdam: the Ethereum
  Foundation's [Glamsterdam testnet announcement][ef] gives the Sepolia
  activation as UNIX 1791294816 (2026-10-06 13:53:36 UTC), and the node's
  `eth_config` reports the same activation time for its current fork. Among
  Glamsterdam's EIPs, that announcement lists EIP-8037 (State Creation Gas
  Cost Increase) and EIP-8038 (State-access gas cost update). Mainnet has not
  adopted these rules. The Anvil column stands in for mainnet as it is today.

The variants:

| Name | Contract | Verifier | Order storage |
|---|---|---|---|
| Shipped | `contracts/src/PointEscrow.sol` | `Pallas.opens` | 7-slot struct |
| Comb | `contracts/bench/PointEscrowFast.sol` | `PallasComb` comb | 7-slot struct |
| Comb + hash | `contracts/bench/HashedPointEscrow.sol` | `PallasComb` comb | one slot holding the order hash |

Comb widths t = 4 to 8 were all measured. The table for width t is the data
contract `PallasCombTable{t}`. "Random" means the median of eight random
scalars, and `2^254−1` is the worst case for `Pallas.opens`, because it has the
most point additions.

## Result at width 8

| Step | Shipped, Prague | Comb t=8, Prague | Comb + hash t=8, Prague | Shipped, Sepolia | Comb t=8, Sepolia | Comb + hash t=8, Sepolia |
|---|---:|---:|---:|---:|---:|---:|
| Deploy table (once) | — | 3,625,780 | 3,625,780 | — | 25,490,376 | 25,490,376 |
| Deploy escrow (once) | 735,311 | 781,168 | 818,179 | 5,090,645 | 5,312,498 | 5,576,975 |
| Lock | 183,707 | 183,694 | **51,071** | 799,459 | 799,446 | **139,103** |
| Claim, random | 515,863 | **98,840** | **93,794** | 605,083 | **191,660** | **186,614** |
| Claim, 2^254−1 | 678,990 | 98,840 | 93,806 | 768,210 | 191,660 | 186,626 |
| Refund | 54,611 | 54,605 | 53,997 | 143,831 | 143,825 | 143,217 |
| Withdraw | 30,719 | 30,722 | 30,766 | 31,216 | 31,218 | 31,253 |
| **Swap: lock + claim + withdraw (random)** | **730,289** | **313,256 (−57%)** | **175,631 (−76%)** | **1,435,758** | **1,022,324 (−29%)** | **356,970 (−75%)** |
| Swap, 2^254−1 | 893,416 | 313,256 (−65%) | 175,643 (−80%) | 1,598,885 | 1,022,324 (−36%) | 356,982 (−78%) |
| No-reveal: lock + refund + withdraw | 269,037 | 269,021 | 135,834 (−50%) | 974,496 | 974,479 | 313,564 (−68%) |

**Ranges.** Lock and withdraw are the largest values observed; calldata zero
bytes move them by up to 24 gas. The random-scalar claims ranged as follows:

| Variant | Prague | Sepolia |
|---|---:|---:|
| Shipped | 493,420–521,626 | 582,640–610,846 |
| Comb | 98,164–98,840 | 190,884–191,660 |
| Comb + hash | 93,139–93,806 | 185,835–186,626 |

**Shipped figures reproduce the earlier records.**

- On Prague, deployment is exactly the recorded 735,311.
- On Sepolia, deployment (5,090,645), lock (799,459), worst-case claim
  (768,210), refund (143,831) and withdraw (31,216) equal
  `evidence/2026-10-18-sepolia-gas.json` exactly. The public run's receipts
  were lock 799,447 and claim 589,726.

**Where Sepolia differs.** Each new storage slot costs about 88k more on
Sepolia than on Prague. Lock grows by 615,752 for the shipped and comb
escrows, which write seven new slots, and by 88,032 for the hashed escrow,
which writes one. Every claim also creates a new credit slot. The
worst-case claim grows by 89,220 for the shipped escrow, and by 92,820 for
the comb at t = 8, rising to 96,020 at t = 4. The extra grows with the number
of table reads (32 at t = 8, 64 at t = 4), which suggests that reading code
from the table contract also costs more on Sepolia. That cause was not
isolated.

**Table size.** Deploying a table costs about 219 gas per byte on Prague and
about 1,549 per byte on Sepolia: the marginal cost from t = 4 (961 bytes) to
t = 8 (16,321 bytes), computed from the measurements. That matches EIP-8037's
1,530 gas per state byte for deployed code, plus calldata and hashing.

**The 2^24 cap does not block the width-8 table.** [EIP-8037][eip8037] (status
Last Call) meters state gas separately: "the transaction gas limit set in
EIP-7825 only applies to execution-gas", and `tx.gas` may reach 2^32−1. Most of
the 25,490,376 gas of the width-8 table deployment is state gas for its 16,321
code bytes, so the 2^24 (16,777,216) execution cap of EIP-7825 does not apply
to it. I verified the EIP text and three observations, but no actual
deployment:

- Simulation with `validation: true` accepted a 30M gas limit.
- In blocks 11,942,012 to 11,943,511, 278 included transactions used more than
  2^24 gas, for example a contract creation of 39,135,637 gas in block
  11,942,024 (tx `0x97571eedbf33c72238bf85ed21d76ca49714802eb9704cfc0820c91eb32ad67e`).
- A plain transfer to a new account costs 204,600 = 21,000 + 183,600, the
  EIP's 120 state bytes × 1,530 for a new account.

Simulation is not inclusion.

Raw output is in `contracts/bench/gas-results.json` (Prague) and
`contracts/bench/sepolia-gas-results.json` (Sepolia).

## Comb width: measured claims and break-even

Claims at the worst-case scalar for each width. On Prague every table was
deployed once and shared by every escrow of that width; on Sepolia each
simulation deployed its own table.

| t | Table bytes | Table deploy, Prague | Table deploy, Sepolia | Comb claim, Prague | Comb + hash claim, Prague | Comb claim, Sepolia | Comb + hash claim, Sepolia |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 4 | 961 | 263,688 | 1,696,604 | 135,128 | 129,806 | 231,148 | 225,826 |
| 5 | 1,985 | 487,837 | 3,282,865 | 120,386 | 115,181 | 215,106 | 209,901 |
| 6 | 4,033 | 936,058 | 6,455,310 | 111,314 | 106,169 | 205,234 | 200,089 |
| 7 | 8,129 | 1,832,512 | 12,800,212 | 104,510 | 99,431 | 197,818 | 192,751 |
| 8 | 16,321 | 3,625,780 | 25,490,376 | 98,840 | 93,806 | 191,660 | 186,626 |

For t = 4 to 7 the sweep used the worst-case scalar and two random scalars;
the random claims fell within 6.5k gas below the worst case. Width 9 would need
a 32,705-byte table, over the 24,576-byte code limit.

**Claims needed to repay a larger table.** The figures below are arithmetic on
the measurements above: the extra table deployment divided by the claim gas
saved per claim, for the comb + hash variant at the worst-case scalar. The comb
variant differs by under 1%.

| Upgrade | Prague | Sepolia |
|---|---:|---:|
| t4 → t5 | 15 | 100 |
| t5 → t6 | 50 | 323 |
| t6 → t7 | 133 | 865 |
| t7 → t8 | 319 | 2,072 |
| t4 → t8 | 93 | 607 |

**Versus keeping the shipped escrow.** The table below is again arithmetic on
the measurements. It assumes a fresh table and escrow are deployed alongside
the swaps. It compares the variant's worst-case swap with the shipped escrow's
median swap, which is conservative for the variant.

| Width | Comb + hash, Prague | Comb + hash, Sepolia | Comb, Prague | Comb, Sepolia |
|---:|---:|---:|---:|---:|
| t = 4 | 0.7 swaps | 2.1 swaps | 0.8 swaps | 5.1 swaps |
| t = 8 | 6.7 swaps | 24.1 swaps | 8.8 swaps | 62.2 swaps |

Total gas on Sepolia for one deployment plus N swaps:

| Swaps N | Shipped (escrow + N median swaps) | Comb + hash t=4 (own table) | Comb + hash t=8 (own table) | Comb + hash t=8 (table already deployed) |
|---:|---:|---:|---:|---:|
| 1 | 6,526,403 | 7,668,458 | 31,424,333 | 5,933,957 |
| 2 | 7,962,161 | 8,064,640 | 31,781,315 | 6,290,939 |
| 5 | 12,269,435 | 9,253,186 | 32,852,261 | 7,361,885 |
| 10 | 19,448,225 | 11,234,096 | 34,637,171 | 9,146,795 |

With its own table, width 4 is the cheapest comb width up to about 100 claims
on Sepolia (and about 15 on Prague).

## Recommendation for bilateral OTC

**Share one table per chain.** The table contract has no owner and no storage,
its code begins with STOP so calling it does nothing, and its code cannot
change. One deployment can serve every
escrow on that chain. `testEveryWidthSettles` uses one table for both a comb
escrow and a comb + hash escrow, and the Prague run shared each table across
all escrows of its width. Each escrow checks the table's code hash in its
constructor. A deterministic address (for example, from a fixed CREATE2
factory) would make the table easy to find, and would make the escrow runtime
hash reproducible.

**Use t = 4 by default.** Sharing a table spreads its cost across escrows,
but it does not remove the break-even: someone still pays the larger table's
extra deployment, and on Sepolia t = 8 repays it over t = 4 only after about
607 claims (93 on Prague) across all users of that table. A 961-byte table
costs 1.70M gas on Sepolia. A larger table repays its extra deployment only
after 100 to 2,072 claims on Sepolia. With its own table, comb + hash at
t = 4 overtakes the shipped escrow from the third swap on Sepolia: the shipped
escrow is cheaper for one swap (6.53M against 7.67M) and still slightly
cheaper for two. Only a table already deployed by someone else makes t = 8 the
cheaper choice for a newcomer (186,626 against 225,826 per claim on Sepolia).

The production candidate, `PointEscrowV2`, uses t = 4 and goes further: see
`docs/escrow-v2-review.md`.

**In both cases, use the one-slot order.** On current Sepolia, lock goes from
799k to 139k gas. That is most of the saving, because the shipped lock creates
seven storage slots.

**The escrow can be shared too.** `PointEscrow` has no owner and keys each
order by chain, contract, maker and salt, so one deployment could serve every
pair. Then only the per-swap figures matter: 356,970 gas for comb + hash
against 1,435,758 shipped, on Sepolia.

## Adopting a variant: requirements and risks

**Both variants require:**

1. **Contract changes.** `PallasComb.sol` and the generated tables now live in
   `contracts/src`; `PointEscrowV2` is the integrated candidate. The escrow takes `(table, teeth)` in its constructor and
   checks `table.codehash` against the generated constant, as both bench
   escrows do.
2. **Review.** Get an independent review of the assembly and of the argument
   under [Same predicate as Pallas.opens](#same-predicate-as-pallasopens).
3. **Redeploy and re-pin.** The creation and runtime hashes change. The
   runtime embeds the table address and the width constants as immutables, so
   the runtime hash depends on where the table is deployed. That needs a new
   policy version beside `config/public-agreement-policy-v1.json`, carrying the
   new hashes, the source hashes, and the table address and code hash. The
   Sepolia escrow `0xcc0ce295627b5e15cd31a40dc6ace4bf3a35ee42` cannot be
   upgraded; it stays pinned by v1.
4. **New fee limits.** Re-derive the fee-profile gas limits from these
   measurements. The current 1,000,000 limits for lock and claim keep 15%
   headroom for every variant. The 6,500,000 deploy limit covers the hashed
   escrow (5,576,975 × 1.15 = 6,413,521), but not a table deployment.
5. **Re-run every flow.** Run `forge test`, the local two-party and owner
   flows, the hosted flow, and this Sepolia simulation on the final bytecode.
   Then repeat the public Sepolia swap. The public deployment and every
   broadcast need explicit authorization and test funds.

**The comb verifier keeps the ABI, but carries these risks:**

- **A wrong verdict loses funds either way.** A false accept would let Alice
  take the ETH without revealing t, so Bob loses. A false reject reverts the
  claim, but the reverted transaction still publishes t: Bob takes the ZEC
  and Alice loses. The mitigations are the differential tests, an independent
  review, and a client pre-check that runs the claim against the pinned
  bytecode on a private, throwaway local node (`scripts/claim_precheck.py`).
  It must never be an `eth_call`, `eth_estimateGas` or `eth_simulateV1` to an
  RPC provider: that would hand t to the provider before Alice's claim is
  included, so a leaky provider could let Bob take the ZEC while her claim
  fails or misses the deadline.
- **Table integrity and immutability.** The constructor rejects any code whose
  hash differs from the generated constant, including an empty address. The
  table's code is fixed: it has no SELFDESTRUCT, and since EIP-6780 code cannot
  be removed outside its creation transaction. Anyone can regenerate it with
  `gen_comb_tables.py`, and `testEveryTableEntryIsTheIntendedMultiple` checks
  every entry against `Pallas.opens`.
- **Reading code from another contract.** Each claim reads 32 to 64 entries
  with `EXTCODECOPY`, whose price is a protocol parameter. On Sepolia the comb
  claim's surcharge over Prague already exceeds the shipped claim's by 3.6k
  (t = 8) to 6.8k (t = 4), growing with the number of table reads (measured
  above; the cause was not isolated). Signed gas limits need headroom, and
  every new fork needs a re-measurement. A table missing on a given chain is
  caught at construction.

**The one-slot order also changes the ABI, and has these risks:**

- **The ABI change.** The calls become `claim(bytes32, Order, uint256)` and
  `refund(bytes32, Order)`, and `orders(id)` returns a hash.
- **Client changes.** Every caller that encodes claim or refund, or decodes
  `orders(id)`, has to change. These callers are:
  - `scripts/evm_participant.py`
  - `scripts/evm_journal.py`
  - `scripts/party_app.py`
  - `scripts/public_eth_outgoing.py`
  - `scripts/prefunding_swap.py`
  - `scripts/run_client_swap.py`
  - `scripts/run_regtest_swap.py`
  - `scripts/recover_regtest_swap.py`
  - `scripts/run_native_evm_gate.py`
  - the `scripts/check_*` harnesses
  - `scripts/measure_sepolia_gas.py`

  Clients would recompute the order hash from the signed terms and compare it
  with `orders(id)`. That check is as strong as reading the seven fields.
- **Validating the calldata order.** Claim and refund proceed only when
  `keccak256(abi.encode(order))` equals the stored hash. The hash binds maker,
  recipient, amount, refundAt, both point coordinates and termsHash, and the
  id binds chain, contract, maker and salt. `testHashedRejectsAnyAlteredField`
  changes each field, including a different point the claimer can open, and
  `testHashedRejectsDirtyOrderWords` shows that dirty high bits in maker,
  recipient or refundAt are rejected rather than cleaned. The CLAIMED (1) and
  REFUNDED (2) tombstones cannot equal a keccak output in practice.
- **Recovering the order.** Recovery depends on having the order fields. Bob
  needs them to refund. They come from the signed agreement, and they are
  rebuilt from the unchanged `Locked` event if the client loses them. Claim
  calldata grows by seven words; that cost is included in the claim figures.

## Method

**Fixed-base comb** (`contracts/src/PallasComb.sol`). This is a Lim–Lee comb
with one table. The scalar is split into t rows of d = ⌈255/t⌉ bits. Column j
selects idx = Σᵢ bit(j + d·i)·2ⁱ, and the precomputed entry is
table[idx] = Σ_{bits i of idx} 2^(d·i)·G. The loop runs MSB column first:
d−1 doublings and at most d mixed additions. With t = 8 that is 31 doublings
and 32 additions, against 254 doublings and up to 254 additions for
`Pallas.opens`. One multiply gathers a column index:
`((k >> j) & mask) * magic >> shift`, where mask = Σ 2^(d·i),
magic = Σ 2^((d−1)(t−1−i)) and shift = (d−1)(t−1). Because t < d, no carry
reaches the target bits. `gen_comb_tables.py` checks the index against the
direct bit sum for each width before writing.

**Arithmetic.** The arithmetic uses inline-assembly `mulmod`/`addmod` on
Jacobian coordinates, with no memory allocation. Doubling is dbl-2009-l
(a = 0), with D computed as (2X)(2Y²) in one multiplication. Addition is
madd-2007-bl, with Z3 = 2·Z1·H. The modulus P < 2^255, so sums below 2^256
(such as 2X or 3X²) go into `mulmod` without reduction. Every stored or
compared value is fully reduced. The escrows hold the comb constants as
immutables set in the constructor.

**Table placement.** Each `PallasCombTable{t}` constructor returns a 0x00 (STOP)
byte followed by the 64-byte affine entries as its runtime code. Entries are
read with `EXTCODECOPY` into scratch memory. `contracts/tools/gen_comb_tables.py`
regenerates `PallasCombTables.sol`, including each width's size and code hash,
from plain affine double-and-add.

**One-slot order** (`contracts/bench/HashedPointEscrow.sol`). Lock stores
`keccak256(abi.encode(Order))` in a single slot instead of the 7-slot struct,
and emits the same `Locked` event with every field. Claim and refund take the
order as calldata and revert with `NotLocked` unless it hashes to the stored
value. After settlement the slot holds a CLAIMED (1) or REFUNDED (2) tombstone,
so an id is never reused. The other rules are copied from `PointEscrow`: fixed
recipient, relayable claim, claim strictly before `refundAt`, refund from
`refundAt`, credit then withdraw. Refund saves little, because the cold storage
reads it saves are paid back as order calldata.

### Verifier alone (Prague, same frame)

`gasleft()` deltas around the internal call (`testGasVerification`, run with
`-vv`):

| t | Random scalars (3) | 2^254−1 | Q−1 | 1 |
|---:|---:|---:|---:|---:|
| 4 | 69,597–70,949 | 72,373 | 55,401 | 10,538 |
| 5 | 56,636–57,988 | 57,644 | 47,172 | 9,082 |
| 6 | 46,736–49,440 | 48,580 | 40,995 | 8,186 |
| 7 | 42,522 | 41,782 | 35,772 | 7,514 |
| 8 | 36,757 | 36,117 | 32,701 | 6,954 |
| `Pallas.opens` | 515,459–519,463 | 711,897 | 389,661 | 80,925 |

`Pallas.opens` allocates a new struct at every step, so its same-frame figure
also includes memory expansion. The gas report measures each function as an
external call in a fresh frame
(`forge test --match-test testGasHarness --gas-report`, four accepting calls:
2^254−1 and three random scalars):

| Function | Min | Median | Max |
|---|---:|---:|---:|
| `opensRef` (`Pallas.opens`) | 479,763 | 489,645 | 694,446 |
| `fast8` (`PallasComb`, t = 8) | 41,803 | 41,803 | 41,803 |

`fast8` also ABI-decodes its input and computes the comb constants in a loop.

**Not done.** None of the following was measured:

- The GLV endomorphism was not implemented. With a comb, only 31 doublings are
  left to save.
- Putting the table in the verifier's own code (`CODECOPY` instead of
  `EXTCODECOPY`) was not built.
- A version with the t = 8 constants written in as literals measured 39,208
  gas, slower than the parameterized 36,757, and was dropped.

## Same predicate as `Pallas.opens`

`PallasComb.opens` makes the same checks in the same order. It returns false
for scalar 0, for scalar ≥ Q, for a coordinate ≥ P, and for a point off
y² = x³ + 5. Otherwise it returns true exactly when scalar·G = T: it compares
X = x·Z² and Y = y·Z³, and returns false if the result is the point at infinity.

Doubling needs no special case: Z3 = 2YZ is 0 for infinity, and for y = 0,
which no Pallas point has because the group order is odd. The equal-x case of
the mixed addition is handled exactly: equal points are doubled, and opposite
points give infinity.

For 0 < k < Q, this case can never happen, because of how the scalar is cut
into columns. Write S_j for the accumulator's scalar after columns d−1…j, and
B_j for the entry's scalar at column j. Then S_j = 2S_{j+1} + B_j, and
0 ≤ S_j ≤ k/2^j < Q. An addition happens only when S_{j+1} ≠ 0 and B_j ≠ 0.

- **"Equal" case.** Both 2S_{j+1} and B_j lie in [0, Q), so 2S_{j+1} ≡ B_j
  (mod Q) means they are equal as integers. In base 2^d, the digits of 2S_{j+1}
  are even and those of B_j are 0 or 1, so both would be 0. That contradicts
  B_j ≠ 0.
- **"Opposite" case.** This would need S_j ≡ 0 (mod Q), but 0 < S_j < Q.

## Tests

| File | What it checks |
|---|---|
| `contracts/test/PallasComb.t.sol` | Widths 4–8 against `Pallas.opens`. Expected points come from a third, independent implementation: affine double-and-add with modexp inversion. |
| `contracts/test/BenchEscrows.t.sol` | The benchmark escrows keep the shipped rules. |

The tests in `PallasComb.t.sol`:

- **Every table entry**: each of the 491 entries is the intended multiple.
- **Edge scalars**: 1, 2, 3, Q−1, Q−2, Q−3, 2^254−1, 2^254, 2^254+1, 2^253,
  2^253−1, 2^252+2^251, (Q±1)/2, Q−2^128, and values around 2^32, 2^64,
  2^128, 2^200 and 2^224.
- **Column boundaries**: 2^(d·i) and 2^(d·i)±1 for every width.
- **Mutations of each valid opening**, all rejected: −T, an x or y bit flip,
  k±1, Q−k, k+Q, x+P and y+P.
- **Fixed rejection cases**: scalars 0, Q, Q+1, 2Q−1, 2^255 and 2^256−1 with G;
  the points (0,0), (0,1), (P, GY), (2^256−1, 2^256−1) and −G with scalar 1.
  Q−1 with −G is accepted by both.
- **Three fuzz tests** at 128 runs each.

`BenchEscrows.t.sol` covers:

- table code-hash and width checks, including a wrong width, an unsupported
  width and an empty address;
- settlement at every width with tables shared between escrows;
- relayed claim to the fixed recipient only;
- replay and double settlement;
- refund and claim-expiry boundaries;
- rejected witnesses;
- altered order fields;
- dirty order words.

Result: `forge test` passes 39 of 39 tests, including the existing
`PointEscrow` and `PallasVectors` suites.

## Commands and versions

```bash
python3 contracts/tools/gen_comb_tables.py   # regenerate PallasCombTables.sol; Python comb self-check
forge build
forge test                                   # 39 tests
forge test --match-test testGasVerification -vv
forge test --match-test testGasHarness --gas-report
python3 contracts/bench/measure_escrow_gas.py        # Prague: private Anvil on a free 127.0.0.1 port -> gas-results.json
python3 contracts/bench/measure_sepolia_variants.py  # Sepolia: eth_simulateV1, pins the latest block -> sepolia-gas-results.json
```

Versions and endpoints:

- forge, anvil and cast 1.3.1-stable (commit
  08d3a4ad4d78b62bcb897350803bf96fc2cf6cc9).
- solc 0.8.25 through solc-js (`scripts/solc.cjs`), `via_ir`, optimizer at
  200 runs, compiled for `evm_version` cancun. These are the settings in
  `foundry.toml`.
- Sepolia endpoint: `https://ethereum-sepolia-rpc.publicnode.com`, client
  `reth/v2.7.0-3d592ec`, `eth_config` fork id `0x6c1d9423`.
- The Sepolia matrix ran 63 simulations at block 11,943,536, with
  `validation: false`. Each simulation deploys its own table and escrow from
  fresh random addresses that exist only through balance overrides.

The scripts read and write no key. The Anvil script uses Anvil's unlocked
development accounts. The Sepolia script signs and broadcasts nothing, but it
does send the benchmark bytecode to the RPC provider.

[ef]: https://blog.ethereum.org/2026/09/17/glamsterdam-testnet-announcement
[eip8037]: https://eips.ethereum.org/EIPS/eip-8037
