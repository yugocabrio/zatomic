# ZEC / ETH point-lock swap — draft v1

Status: isolated-chain success and refund demonstrated; no public-network or
audited security claim. Setup uses separate participant processes on the same host.
Target: native Ironwood ZEC (v6, NU7 isolated regtest/public testnet) ↔ ETH
(local Anvil, then Sepolia). No token approvals or wrapped ZEC. One fixed pair,
two parties, one immutable escrow contract. Mainnet is not supported by the demo.

## Construction

Alice sells ZEC; Bob sells ETH. Alice chooses a fresh uniform nonzero Pallas
scalar t and publishes T=tG, with G the RedPallas SpendAuth basepoint. The EVM
escrow checks tG=T directly. No cross-curve DLEQ, hash/scalar correspondence
proof, oracle or bridge light client is required. This is a proposed composition
of existing techniques, not a claim to have invented PTLC swaps.

Zcash funding uses a fresh 2-of-2 FROST DKG spend key. Neither party holds the
whole spending key. Both obtain shared viewing data and can prove spends.
The FROST adaptor extension is custom and unaudited; upstream FROST security
does NOT automatically establish security of this modified protocol.

New browser runs prepare the native graph without generating a source spend
signature, then deploy the isolated escrow and obtain both owners' signatures
on the full cross-chain agreement. The source wallet verifies these against
pre-provisioned identity pins and journals a source release decision before
signing/releasing F. A local OS lock makes cancellation and release mutually
exclusive; an unreleased v3 setup can be permanently cancelled. See
[setup recovery](setup-recovery.md) and
[funding consent](funding-consent.md). Older reproduction runners retain the
earlier native-funding-first sequence. Owner keys and first secret exposure stay
in the owner clients; independent-host identity provisioning is still open.

## Transaction order

1. Agree canonical terms: both networks/genesis/branches, deployed ETH code
   and address, destinations, amounts/fees, T, refund times, confirmation
   policy and unique salt. Authenticate peers and messages.
2. Prepare Zcash funding F to the joint note. Before broadcast, Alice receives
   a fully signed refund R to her shielded destination; Bob receives and verifies
   an adaptor pre-signature for claim C to his shielded destination. Both C and
   R spend precisely F's joint note and bind all output/fee/expiry fields.
   Until both participants acknowledge their verified, durably saved exit
   bundle, peers see only a preview of F with zeroed spend/binding signatures.
   V6 gives that preview the same txid without making it broadcastable. Earlier
   milestones exposed authorized F in the policy; that setup-order gap is now
   fixed and tested with node rejection and a withheld receipt.
3. R includes an Alice-owned, dedicated transparent auxiliary UTXO with
   non-final sequence; nLockTime=tZ. Without it the native locktime is disabled.
   This auxiliary coin is separate from the shielded principal and cannot be
   a third party's coin. Claim C has no transparent component.
4. Before exposing F to the broadcaster, the local implementation generates
   and verifies both exit circuits against a temporary tree containing the exact
   pending note. Each signer additionally verifies R's shielded spend/binding
   signatures and the auxiliary P2PKH signature, C's dummy authorizations, and
   the presence and consistency of the private data needed to re-prove later.
   C's adaptor pre-signature is verified separately, without revealing t.
   These temporary proofs remain private bundle data and are never broadcast;
   C/R are re-proved after mining.
   Newly funded fixtures split a dedicated 20,000-zatoshi auxiliary coin from
   a matured coinbase first; R returns 15,000 after its incremental fee.
   Alice broadcasts F only after checking the prepared paths.
   Bob waits for authenticated confirmation of the exact note and obtains all
   data needed to prove C. He verifies R cannot become spendable too soon.
5. Bob locks the exact ETH amount in PointEscrow, bound to T, Alice's ETH
   recipient, terms digest and expiry tE. Alice checks the exact contract code,
   state and confirmation policy, with sufficient time remaining.
6. Alice submits t before the conservative reveal cutoff. Anyone may relay
   claim, but it credits only the fixed Alice recipient. Withdrawal is separate
   so a receiving contract that rejects ETH cannot revert a valid claim.
7. Bob obtains t from calldata/event, checks T, completes C and proves/broadcasts
   it. Bob monitors confirmation and rebroadcasts/reanchors as required.

No expiry on C/R is intended within the swap horizon; crossing a network upgrade
must be refused. The isolated chain gates exercise no-expiry v6 claim/refund transactions.
In v6 the signature does not bind anchors/witness/proof, permitting pre-signing
before F is mined. This property must be exercised, not merely cited.

## Recovery

| Stop/failure | Result under the stated assumptions |
|---|---|
| Either party refuses setup | No protocol funding should have occurred |
| Alice funds, Bob does not lock ETH | Alice broadcasts R after tZ |
| Bob locks, Alice never reveals | Bob refunds ETH at tE; Alice refunds ZEC after tZ |
| Alice stops after a valid timely ETH claim is sent | Bob observes t and completes C; Alice's ETH is credited |
| Bob stops after locking ETH | Safe only if Bob resumes/uses a relay before the Zcash recovery window ends |
| Bob sees t in a failed/late EVM transaction | t cannot be made secret again; Alice must enforce cutoff and valid-call checks |
| Reorg/censorship exceeds configured bounds | Safety is not guaranteed by this bounded-timelock construction |

This is a monitored atomic-swap design, not indefinite offline safety. The honest
party needs bounded observation/inclusion latency and sufficient fee reserves.
Confirmations reduce reorg risk; they do not make PoW finality mathematical.

Let ΔE bound ETH inclusion; ΔO bound secret observation; ΔZ bound Zcash
inclusion; κZ bound early Zcash block timestamps. Require conservatively
`tZ - κZ > tE + ΔO + ΔZ`; Alice reveals only when `now + ΔE < tE`.
Deployed-network policy must account for clock error, node lag, fees, confirmation
depth and upgrades. Regtest parameters are not public-network defaults.
Native timestamps use block time, not an assumed MTP rule; see pinned Zebra.

scripts/check_swap_model.py reproduces theft when the refund lock is ineffective
or the safety gap too short. This finite model is not a complete security proof.

## Visibility

- Zcash observers: normal shielded funding/claim metadata, no public principal
  or shielded address. Refund exposes an auxiliary transparent outpoint/amount
  and time; it may link that auxiliary coin to the refund.
- EVM observers: ETH amount, maker/recipient, T, t after reveal, deadlines,
  terms commitment and timing. ETH-side privacy is not claimed.
- Counterparty: agreed amounts/destinations and shared-note viewing/proving data.
  One-time DKG and fresh viewing keys prevent viewing unrelated swaps.
- Local fixture runner: both clients' synthetic secrets on one host; not evidence
  of independent operators or production secret isolation.

## References

- [ZIP 374](https://zips.z.cash/zip-0374): v6 deferred anchors/proofs.
- [ZIP 312](https://zips.z.cash/zip-0312): rerandomized FROST.
- [Zebra accessor](https://github.com/ZcashFoundation/zebra/blob/6cc6d360e51fe07e661c26f02230e06d81b468c7/zebra-chain/src/transaction.rs#L128): non-final transparent input required.
- [Zebra check](https://github.com/ZcashFoundation/zebra/blob/6cc6d360e51fe07e661c26f02230e06d81b468c7/zebra-consensus/src/transaction/check.rs#L71): strict block time/height comparison.
- [ASMR recovery](https://github.com/MerosCrypto/asmr/blob/f7623dda07d052835acb35ff11338e1d98d93f97/src/tests/swap/client/funded_get_scripted.rs): different BTC/Sapling construction with counter-asset recovery. Read, not executed/imported.
- [RFC 9591](https://www.rfc-editor.org/rfc/rfc9591.html): FROST, not a proof for our extension.
- [EFD](https://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html): formulas checked against pasta_curves vectors.

The first native gate now passes on isolated Zebra + Anvil: C/R pre-authorized
before funding, R rejected before its height, C completed from an actual EVM
witness, and competing R rejected after C. A separate no-reveal run returns
both assets. See evidence/2026-10-15-chain-{success,refund}.json. The fixture uses
controlled block heights/times; it does not implement the public timing policy
above. Independent local signer processes and persisted nonce-attempt replay protection
are now implemented. A participant validates its own receiver, funding output,
shared input, payout, fees, auxiliary layout, refund height and signature domain
before contributing. Private pipes are not authenticated remote transport.

Recovery from durable checkpoints restores the owned Anvil node and reconciles
actual native confirmations. This is local restart recovery, not a proof of
public-network finality. It cannot repair an unsafe deadline or guarantee a claim
after an arbitrarily long outage. Original immutable evidence is preserved.
Auxiliary coin reservation and current unspent checks precede the local runner's
funding broadcast and ETH lock; direct users of the low-level Rust primitives
must provide those checks themselves.

Outgoing local EVM calls use a write-ahead signed-transaction journal. Before
broadcast, the preceding owned Anvil state and exact raw transaction/hash are
fsynced. Recovery decodes the signed bytes and recovered sender rather than
trusting the journal's method label. A missing receipt is not proof that the
claim secret stayed private: the same timely claim may be replayed; outside the
bounded window, recovery stops without falling back to both refunds. These
lock/claim interruption paths have actual chain evidence. Partial setup now has
the cancellation/committed-release paths described above; public chain reorg
handling remains separate work.

The optional coordinator-to-signer TLS transport now integrates with a real
chain swap and rejects credential/protocol/role mismatches and replay after
disconnect. This authenticates the coordinator connection, not chain state or
independent economic consent. The tested fixture still shares local artifact
paths; verified native bundles are now delivered over that channel, but
independently operated source wallets and remote owner clients remain unfinished. See
[signer transport](signer-transport.md) for exact scope and reproduction.

Each participant can export its own accepted bundle into a fresh native recovery
workspace with viewing/proving data and the correct prepared exit, without
exporting spending keys. See [recovery bundles](recovery-bundles.md). The fixture
recovery still restores the owned EVM checkpoint and uses its shared journal;
native bundle portability does not establish public-network independence.

The newer [owner CLI path](owner-clients.md) validates each owner's ETH address
and native bundle before accepting the same ETH agreement. It signs fixed
actions locally and stores each owner's signed intent before sending. Actual
mempool/interruption tests pass, including a competing relay that succeeds while
Alice's original transaction reverts. Reconciliation uses the validated order's
canonical event, preserving the fixed recipient. This remains a same-host
fixture with trusted local validating nodes and controlled confirmation policy.

The browser now invokes those owner clients through `prefunding_swap.py`, which
delegates funded settlement to `owner_swap.py`. The local
harness checkpoints its disposable EVM before each owner action; the owner
persists its signed intent before broadcast, and the harness checkpoints again
after success. A lost post-send checkpoint is therefore reconciled by the same
owner and exact signed bytes. Restoring a local test node is not a public-chain
finality or reorg mechanism. An existing claim intent blocks no-reveal refunds,
and missing owner acceptance/identity state rejects recovery. The browser's
normal, post-claim stop and pre-reveal stop paths use each owner's exported
native workspace, with the peer directory unavailable during its native exit.
Partial setup uses [source decision recovery](setup-recovery.md). Peer-directory
moves are journaled before renaming, and surviving process guardians clean the
owned prover/node/signer workers after parent SIGKILL. Actual claim/refund and
setup gates are recorded in [process recovery](process-recovery.md). Arbitrary
instruction-boundary failures and public-network reorg recovery remain unproven.
