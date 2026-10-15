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

## OTC quote before preparation

The operator path can begin with an Alice-signed exact-amount quote and Bob's
signed acceptance. Each signer pins the accepted quote locally before preparing
C/R; the source uses the same amounts. The quote is included in the final native
terms and both full cross-chain consents. Quotes authorize preparation only;
contract identity, salt, deadlines and the exact funding graph still require
final consent. See [OTC offers](otc-offers.md). The legacy browser profile retains
its fixed amounts, and all current execution profiles remain isolated chains.

The public preparation path now has a separate [owner setup](public-owner-setup.md)
CLI. Independently pinned identity keys sign an exact public-profile quote,
authenticated DKG messages and matching destination receipts. The unsigned
testnet graph verifies those receipts and its reserved principal against the
quote. These setup approvals are distinct from transaction consent. Each public
owner can now verify a source-redacted graph packet and participate in C/R
shielded spend presigning using its local DKG share. A separate source stage
signs the reserved R auxiliary; both owners independently verify and durably
save the exact native exits before signing bundle/graph/plan-bound receipts.
Portable exports can be verified without original owner or source directories.
These public-profile checks have used synthetic nonexistent inputs with real
signatures/proofs, not public funded coins. A separate conditional agreement now
binds the native graph/receipts, clock/gas/confirmation policy and intended ETH
escrow target/code. Both owners sign it with a distinct public consent domain.
A separate read-only preflight now verifies those exact consents, rejects
synthetic inputs before network access, checks hash-pinned finalized/latest ETH
code/order state and gas reserves, and requires twelve fresh native F
confirmations for lock/reveal. This is preparation, never a release token.
It binds the exact saved local decisions and identity/peer pins of the caller
under their operator lock. The source wallet additionally requires immutable
owner pins bound to its actual keys and supports permanent pre-release
cancellation without deleting its reservation. Release/outgoing markers forbid
cancellation. A separate private source signer now holds the same source lock
through fresh funding preflight and commits its intent/release marker before
signing F. Restart verifies and reuses the exact signed bytes, including the
proof/signatures and original anchor. Even a pending intent forbids cancellation.
This does not authorize broadcast; public senders remain disabled.
It also derives the exact R auxiliary outpoint from the verified bundle and
checks its current index/origin/confirmations without source-wallet key access.
Funding preflight additionally binds the reserved note/nullifier/FVK/anchor to
the private unsigned F, synchronizes the source under its wallet lock and
rechecks the same unspent note and canonical old/current trees. This has real
isolated-history component tests but no funded public positive run. Portable
watch-only recovery now connects compact note/witness acquisition to private
native reproof of the original C/R authorizations. The native proofs have been
exercised with synthetic public-profile blocks and a retained real isolated
refund, not funded public recovery. Live observations are separate from offline
proving. A private outgoing journal now rechecks actual native bytes against the
accepted effects/proofs/signatures and persists each version before it can be
used by a future sender; interrupted raw persistence can resume without replacing
history. It requires the owner's saved acceptance and both consents. This does
not establish non-exposure or authorize a send. A native-only post-proof reader
now observes the exact exit before requiring an unspent input, verifies the
provider's actual proof/signature bytes, and retains earlier observations across
absence/reorg reports. If still unobserved, watch sync must obtain the prepared
bytes' exact anchor; an exit appearing during sync supersedes a spent-note error.
An owner-bound ETH recovery reader also accepts the exact agreed order's
empty/locked/claimed/refunded states after expiry and preserves checked claim
observations even if later reads fail. A separate bounded reader now extracts
candidate openings from an exact pending/mined claim hash or exact-order events.
Native adaptor/signature verification, independent of ETH finality, accepts the
opening privately; offline restart can resume from a saved raw response. A real
isolated pending claim has fed a synthetic-profile native C reproof. This does
not establish complete mempool visibility, public funding or ETH settlement.
An owner-bound foreground monitor now polls known hashes before bounded event
catch-up, journals coverage, repeats an overlap and restarts from its configured
height if the retained prefix changes. Offline replay accepts a saved opening
before further RPC work. This is trusted-provider observation, not complete
mempool coverage or a latency guarantee; failures need operator supervision.
Cross-chain/auxiliary reconciliation and durable send attempts remain unfinished.
The private source signer is an offline native primitive behind the live
preflight wrapper, not an independent verifier of live chain observations. The integrated
positive public path has not run with funded public inputs.
No public sender is enabled. See
[public preflight and its tested scope](public-testnet.md#agreement-bound-read-only-preflight).

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

In a time-domain deployment design, let ΔE bound ETH inclusion; ΔO bound secret observation; ΔZ bound Zcash
inclusion; κZ bound early Zcash block timestamps. Require conservatively
`tZ - κZ > tE + ΔO + ΔZ`; Alice reveals only when `now + ΔE < tE`.
This is an abstract safety condition, **not the implemented clock policy**:
the current cross-chain profile uses block height HZ, while ETH expiry is a timestamp.
HZ cannot be substituted for tZ, nor converted into a guaranteed time by using
the target block interval. Public deployment requires either a tested timestamp
refund path or an explicitly bounded/probabilistic block-rate assumption.
Deployed-network policy must account for clock error, node lag, fees, confirmation
depth and upgrades. Regtest parameters are not public-network defaults.
Native timestamps use block time, not an assumed MTP rule; see pinned Zebra.
The native-only timestamp primitive now passes an actual isolated refund and
watch-only recovery gate. Existing source/ETH clients refuse that profile until
its cross-chain timing and observation policy is implemented; see
[public-network readiness](public-testnet.md). No height-to-seconds conversion
or public reveal policy has been enabled by this primitive.

scripts/check_swap_model.py reproduces theft when the refund lock is ineffective
or the safety gap too short. This finite model is not a complete security proof.

## Visibility

Public source preparation now joins a historical confirmed witness to the
current compact scan's unspent-note set, checks block/tree identities against a
trusted provider, and creates a durable wallet-local note/auxiliary reservation.
This private package is not F authorization and does not change the transaction
order above. A reservation's age or candidate expiry cannot establish that a
previously signed transaction is impossible; no automatic release is permitted.
An offline public-profile builder can now produce an unsigned F/C/R draft with
native proof checks from this package. The draft binds authenticated owner
destinations but has no adaptor presignatures, bundle receipts or final graph
consents, and cannot authorize F.
The separate private source-signing stage requires the completed exits and both
conditional consents, as described above. Public sending remains disabled. See
the exact preparation thresholds and evidence limits in
[public-testnet.md](public-testnet.md).

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

The owner CLI also executes native exits. Bob reads the canonical ETH claim
event himself; Alice refuses no-reveal refund whenever her own durable claim
intent exists. Both bind their watch-only workspace back to the accepted bundle
and return pending/confirmation states without changing either chain's clock.
The browser's harness invokes these same commands and separately mines its
disposable native chain. Detached-coordinator, no-ETH-key and actual funding-fork
gates are described in [owner-operated recovery](owner-native-recovery.md).
This removes a coordinator filesystem dependency from native settlement; it
does not remove the trusted-RPC or bounded-monitoring assumptions.

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

Controlled Anvil fork tests now remove a previously observed claim receipt,
replay the exact bytes into a different block, then replace it with a different
relayer's canonical claim. Owner settlement observations are append-only per
block/transaction, and the original exposure intent is retained across forks.
The replacement event completes the real native exit. See
[EVM fork recovery](evm-reorg.md); this is before withdrawals/native settlement
and is not a public-network confirmation policy.

The native owner gate is also exercised by actual Zebra block invalidation:
one-confirmation or orphaned F prevents first secret exposure and new owner
lock processing. The original branch is then reconsidered before settlement.
See [native reorg tests](native-reorg.md). Separate actual claim/refund exit
forks retain F in the common ancestor. One-confirmation and pending exits regain
confirmation without a new send; an exit with an orphaned anchor is re-proved
from the accepted owner bundle with the same v6 effects txid. Native recipients
decrypt the same payout, old proof versions remain retained, and ETH withdrawals
are not repeated. The claim test starts after actual ETH secret exposure.
Owners now retain node-observed published F authorizations before ETH actions.
New v3 offers select a six-block older source witness while scanning nullifiers
through the current tip and keeping the current-height refund clock. This
reduces dependence on the newest tree without giving Bob source-wallet viewing
data. The source release wallet rejects an orphaned agreed anchor before signing.
See [funding anchor selection](funding-anchor.md); six blocks is an isolated
fixture parameter, not a public finality guarantee.
If F becomes orphaned but its source anchor/input remain usable, Bob can replay
the same bytes after verifying the exact canonical ETH claim. The actual gate
also refuses restoration when the ETH claim disappears/expires or a competing
ETH refund wins, preserves exposure intent, and restores absent or genuinely
pending F through the normal driver.
See [funding recovery](funding-reorg.md). Source re-proving, conflicting source
spends, coordinated recovery when both settlements are absent, a refund winning
beyond the allowed window, and public-network timing/finality remain unproven.
