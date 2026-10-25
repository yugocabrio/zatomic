# Zatomic protocol

**Status:** settled and refunded on the public Zcash testnet and Sepolia, with the
first escrow (2026-10-18, 2026-10-20) and with the shipped V2 escrow (2026-10-21);
every transaction is in the [evidence index](evidence-index.md). Both owners ran
on one host. The adaptor extension and the Solidity Pallas check are unaudited,
and mainnet is unsupported.

## In one page

**The problem.** Alice has ZEC and wants ETH; Bob has ETH and wants ZEC. Whoever
pays first can be cheated, so the two payments must be linked. Bitcoin-style
swaps do this with hash and time locks in scripts, but a shielded Zcash note has
no scripts: it moves only with a valid spend signature from its key.

![Two payments linked by one secret](images/swap-diagram.png)

**One key, two exits.** A FROST DKG gives Alice and Bob a fresh 2-of-2 spend key.
The joint note is an ordinary Ironwood shielded note whose spend authorization key
is that FROST key, so neither can spend it alone. Before Alice funds it, both
exits from that note are prepared and checked by both sides:

![The joint note and its two exits, both signed before F is sent](images/two-exits.png)


| Transaction | What it does | When it can be used |
|---|---|---|
| F | Moves Alice's ZEC into the joint note; no transparent part | Alice sends it after checking both exits |
| C | Pays the joint note to Bob; adaptor pre-signed | Once t is public |
| R | Returns the joint note to Alice; fully signed | After the native refund time |
| A | Turns some of Alice's own change into a 20,000-zatoshi transparent coin that R spends | Only on the refund path |

On Ethereum, PointEscrowV2's `lock` binds the amount, Alice's fixed recipient,
the expiry and the Pallas point T. `claim(t)` credits Alice if t·G = T, `refund`
returns the ETH to Bob after the expiry, and `withdraw` pays out a credit
separately.

**Why t completes C.** A RedPallas signature (R, s) on key X and message m, with
challenge c = H(R, X, m), verifies when s·G = R + c·X. Alice picks t and shares
only T = t·G, where G is the RedPallas SpendAuth base. The two signers produce a
pre-signature for C that is one secret short, for the randomized spend key X′:

    ŝ·G = R̂ − T + c·X′

Adding t gives s = ŝ + t, and s·G = R̂ + c·X′ is an ordinary valid signature.
Claiming the ETH publishes t, and the escrow checks t·G = T on Pallas itself, so
no cross-curve proof is needed.

In plain FROST the two partial signatures add up to a valid signature; here they
add up to ŝ, one secret short. Bob checks the pre-signature against C's sighash,
the spend key and T himself, before Alice funds anything, and Alice releases her
share only after verifying Bob's (see [security](security.md)). FROST provides the
joint custody; the adaptor signature lets Bob later claim alone.

**Why the exits can be signed before the note exists.** In the v6 transaction
format ([ZIP 229](https://github.com/zcash/zips/blob/929a92f7383e036b6f6a48f43ec88c5bdd130003/zips/zip-0229.md#anchor-commitment-version-6)),
the anchor and the zero-knowledge proofs are authorizing data, outside the digest
that spend signatures sign. So C, R and A are signed before F is mined, checked
against a temporary tree that contains the pending note, and proved against the
real anchor afterwards without new signatures. C and R spend the same note, so
they share a nullifier: only one of them can ever be mined.

**Why the refund needs a transparent coin.** Zcash enforces a lock time only when
a transaction has a transparent input with a non-final sequence number. R
therefore also spends the coin from A, which Alice creates from her own change
only if she refunds. A settled swap puts only F and C on chain, both fully
shielded.

**Deadlines.** The ETH expiry comes first and the native refund time later, so
that after Alice reveals t, Bob still has time to complete C before R becomes
valid. Alice must reveal t early enough for her claim to be mined well before
the ETH expiry. Both sides watch their deadlines, and recovery assumes that
inclusion and reorgs stay within the timing window.

**Outcomes.** If t is revealed, Alice withdraws the ETH and Bob completes C, even
with Alice offline.

![The five steps: thick arrows move funds, a check marks where each side receives the other's asset](images/five-steps.png)
 If nobody reveals t, Bob refunds his ETH after the expiry,
and after the native refund time Alice sends A and R and gets her ZEC back,
shielded.

The rest of this document gives the full construction, the transaction order,
the recovery cases and what each observer sees.

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
[setup recovery](evidence-index.md) and
[funding consent](evidence-index.md). Older reproduction runners retain the
earlier native-funding-first sequence. Owner keys and first secret exposure stay
in the owner clients; independent-host identity provisioning is still open.

## OTC quote before preparation

The operator path can begin with an Alice-signed exact-amount quote and Bob's
signed acceptance. Each signer pins the accepted quote locally before preparing
C/R; the source uses the same amounts. The quote is included in the final native
terms and both full cross-chain consents. Quotes authorize preparation only;
contract identity, salt, deadlines and the exact funding graph still require
final consent. See [OTC offers](protocol.md). New browser runs use the same
canonical quote and acceptance, exact decimal amounts and full funding consent.
Actual browser settlement and refund remain isolated-chain demonstrations.
The public command integration and funding checklist are in
[public execution](public-execution.md); one funded success-path swap ran on the
public testnets on 2026-10-18 ([record](../evidence/2026-10-18-public-testnet-swap.json)),
and one funded no-reveal refund on 2026-10-20 ([record](../evidence/2026-10-20-public-testnet-refund.json)).

The public preparation path now has a separate [owner setup](public-execution.md)
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
This does not authorize broadcast; explicit senders repeat live checks separately.
It also derives the exact R auxiliary outpoint from the verified bundle and
checks its current index/origin/confirmations without source-wallet key access.
Funding preflight additionally binds the reserved note/nullifier/FVK/anchor to
the private unsigned F, synchronizes the source under its wallet lock and
rechecks the same unspent note and canonical old/current trees. This has real
isolated-history component tests, and the 2026-10-18 funded public run passed
through it. Portable
watch-only recovery now connects compact note/witness acquisition to private
native reproof of the original C/R authorizations. The native proofs have been
exercised with synthetic public-profile blocks and a retained real isolated
refund, not funded public recovery. Live observations are separate from offline
proving. A private outgoing journal now rechecks actual native bytes against the
accepted effects/proofs/signatures and persists each version before it can be
used by the explicit sender; interrupted raw persistence can resume without replacing
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
Private Sepolia lock/claim signing now commits an owner decision before key or
opening access, verifies exact signed bytes and preserves possible claim
exposure across restart. A combined native recovery reader holds the owner lock,
prioritizes native settlement, lets an already authorized Bob claim proceed
without an ETH read, and checks Alice's local exposure history, terminal/empty
ETH state, mature timestamp and exact auxiliary before a refund decision.
These decisions never authorize sending. Private ETH refund and withdrawal now
use the same owner journal, fresh pinned order/credit/reserve checks and a fixed
owner withdrawal address. A transport primitive persists possible delivery
before submission; receipt reconciliation checks exact signed effects, canonical
block membership, agreed runtime and the expected event. Actual isolated ETH
execution/withdrawal and a post-send SIGKILL pass on synthetic native agreements.
Explicit public-profile send commands now connect those journals and readers.
First sends repeat live checks; native transport inherits the caller's locks
and has a short validity, while possible delivery is durable before transport.
F replay keeps the same source/anchor/bytes and requires the original wallet.
ETH actions sign at the agreed gas ceiling; no automatic fee/nonce replacement
is performed. Actual cap-priced isolated ETH transactions and native proof,
crash/lock checks pass. The funded public positive path ran once on 2026-10-18
([record](../evidence/2026-10-18-public-testnet-swap.json)) and the funded public
no-reveal refund ran once on 2026-10-20 ([record](../evidence/2026-10-20-public-testnet-refund.json)). The private source signer is an offline native
primitive behind the live preflight wrapper, not an independent verifier of live
chain observations. Default invocation checks only; sending needs the explicit
testnet broadcast flag. See
[public preflight and its tested scope](public-execution.md).

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
   The coin does not exist before a refund (local and public profiles). Alice's
   source wallet builds and signs a private auxiliary transaction A that spends
   her own F change and creates the 20,000-zatoshi coin. R commits to A's txid
   (v6 txids exclude anchors and proofs), so A can stay unbroadcast. Only Alice's
   participant receives A, after verifying its proof, signature and output; she
   sends A and then R only if she refunds. The source wallet reserves the change
   note until then. A settled swap therefore puts only F and C, both fully
   shielded, on the Zcash chain. Bob's safety does not depend on A: R stays
   time-locked whatever its input. On the public path, A is built with the
   unsigned graph from the reserved note's change, signed by the source signer
   together with F (A first, so a released F always has its refund input), and
   sent by `public_auxiliary_execute.py` only on the no-reveal refund path.
4. Before exposing F to the broadcaster, the local implementation generates
   and verifies both exit circuits against a temporary tree containing the exact
   pending note. Each signer additionally verifies R's shielded spend/binding
   signatures and the auxiliary P2PKH signature, C's dummy authorizations, and
   the presence and consistency of the private data needed to re-prove later.
   C's adaptor pre-signature is verified separately, without revealing t.
   These temporary proofs remain private bundle data and are never broadcast;
   C/R are re-proved after mining.
   A costs 15,000 zatoshi in fees; R returns 15,000 of the 20,000-zatoshi
   coin after its incremental fee.
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
[public-network readiness](public-execution.md). No height-to-seconds conversion
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
conditional consents, as described above. Explicit senders enforce separate
fresh checks; the funded success path ran once on 2026-10-18 and the funded
no-reveal refund once on 2026-10-20. See
the exact preparation thresholds and evidence limits in
[the public testnet runbook](public-execution.md).

- Zcash observers: normal shielded funding/claim metadata, no public principal
  or shielded address. Only a refund exposes the auxiliary transaction A (a
  20,000-zatoshi transparent output from Alice's change) and links it to R,
  which returns 15,000 zatoshi to the same transparent address.
- EVM observers: ETH amount, maker/recipient, T, t after reveal, deadlines,
  terms commitment and timing. ETH-side privacy is not claimed.
- Counterparty: agreed amounts, the peer's one-time receive **address** (never
  its viewing key, since 2026-10-17), and shared-note viewing/proving data. The
  one-time DKG prevents viewing unrelated swaps. Observer by observer:
  [privacy](privacy.md).
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
[signer transport](evidence-index.md) for exact scope and reproduction.

Each participant can export its own accepted bundle into a fresh native recovery
workspace with viewing/proving data and the correct prepared exit, without
exporting spending keys. See [recovery bundles](evidence-index.md). The fixture
recovery still restores the owned EVM checkpoint and uses its shared journal;
native bundle portability does not establish public-network independence.

The newer [owner CLI path](evidence-index.md) validates each owner's ETH address
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
gates are described in [owner-operated recovery](evidence-index.md).
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
Partial setup uses [source decision recovery](evidence-index.md). Peer-directory
moves are journaled before renaming, and surviving process guardians clean the
owned prover/node/signer workers after parent SIGKILL. Actual claim/refund and
setup gates are recorded in [process recovery](evidence-index.md). Arbitrary
instruction-boundary failures and public-network reorg recovery remain unproven.

Controlled Anvil fork tests now remove a previously observed claim receipt,
replay the exact bytes into a different block, then replace it with a different
relayer's canonical claim. Owner settlement observations are append-only per
block/transaction, and the original exposure intent is retained across forks.
The replacement event completes the real native exit. See
[EVM fork recovery](evidence-index.md); this is before withdrawals/native settlement
and is not a public-network confirmation policy.

The native owner gate is also exercised by actual Zebra block invalidation:
one-confirmation or orphaned F prevents first secret exposure and new owner
lock processing. The original branch is then reconsidered before settlement.
See [native reorg tests](evidence-index.md). Separate actual claim/refund exit
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
See [funding anchor selection](evidence-index.md); six blocks is an isolated
fixture parameter, not a public finality guarantee.
If F becomes orphaned but its source anchor/input remain usable, Bob can replay
the same bytes after verifying the exact canonical ETH claim. The actual gate
also refuses restoration when the ETH claim disappears/expires or a competing
ETH refund wins, preserves exposure intent, and restores absent or genuinely
pending F through the normal driver.
See [funding recovery](evidence-index.md). Source re-proving, conflicting source
spends, coordinated recovery when both settlements are absent, a refund winning
beyond the allowed window, and public-network timing/finality remain unproven.
