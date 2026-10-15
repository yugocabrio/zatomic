# Security review and deployment limits

Review date: 2026-10-15. Baseline: `3543669` (owner-operated native settlement).
This is a focused internal implementation review, with a second
arithmetic implementation. It is **not an independent auditor's assessment**,
formal proof, or authorization to use real funds. No funds-theft defect was
identified by this review within the explicitly controlled local-chain model.
The public-network and independent-operator gates below remain open.

## What is enforced, and by whom

| Lifecycle invariant | Enforcement and reviewed code | Remaining assumption |
|---|---|---|
| Both owners retain usable exits before source authorization | `participants::validate`, `recovery_bundle::accept`, `funding_consent::verify`, source release guard. Owners verify actual PCZT effects, proofs, pre-signature and auxiliary signature, then sign the bundle/offer digests. | Owner storage and provisioned identity pins remain trustworthy. The source wallet is a privileged signing boundary. |
| Neither recipient, payout, F, deadline nor contract changes after consent | Native spend signatures bind effects; immutable accepted policy binds companion exit terms; both secp256k1 consents bind full agreement and bundle receipts. Source binds exact unsigned F digest. | Current same-host provisioning must become authenticated independent provisioning. Low-level offline signers are not network authorization APIs. |
| A single signer cannot complete arbitrary shared-note spends | 2-of-2 DKG, exact signer-set check, each nonce commitment and signature share checked, aggregate pre-signature and final native signature verified. | Custom adaptor composition is unaudited; algebraic correctness is not a malicious-concurrency proof. |
| Native claim needs the same scalar as ETH settlement | EVM verifies `tG=T` using the RedPallas SpendAuth base. Native adaptation adds `t` to the prepared response scalar. Both owners bind T and transaction. | Alice must keep a fresh t private until authorized exposure. |
| Front-running a valid ETH claim cannot redirect ETH | Contract fixes recipient; permissionless claim credits that recipient, withdrawal is separate. No external call occurs during claim. | Correct contract code/domain and live order observation. |
| Refund cannot win before its native deadline | Fully signed auxiliary P2PKH input has nonfinal sequence, so consensus enforces native lock time. Both exits spend the same native nullifier. | Auxiliary UTXO remains unspent and refund fees suffice. Current implementation is height-based regtest policy. |
| An absent ETH receipt is not treated as unrevealed secret | Alice records signed intent before send; own possible exposure forbids no-reveal fallback. Live canonical event is checked rather than old completion JSON. | Durable own history is not lost/rolled back; observers react within bounded time. |
| F can be replayed after a limited reorg | Only already-published F bytes are relayed after canonical ETH claim, with no new source signature. Older anchors reduce shallow-fork exposure. | Source inputs and at least one published source anchor survive. This is not arbitrary reorg recovery. |
| Repeated settlement does not create another payment | Reconcile actual canonical/mempool txids and fixed escrow order; re-proof retains native effects/txid. | Correct live nodes, intact journals and bounded network availability. |

## Custom signature calculation

For signer i, let `x_i` be its Shamir share, `λ_i` its interpolation weight,
`d_i,e_i` fresh one-use nonces, `ρ_i` its binding factor, and `α` the native
randomizer. The implementation computes:

```
X'    = X + αG
R     = Σ(D_i + ρ_i E_i)
Rhat  = R + T
c     = H_RedPallas(Rhat || X' || sighash)
zhat_i = d_i + ρ_i e_i + λ_i c (x_i + α)
shat  = Σ zhat_i
s     = shat + t
```

Because `Σ λ_i = 1`, adding α to each share gives the desired randomized public
key, rather than adding it twice. Each share is verified against
`D_i + ρ_i E_i + λ_i c (X_i + αG)`. The pre-signature equation is
`shat G = Rhat - T + cX'`; the native final signature verifies
`sG = Rhat + cX'`. Extraction also requires the identical nonce Rhat and checks
`(s-shat)G=T`.

The binding hash covers the randomized key, message hash, ordered nonce
commitments, scheme tag, fresh attempt ID, T and α. The attempt ID is **not**
itself a canonical agreement hash; native participants separately validate and
persist the full transaction policy. This distinction was corrected in the
library comment during review. The transaction sighash and later owner consent
perform their respective cryptographic bindings.

`participants.rs` durably reserves an attempt before returning nonce commitments,
consumes its live nonce before answering a signing request, and never serializes
nonces. A fresh DKG wallet/witness is used per exchange. Reusing T after it has
become public would let Bob complete another claim early; do not reuse swap
wallets or witnesses as a convenience. Refunding uses a deliberately public
witness 1 for its separately time-locked transaction, not for the claim.

Primary references checked: [RFC 9591](https://www.rfc-editor.org/rfc/rfc9591.html),
[ZIP 312](https://zips.z.cash/zip-0312),
[ZIP 374](https://zips.z.cash/zip-0374). These specify the base construction and
transaction format; they do not prove this adaptor extension secure.

## Independent arithmetic cross-check

`audit_transcript` generates three disposable transcripts through the actual DKG
and custom signer, with randomizers 0, random and q−1; current `reddsa 0.6.1`
verifies each final signature. `verify_crypto_transcript.py` independently uses
Python integer affine arithmetic, Tonelli–Shanks decoding and hashlib BLAKE2b:
it imports neither pasta_curves nor FROST nor the Solidity implementation.
It reconstructs binding factors, individual shares, interpolated public key,
aggregate/adapted signatures and witness extraction, then rejects changed
context, nonce, participant and response fields. It also independently computes
the 15 existing Solidity scalar-multiplication vectors.

```
cargo run --locked -j 2 -p shielded-swap-crypto --example audit_transcript -- .local/audit-transcript.json
python3 scripts/verify_crypto_transcript.py .local/audit-transcript.json
cargo clippy --workspace --all-targets --locked -j 2 -- -D warnings
cargo test --workspace --locked -j 2
forge test -vv
```

Use a new private transcript path. The output file is 0600 and must stay ignored;
no pre-signatures or witness values are committed. This checker is variable-time,
public-input review code, **never a signer**. Matching equations/tests support
implementation consistency; they do not establish unforgeability, nonce-side-
channel resistance or arbitrary concurrent-protocol security.

The Solidity review also checked canonical scalar and coordinate bounds,
nonzero witnesses, infinity handling, group order, Jacobian doubling/addition,
fixed recipients, exact refund boundary and checks-effects-interactions in
withdrawal. The existing 22 contract tests pass. Pallas is the prime-order
cofactor-one group here; arbitrary noncurve points are rejected. The contract
does not verify any Zcash transaction, header or finality proof.

## Failures that remain deployment blockers

1. **Public timing/finality.** Six remaining native blocks and 60 ETH seconds
   are controlled-fixture cutoffs, not public safety bounds. Native height and
   Ethereum timestamps cannot be equated using average block intervals. A public
   profile must bind native consensus lock semantics, early-block/clock bounds,
   observation, inclusion, confirmations/reorg risk and upgrades. Until that
   exists, the clients deliberately accept only their isolated domains.
2. **Source conflict/deeper fork.** After ETH reveal, a fork that removes F can
   allow a conflicting source spend or eliminate every usable anchor. Replaying
   F cannot fix that. A six-block-old anchor is a mitigation, not finality or a
   source-wallet recovery right. ETH can remain paid while native recovery is
   unavailable outside the stated native-finality assumption.
3. **Claim disappearance after exposure.** A secret visible in pending,
   reverted or orphaned ETH calldata remains usable on Zcash. Alice must allow
   enough time/fees for a valid fixed-recipient ETH claim to be included and
   survive the chosen finality bound. Refusing a refund afterward avoids an
   unsafe inference; it does not recover ETH automatically after expiry.
4. **Operator and source-wallet isolation.** Same-host identity generation,
   private paths and source-wallet preparation are still fixture conveniences.
   Owner-only exits remove a settlement dependency; they do not complete
   independent provisioning or authenticated remote offers.
5. **Privacy and economics.** Coordinator/participants learn the agreed note
   and transaction data. ETH metadata and witness are public, as is the refund
   auxiliary input. Alice retains a decision window to execute/abort a fixed
   exchange, an economic option; the protocol does not guarantee price fairness,
   execution, censorship resistance or a costless abort for the other party.

The next engineering milestone is independent provisioning and message delivery,
followed by public wallet observation/timing integration. An external review of
the custom signer and EVM arithmetic remains desirable and unperformed. New
fault tests should target a changed guarantee, not grow this document's count.

Subsequent P1 implementation: [separate operators](independent-operators.md)
now generate their own identities, accept authenticated manifest pins and run
through the real protocol with OS-denied cross-operator private roots. This
closes the shared-private-path dependency for the tested workflow. It remains
one administrator/host, uses explicitly trusted RPC, and keeps the native
preparer inside Alice's privileged source-wallet boundary. It does not resolve
the public timing or deeper source-conflict limitations above.

Subsequent OTC amount extension: Alice signs the canonical quote under
`Latch OTC offer v1`, and Bob signs its digest under `Latch OTC acceptance v1`.
Both operators compare the quoted owners with their authenticated local pins.
Native signers require the exact locally accepted quote before producing a
nonce commitment. Native input/output checks, decrypted payouts, recovery-bundle
metadata and source/ETH amount checks derive from that verified quote. Final
funding consent still covers the complete graph, contract, amounts and deadlines.
Neither quote signature alone grants spend authority. Decimal strings become
integers without rounding; the local profile has explicit value/fee limits.
Quote signatures are not market-price guarantees or proof of funding. Each
operator directory handles one trade; quotes have no separate wall-clock expiry.

## Gas-starved first witness disclosure — fixed

The subsequent public-readiness review found that the owner checked a gas-price
cap but not its available ETH balance before signing/sending the first claim.
An insufficient-funds rejection can still disclose the claim witness to the RPC
recipient. A failed Ethereum payment is therefore not a safe secret preflight.
The old path was limited to owned test nodes; this would be a funds-loss risk if
carried into a public or counterparty-observed RPC environment.

`fee_policy.py` now checks pending balance, latest/pending nonce equality, current
base fee and the accepted gas-price cap before the first claim witness is read.
Its RPC methods contain only public account/fee/block queries; neither
`eth_estimateGas` nor `eth_call` receives secret claim calldata. Both owners'
reserves are checked again before native source release. New owner agreements
explicitly include the gas policy in their signed digest; historical agreements
keep their original digest and the original fixed limits.

Actual isolated operator run rejected Alice and Bob gas starvation before F
authorization, then rejected a zero-balance Alice after Bob had locked ETH,
without creating a claim intent or settling the order. Restoring her synthetic
balance allowed both assets to settle; process restart/repeat sent nothing.
Evidence: `evidence/2026-10-15-fee-reserves.json`. This demonstrates refusal and
successful recovery, not a live theft experiment or public-network execution.

The observations do not reserve balances or nonces against another wallet using
the same account. Dedicated accounts, trustworthy fresh RPC, bounded inclusion
and adequate gas remain assumptions. Current legacy-price intents cannot be
arbitrarily repriced after exposure. The fixed gas limits were exercised against
the pinned escrow; this is not remote estimation or proof of all future gas
regimes. Never infer that a rejected/already-published claim became private.
The earlier fixed-profile behavior is retained when no quote is configured.
