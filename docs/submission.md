# Zatomic — Cross-chain submission draft

Draft only. No contest submission or announcement has been made. One funded
exchange settled on the public Zcash testnet and Sepolia on 2026-10-18 (success
path); everything else below ran on isolated local chains and is labelled so.

## One sentence

Zatomic lets two people exchange shielded ZEC for ETH, with recovery paths verified
before funding and no custodian choosing where the money goes.

## What we built

Zatomic is a P2P OTC atomic-swap prototype for native Ironwood ZEC and ETH. Alice
sets exact amounts, Bob accepts her signed quote, and both approve the complete
exchange after verifying their prepared claim and refund transactions. ZEC stays
on Zcash and ETH stays on Ethereum; there is no wrapped asset or bridge minting.

The key connection is a RedPallas adaptor signature. Ethereum's immutable escrow
checks a revealed scalar against the same Pallas point used by the prepared
native claim. That scalar lets Bob complete the authorized shielded ZEC payment
without asking Alice for another signature. The EVM claim needs no Zcash
recipient address, viewing key or note opening.

The working demo runs actual Zebra NU7 and Anvil transactions. It shows a complete
exchange, recovery after stopping following the secret reveal, and a no-reveal
refund. In [two-party mode](two-party.md), Alice and Bob each run their own
sandboxed app that holds only their own keys. The only things passing between
them are pinned-TLS signing and a relay that sees two identity manifests and six
sealed envelopes, never the amounts or the funding transaction. Either app can be
killed and restarted mid-trade. Counterparties exchange one-time receive
addresses, never viewing keys ([what each observer sees](privacy.md)). Owner clients retain their own keys and durable recovery data. Separate
operator runs use pinned TLS and OS-enforced private-directory separation on one
host. Custom-amount exchange and refund runs check native confirmations, receiver
decryption, exact ETH withdrawals and repeat recovery without duplicate payment.

## Why Cross-chain

The product exchanges ownership across two native settlement systems. Its useful
property is that the ZEC principal and recipients stay shielded while the owners
hold prepared recovery paths. It is a focused swap, with no bridge committee,
oracle deciding the exchange outcome or custodial exchange account.

**Compared with the existing route.** NEAR Intents can already pay ZEC out to an
Orchard receiver ([LI.FI docs](https://docs.li.fi/introduction/zcash-ecosystem)).
Its Zcash bridge contract funds that payout from a transparent input, so the
amount is public, and checks it by recovering the output with an all-zero
outgoing viewing key
([code](https://github.com/Near-One/btc-bridge/blob/0b02818d47/contracts/satoshi-bridge/src/zcash_utils/orchard_policy.rs#L11-L13)).
That key is public, so anyone can recover the payout's recipient too. Zatomic's
two Zcash transactions have no transparent input or output, and their outputs
are built with no outgoing viewing key, so nobody can recover them that way.
What Zatomic leaves public is under Honest limits: the ETH side, timing, and on
a refund one transparent coin. NEAR's Confidential Intents hide order flow on
NEAR; they are a different layer from the Zcash transactions compared here.

## Demonstration and verification

- Live demo: `make two-party`, then open http://127.0.0.1:8790. The front page
  explains the swap and links its evidence; **Try the live demo** opens both
  owner apps side by side with Autoplay, Refund path, Stop/Restart Bob and New
  trade ([two-party mode](two-party.md))
- [Earlier two-minute captioned video](demo/latch-2min.mp4) — the single-window demo before the rename from Latch; real screen checkpoints, waits omitted
- [Two-minute walkthrough](demo-walkthrough.md#two-minute-presentation)
- [What each observer can see](privacy.md)
- [Evidence by guarantee level](evidence-index.md)
- [Exact reproduction commands](reproduce.md)
- [Protocol and transaction order](protocol.md)
- [Security review and assumptions](security.md) and the
  [second review with its fixed signing-order flaw](review-2026-10-17.md)
- [Repository](https://github.com/yugocabrio/zeceth)

The browser and the CLI both use exact peer-selected amounts. Alice signs the
quote, Bob reviews and signs his acceptance, and funding is a separate approval.
There is no market feed, order book or counterparty discovery service. A local
run takes about two and a half minutes on this machine, most of it proving.
The earlier two-minute presentation is a clearly labeled edit of actual screen
checkpoints.

## Honest limits

One funded exchange settled on the public Zcash testnet and Sepolia on
2026-10-18 ([record](../evidence/2026-10-18-public-testnet-swap.json)): F and C
are fully shielded and the refund auxiliary was never broadcast. Only the success
path ran publicly; refunds and crash recovery were exercised on isolated chains.
A second internal review found and fixed a release-order flaw in the custom adaptor
signing (see the review above). It is not an external audit. Independently
administered hosts have not been demonstrated. The custom adaptor composition is unaudited; the arithmetic
cross-check is not an external audit or a security proof.

The swap requires bounded monitoring, inclusion and reorg assumptions. Arbitrary
outages or source-conflicting deep forks are outside its demonstrated guarantees.
ETH addresses, amounts, witness and timing are public. A settled swap is fully
shielded on Zcash; only a refund creates and spends a transparent auxiliary
coin. The ZEC exchange principal remains shielded either way. This is not a claim that the entire exchange is anonymous or mainnet
ready.

## Before submitting

Settlement code `9b978e3` passed [fresh-checkout reproduction](../evidence/2026-10-15-clean-reproduction.json).
The [two-minute presentation file](demo/latch-2min.mp4) and its reviewed source
images are included. It is a captioned edit of actual screen checkpoints, not a
continuous recording. The public testnet settlement is recorded above with its
six transactions. Submission itself still requires the user's instruction.
