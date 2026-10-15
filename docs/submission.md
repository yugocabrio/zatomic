# Latch — Cross-chain submission draft

Draft only. No contest submission, public deployment or announcement has been
made. The claims below describe the working isolated-chain release candidate;
they must not be relabeled as a public-testnet demonstration.

## One sentence

Latch lets two people exchange shielded ZEC for ETH, with recovery paths verified
before funding and no custodian choosing where the money goes.

## What we built

Latch is a P2P OTC atomic-swap prototype for native Ironwood ZEC and ETH. Alice
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
refund. Owner clients retain their own keys and durable recovery data. Separate
operator runs use pinned TLS and OS-enforced private-directory separation on one
host. Custom-amount exchange and refund runs check native confirmations, receiver
decryption, exact ETH withdrawals and repeat recovery without duplicate payment.

## Why Cross-chain

The product exchanges ownership across two native settlement systems. Its useful
property is that the ZEC principal and recipients stay shielded while the owners
hold prepared recovery paths. It is a focused swap, with no bridge committee,
oracle deciding the exchange outcome or custodial exchange account.

## Demonstration and verification

- [Two-minute walkthrough](demo-walkthrough.md#two-minute-presentation)
- [Evidence by guarantee level](evidence-index.md)
- [Exact reproduction commands](reproduce.md)
- [Protocol and transaction order](protocol.md)
- [Security review and assumptions](security.md)
- [Repository](https://github.com/yugocabrio/zeceth)

The browser uses fixed demonstration amounts; the CLI supports signed
peer-selected amounts. There is no market feed, order book or counterparty
discovery service. Full setup/proving can take minutes: a two-minute presentation
uses a clearly labeled recording or an already prepared run.

## Honest limits

All executed swaps use isolated chains. Public-testnet wallet/observation and
recovery preparation and explicit sender entry points are implemented, but the
complete positive path has not run with funded public inputs. Independently administered hosts have not
been demonstrated. The custom adaptor composition is unaudited; the arithmetic
cross-check is not an external audit or a security proof.

The swap requires bounded monitoring, inclusion and reorg assumptions. Arbitrary
outages or source-conflicting deep forks are outside its demonstrated guarantees.
ETH addresses, amounts, witness and timing are public. Native refund additionally
uses a public transparent auxiliary coin; the ZEC exchange principal remains
shielded. This is not a claim that the entire exchange is anonymous or mainnet
ready.

## Before submitting

Confirm the final release commit, clean-checkout reproduction result and actual
recording link. Keep any public-testnet result separate and add it only after
authorized execution with verifiable transaction evidence. Submission itself
requires the user's instruction.
