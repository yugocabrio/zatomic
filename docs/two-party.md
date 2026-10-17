# Two-party mode: each owner runs their own app

```sh
make two-party
```

This opens three local pages:

| Page | What it is |
|---|---|
| **Alice** · http://127.0.0.1:8791 | Alice's app. It holds her participant keys, her secret `t`, and her own source wallet operator. |
| **Bob** · http://127.0.0.1:8792 | Bob's app. It holds his participant keys only. |
| **Network** · http://127.0.0.1:8790 | A stand-in for the public chains, plus a relay for public messages. It holds no participant key. |

Each app runs under its own macOS `sandbox-exec` policy that denies reads and
writes of the other owner's directories. At launch, the network page *proves*
this: under each app's exact policy, reading the other owner's identity file
fails with a permission error. Native preparation (DKG and adaptor
pre-signatures) runs over the existing certificate-pinned TLS signer channel.
Everything else Alice and Bob exchange goes through the relay, and the network
page lists every message. That is eight public messages per trade: identities,
the signed quote, the acceptance, "signer online", the full terms, Bob's
consent and the ETH order ID. No key, receive address, viewing key, witness or
note data crosses the relay.

![The network page: chains, sandbox check and every relayed message](images/two-party-network.png)

## A trade, step by step

1. **Trust.** Each app shows the other's identity fingerprint. Compare them over
   a channel you already trust, then click *Fingerprints match*.
2. **Quote.** Alice enters exact amounts and signs. Bob's app verifies her
   signature and shows the amounts, the price and the signature status. Bob
   accepts, and his signer goes online.
3. **Prepare.** Alice funds her local source wallet (a regtest faucet). She then
   runs DKG and pre-signs both exits with Bob's signer. Each owner verifies and
   saves its own exit.
4. **Full terms.** Alice posts the agreement: escrow, amounts, expiry, refund
   height and funding transaction. Bob's client checks it and signs. Alice signs;
   her source wallet releases the ZEC funding only with both signatures.
5. **Settle.** Bob locks ETH. Alice claims it, which publishes `t`. Bob's app
   sees the claim and completes his shielded ZEC claim. Alice withdraws.

![Bob's app after the trade: his ZEC claim decrypted by his own wallet](images/two-party-bob.png)

## Recovery that you can show

- **Crash after the reveal.** After Alice claims, click *Kill app (SIGKILL)* for
  Bob on the network page, then *Start*. Bob's app rebuilds its state from its
  own files and the chains, and offers *Claim my ZEC* again. Alice can withdraw
  meanwhile; she never needs Bob online.
- **No reveal.** Let Bob lock and Alice not claim. The network page's *Advance
  ETH time 61 min* stands in for waiting. Bob refunds and withdraws. *Mine 24
  Zcash blocks* passes the native refund height, and Alice's prepared refund
  returns her ZEC.

![Alice's app after a no-reveal refund](images/two-party-alice-refund.png)

## What this does and does not show

It shows that the protocol runs between two separately held sets of keys and
journals. It also shows that only public messages pass between the owners, and
that either side can stop and resume without the other's help.

It does **not** show separate machines or administrators: everything runs on one
host and one OS account. The network is a local stand-in: it mines regtest
blocks when transactions are pending and offers labelled controls for time. Each
workspace holds one trade, so `make two-party` starts a fresh one. Recorded
results: [evidence](../evidence/2026-10-17-two-party.json).
