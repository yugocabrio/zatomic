# What each observer can see

Zatomic keeps the ZEC principal, the Zcash recipients and the Zcash amounts
shielded. Ethereum is a public chain, so the ETH leg is public. This page states
what each party or observer can and cannot learn. It is meant to be checked
against the code, not taken on trust.

## Summary

| Observer | Learns | Does not learn |
|---|---|---|
| **Zcash chain observer** | That shielded transactions occurred, their fee and timing. A settled swap has no transparent component. On the refund path only: Alice's auxiliary transaction A (one 20,000-zatoshi transparent output) and the refund R, which spends that coin and returns 15,000 zatoshi (the coin less a 5,000-zatoshi fee) to the same transparent address. | Amounts, senders, recipients, memos. Which note F created. That claim C spends that note. |
| **Ethereum chain observer** | Bob's and Alice's ETH addresses, the ETH amount, the expiry, the point `T`, a hash of the agreed terms, the revealed `t`, and who relayed the claim. | Any Zcash address, viewing key, note or ZEC amount. The terms appear only as a hash commitment. |
| **Your counterparty** | The agreed amounts, both ETH addresses, your **one-time** Zcash receive address, the funding txid, the shared one-time joint note, and the refund auxiliary outpoint (a txid that reaches the chain only if Alice refunds). | Your viewing keys, your source wallet, or where your received ZEC goes next. |
| **Relay** (two-party mode) | Each owner's identity: public keys and ETH address. For every other message: sender, recipient, size and time. | The quote, amounts, terms, funding txid, note commitment, consents or order ID. These are sealed to the recipient. |
| **RPC / light-wallet provider** | Which transactions and orders your client asks about, plus network metadata (IP address, timing). | Your notes: compact blocks are trial-decrypted locally. |
| **The browser page** | Public stage records only: txids, confirmations, amounts. | Keys, notes, PCZTs, witnesses or journals. The server only reads named public files; `check_demo_boundary.py` tests this. |

## Details and limits

**One scalar, unlinkable to third parties.** Bob's Zcash claim signature is
`(R̂, s)` with `s = ŝ + t`. Someone who sees `t` on Ethereum and every Zcash
signature still can't tell which signature it completed. That would require the
pre-signature `ŝ`, which only Alice and Bob hold.

**Counterparties exchange receive addresses, not viewing keys (fixed
2026-10-17).** Earlier versions exchanged each receiver's full viewing key, which
would let the counterparty detect and decrypt the payout's later spends. Now
peers and coordinators see only the one-time address. Each owner verifies that
its own payout decrypts, using its own key. A funded public graph requires the
address-only setup format.

**Relay messages are sealed (fixed 2026-10-17).** In two-party mode the relay
used to carry the quote, the full terms and the consents in the clear. Its
operator could read the exact ZEC amount, the funding txid and the joint note
commitment. Now only the identity manifests are in the clear; everything else is
sealed to the recipient's pinned relay key ([details](two-party.md#sealed-relay-messages)).
`scripts/check_relay_privacy.py` checks a finished run.

**Transactions are recognisable.** Funding F, claim C and refund R use
`expiry_height = 0`. C and R are signed before funding and must stay valid until
used; the signature hash covers the expiry. F's txid is fixed when the exits
are prepared. Ordinary wallets set a short expiry, so these transactions stand
out. Combined with the timing of Ethereum escrow events, an observer can
plausibly pair the Zcash legs with an ETH order. The public ETH amount then
suggests the approximate ZEC amount via the market price. Recipients and exact
ZEC amounts stay hidden. The Ironwood pool is still small, which makes timing
correlation easier.

**Only a refund touches the transparent pool (local profiles, 2026-10-17).**
Zcash enforces `nLockTime` only when a transaction has a non-final transparent
input. A shielded-only refund would be valid immediately, so Alice could race
Bob's claim. R therefore spends a 20,000-zatoshi transparent coin with a
non-final sequence. That coin used to be created and mined before the swap, so
even a settled swap left a transparent output on chain. Now Alice's source
wallet signs a private auxiliary transaction A at setup: it spends her own F
change and creates the coin. A is never sent unless Alice refunds, and only her
own participant holds it. A settled swap puts only F and C on chain, both fully
shielded. On a refund, A shows 20,000 zatoshi leaving the shielded pool to a
transparent address, and R spends it and returns the remaining 15,000 zatoshi to
that same address, where it stays until Alice sweeps it. Locally that address is
fresh per swap;
on the public testnet it is the source wallet's dedicated auxiliary address,
which the provider first sees only on a refund. The public path does the same
since 2026-10-17: its source reservation holds only the shielded note, and the
source signer signs A together with F.

**ETH side.** Addresses, the amount and timing are public by design. Use fresh
ETH addresses per trade if those must not link to other activity.

**Not covered.** Network-level privacy (use Tor or a trusted node), the free
option Alice holds between Bob's lock and her reveal, and anything an owner
reveals out of band.
