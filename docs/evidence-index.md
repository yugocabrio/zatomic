# Latch evidence: start here

**The strongest completed result is a real isolated-chain OTC exchange and
refund, with separately held participant state on one host.** Public-network
settlement and independently administered hosts have not been demonstrated.

These are development-run records committed with the implementation. They are
not an auditor's attestation or a self-contained blockchain proof. Local txids
will not resolve in a public block explorer. Reproduction requires fresh private
test wallets; the original keys, notes and journals are deliberately excluded.

| Evidence level | What actually ran | Primary record | What it does not establish |
|---|---|---|---|
| Arithmetic / property checks | Separate Python affine arithmetic reconstructs the custom adaptor equations and checks Solidity vectors; a bounded timing model rejects unsafe configurations. | [Arithmetic review](../evidence/2026-10-15-security-review.json), [model / primitive checks](../evidence/2026-10-15-crypto-evm-gate.json) | External audit, cryptographic security proof, public timing bounds. |
| Native proof and signature | Conditional RedPallas authorization completes a real native proof with a later anchor; the recipient decrypts a synthetic note. | [Native/EVM compatibility](../evidence/2026-10-15-native-evm-gate.json) | A mined or spendable public note; native node acceptance. |
| Node acceptance and settlement | A signed custom quote settles 0.02345678 ZEC for 0.037000000000000001 ETH. A separate no-reveal trade refunds both sides. Native node confirmations, recipient decryption and ETH withdrawal are checked. | [OTC exchange and refund](../evidence/2026-10-15-otc-offers.json) | Public finality, market pricing, production safety. All amounts are disposable fixtures. |
| Participant isolation and restart | Owner-generated keys, pinned TLS and accepted recovery material; peer private roots are OS-denied. The remaining owner completes its native exit. Repeated recovery sends no second payment. | [Operator isolation](../evidence/2026-10-15-independent-operators.json), [browser recovery](../evidence/2026-10-15-consent-browser.json) | Independent machines/administrators, hardened whole-host sandbox, untrusted source-wallet preparer. |
| Public read-only interoperability | Public Ironwood blocks and a transaction were read and checked with local decoding; wallet sync used an unfunded wallet. | [Wallet sync](../evidence/2026-10-15-public-wallet-sync.json), [transaction observation](../evidence/2026-10-15-public-transaction.json) | A funded public swap or trustless RPC observations. |
| Recovery plumbing for the public profile | A real isolated pending ETH claim feeds actual native opening acceptance and a synthetic-profile claim reproof. Bounded monitoring survives SIGKILL and explicit fork/error transcripts. | [Opening capture](../evidence/2026-10-15-public-opening.json), [monitor](../evidence/2026-10-15-public-opening-monitor.json) | Funded public integration, complete mempool coverage, guaranteed observation latency or a sender. |
| Private source authorization for the public profile | Actual owner consents and a real native F signature; release-before-raw SIGKILL, exact-byte restart and inherited source-lock retention. | [Source release](../evidence/2026-10-15-public-source-release.json) | Funded public inputs, positive live preflight, node acceptance or a broadcast. Inputs are explicitly synthetic. |
| Public-profile ETH preparation and recovery decisions | Actual Sepolia-domain lock/claim signatures survive decision-before-signing interruption; native recovery policy retains exposure and checks refund prerequisites. | [ETH journal](../evidence/2026-10-15-public-eth-outgoing.json), [recovery decision](../evidence/2026-10-15-public-recovery-decision.json) | Public inclusion/withdrawal, funded live integration or permission to send. Reserves and chain states are explicit transcripts. |
| Public settlement / independent-host operation | **Not executed.** | [Remaining gates](public-testnet.md#gates-before-a-funded-public-demonstration) | Do not present any earlier row as this result. |

## Check the headline local result

The [OTC record](../evidence/2026-10-15-otc-offers.json), committed in `d1b9600`,
contains the exact amounts and local transaction identifiers for both paths.
Its successful trade received 2,345,678 zatoshi and 37,000,000,000,000,001 wei;
its separate refund received 7,654,321 zatoshi and 12,345,678,901,234,567 wei.
Both native exits were observed with two controlled confirmations. Native/EVM
recovery replay reported zero new transactions. These are recorded execution
results from that milestone, not a claim that every later commit reran them.

The [operator record](../evidence/2026-10-15-independent-operators.json) was
committed in `920f01b`; the [arithmetic review](../evidence/2026-10-15-security-review.json)
in `89d58f9`. Each record identifies its own commands and limitations. The public
opening monitor was committed in `0393076`. Use Git history to inspect the code
alongside its evidence; a JSON `true` field alone is not an independent check.

## Reproduce, in order

1. Follow [prerequisites and local reproduction](reproduce.md). `make doctor`
   only checks prerequisites; it does not execute a swap.
2. `make verify` checks code/contract/model boundaries. It is not settlement.
3. Follow the [OTC commands](otc-offers.md) or [operator gate](independent-operators.md#executed-isolation-gate)
   for a fresh actual exchange and refund; preserve each output directory.
4. Use the [two-minute presentation](demo-walkthrough.md#two-minute-presentation)
   to show the result and one interruption. Mark all displayed runs as local.

Keep `.local`, wallets, private logs, PCZTs, presignatures and note witnesses
out of the recording, repository and any evidence export.
