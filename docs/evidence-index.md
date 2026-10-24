# Zatomic evidence: start here

**The strongest results are both outcomes on the public Zcash testnet and
Sepolia, twice: a funded exchange that settled and a funded no-reveal trade that
refunded both sides, first with the original escrow (2026-10-18 and 10-20) and
again with the shipped V2 escrow (2026-10-21), plus real isolated-chain
exchanges, refunds and crash recoveries with separately held participant state
on one host.** Independently administered hosts have not been demonstrated.

These are development-run records committed with the implementation. They are
not an auditor's attestation or a self-contained blockchain proof. Local txids
will not resolve in a public block explorer. Reproduction requires fresh private
test wallets; the original keys, notes and journals are deliberately excluded.

**Adaptor signing review, 2026-10-17:**
[record](../evidence/2026-10-17-second-review.json). It fixed an adaptor
share-release flaw (Alice now verifies Bob's share first) and redesigned the
browser. It re-ran success, stop-after-reveal and stop-before-reveal runs on the
rebuilt signer; every replay sent zero new transactions. Same host, isolated
chains; not an external audit.

**Two-party mode, 2026-10-17:** separate sandboxed apps for Alice and Bob
settled a trade (with Bob's app killed and restarted after the reveal) and a
no-reveal refund. [Record](../evidence/2026-10-17-two-party.json),
[how to run it](two-party.md). Same host; not separate administration.

**Sealed relay, 2026-10-17:** the two-party relay now sees only identity
manifests and sealed envelopes. Before, it could read the ZEC amount, funding
txid and joint note commitment. A fresh exchange ran over the sealed relay.
[Record](../evidence/2026-10-17-relay-sealing.json).

**Fully shielded settlement, 2026-10-17:** a settled swap now puts only F and C
on the Zcash chain. The refund's transparent coin comes from Alice's private
auxiliary transaction, sent only if she refunds. Two-party success and refund,
a browser refund recovery and a timelock check ran on chain. The public path
was ported too (synthetic-input checks; funded refund not yet exercised).
[Record](../evidence/2026-10-17-deferred-auxiliary.json).

**Public testnet runs on the V2 escrow, 2026-10-21:** the shipped
PointEscrowV2 deployed to Sepolia (7,100,182 gas with its comb table) and
settled a funded swap under the short timing profile: lock 139,146, claim
112,528, withdrawal 43,562 gas. F and C are fully shielded. A no-reveal run
refunded both sides: Bob's refund (32,981 gas) and withdrawal, then Alice's A
and R; her wallet holds the returned 0.001 ZEC. Three tool defects found and
fixed on the way (claim resend window, stale action directory, native tip
race). [Record](../evidence/2026-10-21-public-testnet-v2.json).

**Sepolia gas, 2026-10-18:** current Sepolia rules need far more gas for new
state; the planned public deployment and lock would have run out of gas. Limits
were re-measured by simulation and raised (fee profile v2).
[Record](../evidence/2026-10-18-sepolia-gas.json).

**Hosted judge demo, 2026-10-18:** https://162-55-186-88.sslip.io on a
rented x86_64 server. Each owner app runs as its own Linux user, and the network
proves the denial at every trade. The three scenarios ran from a browser over
HTTPS (1:46, 1:55, 1:59). One operator runs all roles.
[Record](../evidence/2026-10-18-hosted-demo.json).

**Judge stage on real local chains, 2026-10-18:** the three one-click
scenarios ran from the browser, each on a fresh trade: swap (3:32, 3:42), Bob's
app killed and restarted after the claim (3:47), both refund (3:37). Two defects
were found and fixed (blank app frames after New trade; quotes too large for one
regtest coinbase after the reward halved).
[Record](../evidence/2026-10-18-stage-scenarios.json).

**Public testnet swap, 2026-10-18:** the first funded exchange on the public
Zcash testnet and Sepolia settled and passed the final verify. F and C are fully
shielded; the refund auxiliary was never broadcast. One host.
[Record](../evidence/2026-10-18-public-testnet-swap.json).

**Public testnet refund, 2026-10-20:** a second funded trade where nobody
revealed t. After the ETH deadline Bob refunded and withdrew exactly 0.001 ETH;
after the Zcash refund height Alice sent A (the 20,000-zatoshi coin) and her
time-locked R, and her own wallet decrypted the returned 0.001 ZEC. Same pinned
escrow, one host. [Record](../evidence/2026-10-20-public-testnet-refund.json).

Latest additions after the original local release:
[actual browser OTC success/refund](../evidence/2026-10-15-browser-otc.json),
[isolated pinned deployment](../evidence/2026-10-15-public-deployment-integration.json),
[read-only public readiness and revised funding](../evidence/2026-10-15-public-integration-readiness.json).
The [execution checklist](public-execution.md) supersedes the earlier 0.431 ETH
budget. These 2026-10-15 additions included no funded public swap; that came on
2026-10-18 (above).

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
| Public-profile ETH delivery primitives on an isolated EVM | Real signed lock/claim/refund/withdrawal, post-submit SIGKILL and exact receipt recovery; both recipients' balance changes equal credit minus gas. | [ETH delivery](../evidence/2026-10-15-public-eth-delivery.json) | Public deployment/settlement or a complete sender. Native inputs are synthetic, runtime is installed locally, finality labels are modeled. |
| Public settlement, success path | **Executed 2026-10-18:** deploy, F, lock, claim, C, withdraw on Zcash testnet and Sepolia; final verify passed; F and C fully shielded; refund auxiliary never broadcast. | [Public swap](../evidence/2026-10-18-public-testnet-swap.json) | Independent hosts; local consensus verification (trusted RPC providers). |
| Public no-reveal refund | **Executed 2026-10-20:** F, lock, Bob's refund and withdrawal after the ETH deadline, Alice's A and time-locked R after the Zcash refund height; Alice's wallet decrypted her 0.001 ZEC, Bob's withdrawal verified. | [Public refund](../evidence/2026-10-20-public-testnet-refund.json) | Independent hosts; local consensus verification (trusted RPC providers). |
| Independent-host operation | **Not executed.** Both owners ran on one host. | [Hosting](hosting.md) | Do not present any row as separately administered. |

The latest [explicit sender candidate checks](../evidence/2026-10-15-public-execution.json)
add actual cap-priced isolated ETH settlement, retained native F/C/R validation,
crash/lock retention and modeled native transport/observation boundaries. These
2026-10-15 rows are not the funded public run; that is the 2026-10-18 record.

The [fresh browser release demonstration](../evidence/2026-10-15-release-demo.json)
reran all three scenarios on `c6e03b0` and checked zero-new-payment replay.
The [public launch plan](../evidence/2026-10-15-public-launch-plan.json) records
read-only endpoint checks and an unsigned, unfunded execution budget.

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

The [clean-checkout release check](../evidence/2026-10-15-clean-reproduction.json)
rebuilt `9b978e3`, passed make verify and executed fresh exchange/refund/replay
using new private state and its own node. The original node remained unchanged.
It is same-host reproducibility, not independent-host administration.

## Reproduce, in order

1. Follow [prerequisites and local reproduction](reproduce.md). `make doctor`
   only checks prerequisites; it does not execute a swap.
2. `make verify` checks code/contract/model boundaries. It is not settlement.
3. Run `make demo` or `make two-party` for a fresh actual exchange and refund;
   preserve each output directory.

Keep `.local`, wallets, private logs, PCZTs, presignatures and note witnesses
out of the recording, repository and any evidence export.
