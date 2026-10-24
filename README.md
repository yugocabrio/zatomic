<img src="docs/images/zatomic-mark.svg" width="72" height="72" alt="Zatomic mark: a Z inside an orbit with two nodes">

# Zatomic

**Atomic swaps of shielded ZEC for ETH, with both exits prepared before funding.**

![Zatomic stage after a settled swap: Alice’s and Bob’s apps, and between them only what an outside observer saw](docs/images/stage-swap.png)

Zatomic swaps native shielded ZEC for ETH between two parties who have already
agreed a trade. There is no bridge, no wrapped ZEC and no custodian or solver.

- A 2-of-2 FROST key controls the ZEC in a shielded Ironwood note.
- Before Alice funds that note, Bob holds his claim C pre-signed with a RedPallas
  adaptor signature, and Alice holds her refund R fully signed and time-locked.
- Bob locks ETH in an escrow bound to a Pallas point T. Alice claims it with t;
  the escrow checks t·G = T on Pallas, and the same t completes Bob's Zcash
  signature for C.
- If nobody reveals t, Bob takes his ETH back after the deadline, and Zcash's own
  lock time lets R return Alice's ZEC.

**Live demo:** https://162-55-186-88.sslip.io runs separate apps for Alice and
Bob on private test chains: a swap, a crash after the claim, or a refund.

## Public testnet runs

Zcash public testnet (Ironwood) and Sepolia, 0.001 test ZEC for 0.001 Sepolia ETH:

| Date | Escrow | Outcome | Record |
|---|---|---|---|
| 2026-10-21 | V2 (shipped) | Settled; Zcash saw two fully shielded transactions | [record](evidence/2026-10-21-public-testnet-v2.json) |
| 2026-10-21 | V2 (shipped) | Nobody revealed t; both sides refunded | same record |
| 2026-10-20 | V1 | Nobody revealed t; both sides refunded | [record](evidence/2026-10-20-public-testnet-refund.json) |
| 2026-10-18 | V1 | Settled | [record](evidence/2026-10-18-public-testnet-swap.json) |

On Sepolia the V2 escrow used 295,236 gas for a settled swap (lock, claim,
withdraw) and 215,713 for a refund, against 1,420,389 and 974,494 for V1. Both
owners ran on one host, and chain data came from public RPC providers.

## Run it

Prerequisites: Rust 1.93, Python 3.11+, Node/npm, Foundry 1.3.1 and Docker. The
pinned node bootstrap supports Apple Silicon and Linux ARM64.

```sh
make doctor
make demo        # one browser app at http://127.0.0.1:8787
make two-party   # separate apps for Alice and Bob; stage at http://127.0.0.1:8790/stage
make verify      # Rust checks, contract tests and the timing model
```

More: [two-party mode](docs/two-party.md), [reproduction](docs/reproduce.md),
[public testnet runbook](docs/public-execution.md), [hosting](docs/hosting.md).

## Read more

- [Overview](docs/overview.md): what is new and how it compares
- [Protocol](docs/protocol.md): transactions, deadlines and assumptions
- [Security](docs/security.md) and [privacy](docs/privacy.md)
- [Evidence index](docs/evidence-index.md): every recorded run
- [Architecture](docs/architecture.md), [escrow gas](docs/gas-optimization.md)
  and [dependencies](docs/dependencies.md)

## Limits

- A settled swap is fully shielded on Zcash. A refund adds one small transparent
  coin, created from Alice's own change, because Zcash enforces a lock time only
  on a transparent input. The ETH side is public.
- Both owners have run on one host; independently administered hosts are not
  demonstrated.
- The adaptor extension and the Solidity Pallas check are unaudited, and mainnet
  is unsupported.
- Each side must watch its deadline, and inclusion and reorgs must stay within
  the timing window.
- Private keys, notes and journals stay in ignored `.local` directories.

MIT licensed; upstream components keep their own licenses.
