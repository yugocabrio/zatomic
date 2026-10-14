# Shielded Swap · ZECATHON

An independent Cross-chain project: exchange native shielded ZEC for another
chain's asset, with explicit settlement and failure-recovery guarantees.

**Experimental local prototype; no mainnet or audited-security claim.**
Actual Zebra NU7 + Anvil transactions now demonstrate exchange and both-sided
refund. The principal remains shielded; the refund uses a transparent auxiliary
input. Setup is still a same-host fixture, and monitoring/timing assumptions
remain explicit. See [status](STATUS.md), [protocol](docs/protocol.md),
[reproduction](docs/reproduce.md), and [competitive target](docs/competitive-position.md).

Local-only Git repository. No remote, release, mainnet funds, or public service.

Original code is MIT licensed; reused upstream components retain their licenses.
