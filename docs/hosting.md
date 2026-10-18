# Hosting the judge demo

The hosted demo is the [two-party mode](two-party.md) on one rented server,
reachable over HTTPS. Judges open one address: `/` explains the swap, `/stage`
runs a trade with both owner apps side by side, `/network` shows the relay's
records and the isolation check. Everything runs on an isolated Zcash regtest
chain and a local Anvil: no wallet, real key, public network or real value is
involved.

## What runs

| Service | Unix user | Listens on |
|---|---|---|
| `latch-zebra` | `latch-zebra` | Zebra NU7 regtest, RPC on `127.0.0.1:30342` |
| `latch-network` | `latch` | site `127.0.0.1:8790`, Anvil, relay |
| Alice's app (started by the network) | `latch-alice` | `127.0.0.1:8791`, her signer `18741` |
| Bob's app (started by the network) | `latch-bob` | `127.0.0.1:8792`, his signer `18742` |
| Caddy | `caddy` | public `:80` and `:443`, HTTPS for all three names |

The firewall opens only SSH, 80 and 443. Each owner's files live under
`/var/lib/latch/<owner>`, mode 0700 and owned by that owner's user. The other
owner's app gets a permission error there, and so does the network process. The
network proves both denials at the start of every trade, and the stage footer
shows the result. The network may start, probe and kill each app as that app's
user and nothing else ([`deploy/sudoers`](../deploy/sudoers)).

## Server

- **arm64**, because the pinned `zebrad` release is aarch64 Linux. Ubuntu 24.04.
- 4 vCPU and 8 GB RAM is enough; 8 vCPU and 16 GB proves and builds faster.
  The first Rust release build takes roughly 15 to 30 minutes (an estimate; not
  yet timed on such a server). Disk: 40 GB.
- For example, Hetzner Cloud CAX21 (4 vCPU, 8 GB) or CAX31 (8 vCPU, 16 GB).

The site needs three names that point at the server: `HOST`, `alice.HOST` and
`bob.HOST`. Each owner app gets its own origin, so the browser keeps them apart
as well.

- Without a domain: use `HOST=<IP with dashes>.sslip.io`, for example
  `203-0-113-7.sslip.io`. `alice.203-0-113-7.sslip.io` resolves to the same IP.
- With a domain: add A records for all three names, or a wildcard.

## Set up

```sh
ssh root@SERVER_IP
git clone https://github.com/yugocabrio/zeceth /opt/latch
LATCH_HOST=203-0-113-7.sslip.io bash /opt/latch/deploy/setup.sh
```

If the repository is private, give the server a read-only deploy key or copy a
checkout to `/opt/latch` with `rsync`. [`deploy/setup.sh`](../deploy/setup.sh)
installs the packages, Rust 1.93 (from `rust-toolchain.toml`) and Foundry 1.3.1,
builds the native binary and the contract, and fetches the pinned `zebrad`,
checking its SHA-256. It then creates the four users and their private
directories, installs the sudo rule, the systemd units and the Caddy site, turns
on the firewall and starts everything. Running it again rebuilds and keeps the
chain and trades. Then open `https://HOST`. The first start activates NU7 and
prepares a trade; allow a minute or two.

## One driver at a time

Everyone sees the same trade. The first visitor to press a stage control gets
the controls. That visitor can also press the buttons inside both apps. Everyone
else watches live; their buttons are disabled and the stage says until when.
The controls free up five minutes after the driver's last action, or two
minutes after Autoplay stops, whichever is later. Pressing on behalf of both owners is a demo
convenience: in a real deployment each owner runs their own app on their own
device.

## Chain capacity

The budget is 400 regtest blocks per trade, a generous bound: Alice's faucet
mines 101, and the refund path advances 72 more. The local wallet scan stops at height 10,002. New trade is refused when
fewer than 400 blocks remain. Every day at 04:00 UTC `latch-reset.timer` checks
the height, and above 7,000 it starts a fresh chain. That deletes every demo
trade, all regtest data. To reset by hand: `/usr/local/sbin/latch-reset --force`.

## Operating

```sh
systemctl status latch-network latch-zebra caddy
journalctl -u latch-network -f
cd /opt/latch && git pull && LATCH_HOST=203-0-113-7.sslip.io bash deploy/setup.sh
```

The apps' stdout and stderr go to `/var/lib/latch/net/<trade>/network/`.

## How it differs from the local demo

| | Local (`make two-party`) | Hosted |
|---|---|---|
| App separation | a macOS `sandbox-exec` policy per app | a Unix user per app; the network cannot read either |
| Zcash node | Zebra in Docker | `zebrad` as its own service; no Docker |
| Reach | loopback only | HTTPS through Caddy; the servers still bind loopback and check Host and Origin |
| Controls | anyone on the machine | one visitor at a time |

**Not claimed:** all three roles run on one machine run by one operator. This is
not independent administration, and the network process can start or stop
either app.
