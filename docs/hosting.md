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

- Ubuntu 24.04 on **arm64 or x86_64**. The setup picks the matching official
  `zebrad` and Foundry builds and checks each against its pinned SHA-256.
- 4 vCPU and 8 GB RAM is enough. Avoid 4 GB. Disk: 40 GB.
- Running now on a Hetzner Cloud CPX32 (x86_64, 4 vCPU AMD EPYC Genoa, 8 GB,
  Ubuntu 24.04.4): the release Rust build took 1 minute, the whole setup about
  3 minutes, and a stage swap 1:46
  ([record](../evidence/2026-10-18-hosted-demo.json)). Arm64 hosts (Hetzner
  CAX21/CAX31 when available, netcup VPS 2000 ARM) use the same setup.
- If the provider has its own firewall (Hetzner Cloud Firewall), allow inbound
  TCP 80 and 443 as well as 22. Otherwise the certificates cannot be issued.

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
checkout to `/opt/latch` with `rsync` (the setup resets the copied files to
root ownership). [`deploy/setup.sh`](../deploy/setup.sh)
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

A swap uses about 105 regtest blocks and a refund about 180: Alice's faucet
mines 101, and the refund path advances 72 more. The budget is a generous 400
per trade. The local wallet scan stops at height 10,002, so New trade is refused
when fewer than 400 blocks remain.

The faucet funds Alice with one coinbase note, and the regtest block reward
halves every 864 blocks (0.0326 ZEC from height 5,177, 0.0163 from 6,041,
0.0081 from 6,905). Demo quotes are 0.015 ZEC for 0.0293 ETH while one reward
covers that, and proportionally smaller after that, so trades keep working, just
with smaller amounts. Every day at 04:00 UTC `latch-reset.timer` checks the
height; at 6,800 or above it starts a fresh chain, before the amounts shrink. That
deletes every demo trade, all regtest data. To reset by hand:
`/usr/local/sbin/latch-reset --force`.

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
