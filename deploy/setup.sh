#!/usr/bin/env bash
# Sets up the hosted Zatomic demo on a fresh Ubuntu 24.04 server (arm64 or x86_64).
#
#   git clone https://github.com/yugocabrio/zeceth /opt/latch
#   LATCH_HOST=203-0-113-7.sslip.io bash /opt/latch/deploy/setup.sh
#
# LATCH_HOST is the site's host name. alice.$LATCH_HOST and bob.$LATCH_HOST
# must resolve to this server too (sslip.io names do so automatically).
# Safe to re-run: it rebuilds and reinstalls, and keeps the chain and trades.
# Everything runs on an isolated regtest chain and a local Anvil: no wallet,
# key or public network is involved.
set -euo pipefail

HOST=${LATCH_HOST:?set LATCH_HOST to the site host name}
[[ $HOST =~ ^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$ ]] || { echo "LATCH_HOST: lowercase host name only" >&2; exit 1; }
APP=/opt/latch
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }
# Pinned official Foundry builds (SHA-256 from the v1.3.1 release).
case "$(uname -m)" in
  aarch64) FOUNDRY_ARCH=arm64; FOUNDRY_SHA256=ac5f88c0f6c1e5ed09c035a9f4405f74b996ea8a701d7150dc0184c18dd09f11 ;;
  x86_64) FOUNDRY_ARCH=amd64; FOUNDRY_SHA256=baad3e1b06d6f310d210c93e95258a03d923fe610f8d0742138f2245f94abd7c ;;
  *) echo "use an arm64 or x86_64 server" >&2; exit 1 ;;
esac
[ -f "$APP/scripts/two_party.py" ] || { echo "clone the repository to $APP first" >&2; exit 1; }
FOUNDRY=v1.3.1
DEPLOY=$APP/deploy

echo "== packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -y -q --no-install-recommends ca-certificates curl git build-essential python3 nodejs npm sudo caddy ufw

echo "== users: the network, each owner and the node; each home is its private state"
for entry in latch:/var/lib/latch/net latch-alice:/var/lib/latch/alice latch-bob:/var/lib/latch/bob \
    latch-zebra:/var/lib/latch-zebra; do
  user=${entry%%:*}
  id -u "$user" >/dev/null 2>&1 || useradd --system --user-group --no-create-home \
    --home-dir "${entry#*:}" --shell /usr/sbin/nologin "$user"
done

echo "== toolchains"
if [ ! -x /root/.cargo/bin/rustup ]; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain none
fi
export PATH=/root/.cargo/bin:$PATH
rustup toolchain install "$(sed -n 's/^channel = "\(.*\)"/\1/p' "$APP/rust-toolchain.toml")" --profile minimal
if ! anvil --version 2>/dev/null | head -1 | grep -q "^anvil Version: ${FOUNDRY#v}-"; then
  archive=foundry_${FOUNDRY}_linux_${FOUNDRY_ARCH}.tar.gz
  work=$(mktemp -d)
  curl -fsSL -o "$work/$archive" "https://github.com/foundry-rs/foundry/releases/download/$FOUNDRY/$archive"
  echo "$FOUNDRY_SHA256  $work/$archive" | sha256sum -c -
  tar -xzf "$work/$archive" -C "$work" anvil cast forge
  install -m 0755 "$work/anvil" "$work/cast" "$work/forge" /usr/local/bin/
  rm -rf "$work"
fi

echo "== build (the first Rust release build took about a minute on 4 vCPU)"
cd "$APP"
install -d -m 0755 "$APP/.local"
npm ci --ignore-scripts --no-audit --no-fund
CARGO_BUILD_JOBS=4 cargo build --locked --release -p shielded-swap-native
forge build
LATCH_NODE=external python3 -c 'import sys; sys.path.insert(0, "scripts"); import regtest_node; regtest_node.prepare()'
python3 -m compileall -q scripts
# Everything under /opt/latch stays root-owned and world-readable; the network
# user may only create its lock and process list in .local. (A copied checkout
# keeps the copier's numeric owner, so set it explicitly.)
find "$APP" -path "$APP/.local" -prune -o -exec chown -h root:root {} +
chmod -R go+rX "$APP"
chown latch:latch "$APP/.local"
chmod 0755 "$APP/.local"

echo "== state directories"
install -d -m 0755 /var/lib/latch
install -d -m 0700 -o latch -g latch /var/lib/latch/net
install -d -m 0700 -o latch-alice -g latch-alice /var/lib/latch/alice
install -d -m 0700 -o latch-bob -g latch-bob /var/lib/latch/bob
install -d -m 0700 -o latch-zebra -g latch-zebra /var/lib/latch-zebra /var/lib/latch-zebra/state

echo "== configuration"
install -d -m 0755 /etc/latch
LATCH_NODE=external python3 "$APP/scripts/regtest_node.py" hosted-config > /etc/latch/zebra.toml
chmod 0644 /etc/latch/zebra.toml
cat > /etc/latch/latch.env <<ENV
LATCH_SITE_ORIGIN=https://$HOST
LATCH_ALICE_ORIGIN=https://alice.$HOST
LATCH_BOB_ORIGIN=https://bob.$HOST
LATCH_APP_USERS=1
LATCH_APP_BASE=/var/lib/latch
LATCH_NODE=external
RAYON_NUM_THREADS=2
ENV
chmod 0644 /etc/latch/latch.env
install -d -m 0755 /usr/local/libexec
install -m 0755 "$DEPLOY/latch-app" "$DEPLOY/latch-probe" /usr/local/libexec/
install -m 0755 "$DEPLOY/latch-reset" /usr/local/sbin/
install -m 0440 "$DEPLOY/sudoers" /etc/sudoers.d/latch.new
visudo -cf /etc/sudoers.d/latch.new
mv /etc/sudoers.d/latch.new /etc/sudoers.d/latch
install -m 0644 "$DEPLOY"/latch-zebra.service "$DEPLOY"/latch-network.service \
  "$DEPLOY"/latch-reset.service "$DEPLOY"/latch-reset.timer /etc/systemd/system/
sed "s/{\$LATCH_HOST}/$HOST/g" "$DEPLOY/Caddyfile" > /etc/caddy/Caddyfile
caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile

echo "== firewall: SSH and HTTPS only; every demo service listens on loopback"
ufw allow OpenSSH
ufw allow 80/tcp
ufw allow 443/tcp
ufw --force enable

echo "== start"
systemctl daemon-reload
systemctl enable --now latch-zebra.service
systemctl restart latch-network.service || systemctl enable --now latch-network.service
systemctl enable latch-network.service
systemctl enable --now latch-reset.timer
systemctl reload caddy || systemctl restart caddy
echo "Done. Open https://$HOST (the first start mines and builds a trade: about a minute)."
