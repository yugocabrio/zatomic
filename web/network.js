'use strict';
const $ = (s) => document.querySelector(s);
let state = null;
const name = (role) => role === 'alice' ? 'Alice' : 'Bob';
// The relay cannot open sealed messages, so this page shows what the relay sees.
const label = (m) => m.topic === 'sealed' ? `Sealed for ${name(m.to)} · ${m.bytes.toLocaleString()} bytes` : 'Identity (public keys, in the clear)';

// Rebuild a region only when its content changed, so buttons stay clickable.
function update(node, key, build) {
  if (node.dataset.key === key) return;
  node.dataset.key = key;
  node.replaceChildren(...build());
}
function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function render() {
  $('#network-dot').className = state ? 'online' : 'offline';
  $('#network-status').textContent = state ? `ZEC #${state.zcash.height} · ETH block ${state.ethereum.block}` : 'Network page offline';
  if (!state) return;
  update($('#apps'), JSON.stringify(state.apps), () => Object.entries(state.apps).map(([role, app]) => {
    const card = el('div', 'n-app');
    const link = el('a', 'n-link', `${role === 'alice' ? 'Alice' : 'Bob'} · 127.0.0.1:${app.port}`);
    link.href = `http://127.0.0.1:${app.port}/`; link.target = '_blank'; link.rel = 'noopener';
    const status = el('span', `tag ${app.running ? 'tag-strong' : 'tag-limit'}`, app.running ? 'running' : 'stopped');
    const crash = el('button', 'btn btn-ghost', 'Kill app (SIGKILL)'); crash.disabled = !app.running;
    crash.addEventListener('click', () => control({action: 'crash', role}));
    const restart = el('button', 'btn btn-ghost', app.running ? 'Restart' : 'Start');
    restart.addEventListener('click', () => control({action: 'restart', role}));
    const row = el('div', 'btn-row'); row.append(crash, restart);
    card.append(link, status, row);
    return card;
  }));
  const rows = [['Zcash (Zebra NU7 regtest)', `height ${state.zcash.height} · mempool ${state.zcash.mempool}`],
    ['Ethereum (Anvil 31338)', `block ${state.ethereum.block} · ${new Date(state.ethereum.timestamp * 1000).toLocaleTimeString()}`],
    ['PointEscrow', state.escrow.address], ['Runtime code hash', `${state.escrow.code_hash.slice(0, 18)}…`],
    ['App isolation', !state.isolation_proven ? 'checking…' : state.isolation_by === 'users'
      ? 'Unix-user denial verified both ways' : 'OS sandbox denial verified both ways']];
  update($('#chains'), JSON.stringify(rows), () => rows.flatMap(([k, v]) => [el('dt', '', k), el('dd', 'p-mono', v)]));
  update($('#relay'), JSON.stringify(state.relay), () => state.relay.map(m => {
    const row = el('tr');
    row.append(el('td', '', String(m.seq)), el('td', '', name(m.from)), el('td', '', label(m)), el('td', 'p-mono', `${m.sha256.slice(0, 16)}…`));
    return row;
  }));
  update($('#events'), JSON.stringify(state.events), () => state.events.map(e => el('li', '', `${new Date(e.at * 1000).toLocaleTimeString()}  ${e.text}`)));
}

async function control(body) {
  try {
    // Hosted demo: the stage's lease, if this browser holds the controls.
    try { const held = localStorage.getItem('latch-lease'); if (held) body.lease = held; } catch {}
    const response = await fetch('/api/control', {method: 'POST', headers: {'Content-Type': 'application/json', 'X-Latch-Token': state.token}, body: JSON.stringify(body)});
    const result = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(result.error || 'Refused.');
    $('#error').hidden = true;
  } catch (error) { $('#error').textContent = error.message; $('#error').hidden = false; }
  poll();
}
document.querySelectorAll('[data-control]').forEach(b => b.addEventListener('click', () => control({action: b.dataset.control})));

async function poll() {
  try { state = await (await fetch('/api/network', {cache: 'no-store'})).json(); } catch { state = null; }
  render();
}
poll();
setInterval(poll, 2000);
