'use strict';
// Renders the owner app's own view model. The server decides which action is
// available from this owner's files, the relay and the chains.
const $ = (s) => document.querySelector(s);
let view = null;
let sending = false;

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}
function setText(selector, value) { const node = $(selector); if (node.textContent !== value) node.textContent = value; }
function short(value) { return value && value.length > 20 ? `${value.slice(0, 10)}…${value.slice(-6)}` : (value || ''); }
const NAMES = {alice: 'Alice · sells ZEC', bob: 'Bob · sells ETH'};
// Inside the network's stage view the app drops its chrome and privacy panel.
const EMBED = new URLSearchParams(location.search).has('embed');
if (EMBED) document.documentElement.classList.add('embed');
// Hosted demo: the stage passes the driver's lease; without it this page only watches.
const LEASE = new URLSearchParams(location.search).get('lease') || '';
const NOTES = {alice: ['shielded, from my own wallet', 'on Ethereum, after I reveal t'],
  bob: ['locked in the escrow on Ethereum', 'shielded, to a one-time address']};

function renderAction(action) {
  const box = $('#action');
  const key = JSON.stringify([action, view.busy, view.complete]);
  if (box.dataset.key === key) return;
  box.dataset.key = key;
  box.replaceChildren();
  if (view.complete) {
    box.append(el('p', 'p-done', view.complete.title), el('p', 'p-note', view.complete.text));
    return;
  }
  if (view.busy) {
    box.append(el('p', 'p-wait is-busy', `${view.busy}…`), el('p', 'p-note', 'Proving and confirming on the local chains. This page keeps updating.'));
    return;
  }
  if (!action) { box.append(el('p', 'p-note', 'Nothing to do right now.')); return; }
  if (action.wait) { box.append(el('p', 'p-wait', action.wait)); return; }
  if (action.fingerprint) {
    const peer = view.role === 'alice' ? 'Bob' : 'Alice';
    box.append(el('p', 'p-note', `Compare these with ${peer} over a channel you already trust (call, chat). Trust only if they match.`));
    const list = el('dl', 'review');
    // Inside the stage the fingerprints are shortened (full on hover); the
    // standalone app shows them in full, as a real owner should compare them.
    const fp = (value) => { const dd = el('dd', 'p-mono', EMBED ? `${value.slice(0, 16)}…${value.slice(-12)}` : value); dd.title = value; return dd; };
    list.append(el('dt', '', `${peer}'s fingerprint`), fp(action.fingerprint));
    if (action.source_fingerprint) list.append(el('dt', '', 'Alice’s source operator'), fp(action.source_fingerprint));
    box.append(list);
  }
  if (action.review) {
    const r = action.review;
    const list = el('dl', 'review');
    for (const [k, v] of [['Bob receives', `${r.zec_received_by_bob} ZEC, shielded`], ['Alice receives', `${r.eth_received_by_alice} ETH`],
        ['Implied price', `${r.indicative_eth_per_zec.replace(/\.?0+$/, '')} ETH per ZEC`], ['Alice’s signature', 'Verified ✓']]) {
      list.append(el('dt', '', k), el('dd', '', v));
    }
    box.append(list, el('p', 'p-note', 'Accepting signs only this quote. My signer then goes online for the exit preparation.'));
  }
  if (action.terms) {
    const list = el('ul', 'p-terms');
    for (const t of action.terms) list.append(el('li', '', t));
    box.append(el('p', 'p-note', 'My client already verified my exit. Signing binds all of this:'), list);
  }
  let fields = null;
  if (action.fields) {
    fields = el('div', 'p-fields');
    const d = action.defaults || {zec: '0.015', eth: '0.0293'};
    for (const [id, label, value] of [['zec', 'Bob receives (ZEC)', d.zec], ['eth', 'Alice receives (ETH)', d.eth]]) {
      const wrap = el('label', 'field'); const span = el('span', '', label);
      const input = el('input'); input.id = `p-${id}`; input.value = value; input.inputMode = 'decimal'; input.autocomplete = 'off';
      wrap.append(span, input); fields.append(wrap);
    }
    box.append(fields);
  }
  if (action.note) box.append(el('p', 'p-note', action.note));
  const button = el('button', `btn ${action.danger ? 'btn-recover' : 'btn-primary'} btn-wide`);
  button.append(el('span', '', action.label), el('span', '', '→'));
  button.addEventListener('click', () => act(action, fields));
  box.append(button);
  if (view.public && !LEASE) {
    button.disabled = true;
    box.append(el('p', 'p-note', 'Watching. To press this, take the controls on the stage page.'));
  }
}

async function act(action, fields) {
  if (sending) return;
  sending = true;
  const body = {action: action.id};
  if (LEASE) body.lease = LEASE;
  if (action.fingerprint) { body.fingerprint = action.fingerprint; body.source_fingerprint = action.source_fingerprint; }
  if (fields) { body.zec_amount = $('#p-zec').value.trim(); body.eth_amount = $('#p-eth').value.trim(); }
  try {
    const response = await fetch('/api/act', {method: 'POST', headers: {'Content-Type': 'application/json', 'X-Latch-Token': view.token}, body: JSON.stringify(body)});
    const result = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(result.error || 'The action was refused.');
    $('#error').hidden = true;
  } catch (error) {
    $('#error').textContent = error.message; $('#error').hidden = false;
  } finally {
    sending = false; poll();
  }
}

function render() {
  document.body.dataset.role = view.role;
  setText('#role-chip', NAMES[view.role]);
  setText('#holds', `This app holds only ${view.role === 'alice' ? 'Alice' : 'Bob'}’s keys`);
  document.title = `Zatomic — ${view.role === 'alice' ? 'Alice' : 'Bob'}`;
  $('#network-dot').className = view.offline ? 'offline' : 'online';
  setText('#network-status', view.offline ? 'Network unreachable' : `ZEC #${view.chain.zcash_height} · relay ${view.relay_count} msgs`);
  if (view.offline) return;
  const busy = $('#busy-chip'); busy.hidden = !view.busy; setText('#busy-chip', view.busy || '');
  if (view.error) { $('#error').textContent = view.error; $('#error').hidden = false; }
  renderAction(view.action);
  const deal = $('#deal');
  deal.hidden = !view.trade;
  if (view.trade) {
    setText('#give', view.trade.give); setText('#get', view.trade.get);
    setText('#give-note', NOTES[view.role][0]); setText('#get-note', NOTES[view.role][1]);
    const done = view.steps.filter(s => s.done).length;
    $('#progress-bar').style.width = `${Math.round(100 * done / view.steps.length)}%`;
    setText('#progress-text', view.complete ? view.complete.title : `Step ${Math.min(done + 1, view.steps.length)} of ${view.steps.length}`);
    deal.classList.toggle('is-complete', Boolean(view.complete));
  }
  const steps = $('#steps');
  const key = JSON.stringify(view.steps);
  if (steps.dataset.key !== key) {
    steps.dataset.key = key;
    const current = view.steps.findIndex(s => !s.done);
    steps.replaceChildren(...view.steps.map((s, i) => {
      const item = el('li', `agree-step ${s.done ? 'is-done' : i === current ? 'is-current' : 'is-locked'}`);
      const head = el('div', 'agree-head');
      const text = el('div'); text.append(el('h4', '', s.title));
      if (s.detail) text.append(el('p', 'p-detail', s.detail));
      head.append(el('span', 'agree-mark', s.done ? '✓' : String(i + 1)), text);
      item.append(head);
      return item;
    }));
  }
  setText('#peer-name', view.shared.peer);
  for (const [id, items] of [['#sent', view.shared.sent], ['#kept', view.shared.kept]]) {
    const list = $(id); const k = items.join('|');
    if (list.dataset.key !== k) { list.dataset.key = k; list.replaceChildren(...items.map(t => el('li', '', t))); }
  }
  setText('#my-fp', short(view.me.fingerprint)); setText('#my-address', short(view.me.address));
  const c = view.chain;
  const rows = [['Zcash height', `#${c.zcash_height}`]];
  if (c.funding_confirmations !== undefined) rows.push(['ZEC funding', c.funding_confirmations === null ? 'not seen' : `${c.funding_confirmations} confirmations`]);
  if (c.order_state !== undefined) rows.push(['ETH order', ['empty', 'locked', 'claimed (t public)', 'refunded'][c.order_state] || '—']);
  if (c.eth_expired !== undefined) rows.push(['ETH expiry', c.eth_expired ? 'passed' : 'not yet']);
  const chain = $('#chain'); const ck = JSON.stringify(rows);
  if (chain.dataset.key !== ck) { chain.dataset.key = ck; chain.replaceChildren(...rows.flatMap(([k, v]) => [el('dt', '', k), el('dd', '', v)])); }
}

async function poll() {
  try {
    const response = await fetch('/api/state', {cache: 'no-store'});
    view = await response.json();
  } catch {
    view = Object.assign(view || {role: 'alice', chain: {}}, {offline: true});
  }
  render();
}
poll();
setInterval(poll, 1500);
