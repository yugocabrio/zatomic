'use strict';
// The stage shows the two real owner apps and, between them, only public data:
// relay envelopes, Zcash transactions as an observer decodes them, and escrow
// events. Its narration is inferred from that public data alone.
const $ = (s) => document.querySelector(s);
let latest = null;
const shown = {generation: null, running: {}, lease: {}};
// Hosted demo: one visitor drives at a time. The lease is a per-browser
// convenience; the server decides who holds the controls.
const lease = {
  get() { try { return localStorage.getItem('latch-lease') || ''; } catch { return ''; } },
  set(value) { try { value ? localStorage.setItem('latch-lease', value) : localStorage.removeItem('latch-lease'); } catch {} },
};
const utc = (seconds) => new Date(seconds * 1000).toISOString().slice(11, 16);

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}
function eth(wei) {
  const value = BigInt(wei), unit = 10n ** 18n;
  const fraction = (value % unit).toString().padStart(18, '0').replace(/0+$/, '');
  return `${value / unit}${fraction ? '.' + fraction : ''} ETH`;
}
const zec = (zatoshi) => `${zatoshi / 1e8} ZEC`;
const short = (value) => `${value.slice(0, 8)}…${value.slice(-6)}`;

function describe(e, names) {
  const who = (address) => names[(address || '').toLowerCase()] || short(address || '0x');
  if (e.chain === 'relay') {
    if (e.kind === 'manifest') return ['relay', `${who(e.from)} posts an identity: public keys only`, ''];
    return ['relay', `${who(e.from)} → ${who(e.to)}: sealed message`, `${(e.bytes || 0).toLocaleString()} bytes · the relay cannot open it`];
  }
  if (e.chain === 'zcash') {
    if (e.transparent_outputs.length) return ['zec warn', `Zcash: ${e.transparent_outputs.map(zec).join(', ')} to a transparent address`, 'Appears only on the refund path'];
    if (e.transparent_inputs) return ['zec', 'Zcash: shielded refund, time-locked by a transparent input', `${e.actions} actions · amount and recipient hidden`];
    return ['zec', 'Zcash: shielded transaction', `${e.actions} actions · amount, sender and recipient hidden · block #${e.height}`];
  }
  if (e.event === 'locked') return ['eth', `Ethereum: ${who(e.maker)} locks ${eth(e.amount_wei)} for ${who(e.recipient)}`, 'Claimable only with the secret t'];
  if (e.event === 'claimed') return ['eth key', `Ethereum: claimed. t is now public`, `t = ${short(e.witness)} · it completes Bob’s pre-signed Zcash claim`];
  if (e.event === 'refunded') return ['eth', 'Ethereum: ETH refunded at expiry', 'No secret was revealed'];
  return ['eth', `Ethereum: ${eth(e.amount_wei)} withdrawn by ${who(e.owner)}`, ''];
}

// The step is inferred from public events only, in protocol order.
function narrate(events) {
  const relay = events.filter(e => e.chain === 'relay');
  const zcash = events.filter(e => e.chain === 'zcash');
  const find = (kind) => events.find(e => e.chain === 'ethereum' && e.event === kind);
  const claimed = find('claimed'), refunded = find('refunded');
  const shielded = zcash.filter(e => !e.transparent_outputs.length && !e.transparent_inputs);
  const steps = refunded || zcash.some(e => e.transparent_outputs.length) ? [
    [relay.some(e => e.kind === 'manifest'), 'Owners exchange identities', 'Each app posts its public keys; the owners compare fingerprints out of band.'],
    [relay.some(e => e.kind === 'sealed'), 'Quote, terms and both exits', 'Sealed messages only. Both exits are signed before any money moves.'],
    [shielded.length > 0, 'Alice funds the shared note', 'A shielded Zcash transaction: no amount or address is visible.'],
    [Boolean(find('locked')), 'Bob locks ETH', 'Public on Ethereum: amount, both addresses and the point T.'],
    [Boolean(refunded), 'No reveal: Bob takes his ETH back', 'Alice never published t, so Bob refunds after the expiry.'],
    [zcash.some(e => e.transparent_outputs.length), 'Alice creates her refund coin', 'Her private auxiliary transaction appears only now, on the refund path.'],
    [zcash.some(e => e.transparent_inputs), 'Alice’s ZEC comes back', 'Her pre-signed refund is valid only after the refund time.'],
  ] : [
    [relay.some(e => e.kind === 'manifest'), 'Owners exchange identities', 'Each app posts its public keys; the owners compare fingerprints out of band.'],
    [relay.some(e => e.kind === 'sealed'), 'Quote, terms and both exits', 'Sealed messages only. Both exits are signed before any money moves.'],
    [shielded.length > 0, 'Alice funds the shared note', 'A shielded Zcash transaction: no amount or address is visible.'],
    [Boolean(find('locked')), 'Bob locks ETH', 'Public on Ethereum: amount, both addresses and the point T.'],
    [Boolean(claimed), 'Alice claims the ETH and reveals t', 'The same t completes Bob’s pre-signed Zcash claim. Nobody else can link t to it.'],
    [Boolean(claimed) && shielded.some(e => e.at >= claimed.at), 'Bob claims his ZEC', 'Another shielded transaction; Bob’s own wallet decrypts it.'],
    [Boolean(find('withdrawn')), 'Alice withdraws the ETH', 'Settled. No transparent output ever appeared on Zcash.'],
  ];
  const refund = Boolean(refunded || zcash.some(e => e.transparent_outputs.length));
  const done = steps.filter(s => s[0]).length === steps.length;
  if (done) return {done, refund, step: refund ? 'Refunded · both sides' : `Settled · ${steps.length} of ${steps.length}`, caption: steps[steps.length - 1][2]};
  const next = steps.findIndex(s => !s[0]);
  return {done, refund, step: `Step ${next + 1} of ${steps.length} · ${steps[next][1]}`, caption: steps[next][2]};
}

const SCENARIOS = {success: 'The swap', crash: 'Bob’s app crashes', refund: 'Both refund'};
const RECORD = new URLSearchParams(location.search).has('record');
if (RECORD) document.body.classList.add('record');
const clock = (seconds) => `${Math.floor(seconds / 60)}:${String(seconds % 60).padStart(2, '0')}`;

// The end of a trade, from public data only: the ZEC amount and receive
// addresses are visible inside the apps, never here.
function summary(state, story) {
  const zcash = state.events.filter(e => e.chain === 'zcash');
  const find = (kind) => state.events.find(e => e.chain === 'ethereum' && e.event === kind);
  const locked = find('locked');
  const relay = state.events.filter(e => e.chain === 'relay');
  const sealed = relay.filter(e => e.kind === 'sealed').length;
  const s = state.scenario;
  const took = s && s.ended && s.ended >= s.started ? ` in ${clock(s.ended - s.started)}` : '';
  const lines = story.refund ? [
    `Ethereum: ${locked ? eth(locked.amount_wei) : 'the ETH'} locked, then refunded to Bob after the expiry. t was never revealed.`,
    'Zcash: Alice’s pre-signed refund returned her ZEC. Only on this path does one transparent coin appear.',
  ] : [
    `Ethereum: ${locked ? eth(locked.amount_wei) : 'the ETH'} locked by Bob, claimed with t, withdrawn by Alice.`,
    `Zcash: ${zcash.length} shielded transactions. No amount, no address, nothing transparent.`,
  ];
  lines.push(`Relay: ${relay.length} messages, ${sealed} sealed. It never saw the amounts.`);
  if ((state.interrupted || []).includes('bob')) lines.push('Bob’s app was killed mid-swap. It resumed from its own journal and claimed with t from Ethereum, needing nothing from Alice.');
  lines.push('Each app shows what its owner received. The exact ZEC amount appears only there, though the public ETH amount hints at it via the market price.');
  return {title: (story.refund ? 'Both refunded' : 'Swap settled') + took, lines};
}

async function send(body) {
  const response = await fetch('/api/control', {method: 'POST', headers: {'Content-Type': 'application/json',
    'X-Latch-Token': latest.token}, body: JSON.stringify(body)});
  const result = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(result.error || 'Refused.');
  return result;
}

async function control(body, label) {
  const status = $('#ctl-status');
  try {
    status.textContent = `${label}…`;
    if (latest.public) {
      // Free controls are taken by the first press; a held lease is renewed.
      if (!(latest.driver && latest.driver.mine)) lease.set((await send({action: 'drive', lease: lease.get()})).lease);
      body.lease = lease.get();
    }
    await send(body);
    status.textContent = `${label}: done`;
  } catch (error) {
    status.textContent = error.message;
  }
  poll();
}
// A finished trade cannot run again: scenarios then start from a fresh trade.
function play(path) {
  const fresh = Boolean(latest && latest.finished);
  control({action: 'autoplay', path, fresh}, `${SCENARIOS[path]}${fresh ? ' (new trade)' : ''}`);
}
function newTrade(ask) {
  if (ask && !RECORD && !confirm('Start a new trade? The current one stays on disk.')) return;
  control({action: 'new-trade'}, 'New trade');
}
document.querySelectorAll('[data-play]').forEach(b => b.addEventListener('click', () => play(b.dataset.play)));
document.querySelectorAll('[data-scenario]').forEach(b => b.addEventListener('click', () => play(b.dataset.scenario)));
document.querySelector('[data-again]').addEventListener('click', (e) => play(e.currentTarget.dataset.again));
document.querySelectorAll('[data-other]').forEach(b => b.addEventListener('click', () => play(b.dataset.path)));
document.querySelector('[data-resume="success"]').addEventListener('click', () => play('success'));
document.querySelector('[data-resume="new"]').addEventListener('click', () => newTrade(false));
document.querySelectorAll('[data-control]').forEach(b => b.addEventListener('click', () => {
  if (b.dataset.control === 'new-trade') return newTrade(true);
  control(b.dataset.role ? {action: b.dataset.control, role: b.dataset.role} : {action: b.dataset.control}, b.textContent);
}));
// Keys for presenting and recording (the control bar is hidden with ?record):
// 1 2 3 scenarios, N new trade, S/R stop/restart Bob, E/Z time on ETH/Zcash.
document.addEventListener('keydown', (e) => {
  if (!latest || e.metaKey || e.ctrlKey || e.altKey || e.repeat) return;
  const key = e.key.toLowerCase();
  const paths = {1: 'success', 2: 'crash', 3: 'refund'};
  if (paths[key]) return play(paths[key]);
  const actions = {n: () => newTrade(true), s: () => control({action: 'crash', role: 'bob'}, 'Stop Bob’s app'),
    r: () => control({action: 'restart', role: 'bob'}, 'Restart Bob’s app'),
    e: () => control({action: 'advance-eth'}, 'ETH +61 min'), z: () => control({action: 'advance-zec'}, 'Zcash +24 blocks')};
  if (actions[key]) actions[key]();
});

function render(state) {
  latest = state;
  const driver = state.driver;
  const watching = Boolean(state.public && driver && !driver.mine);
  if (state.public && !(driver && driver.mine)) lease.set('');
  for (const b of document.querySelectorAll('.stage-controls button')) b.disabled = watching;
  for (const b of document.querySelectorAll('[data-play]')) b.disabled ||= Boolean(state.autoplay);
  const bob = state.running ? state.running.bob : true;
  document.querySelector('[data-control="crash"]').disabled ||= !bob;
  document.querySelector('[data-control="restart"]').disabled ||= bob;
  const who = $('#ctl-driver');
  who.hidden = !state.public;
  who.textContent = !state.public ? '' : watching ? `Another visitor is driving until ${utc(driver.until)} UTC. You are watching live.`
    : driver ? 'You have the controls. They free up after five idle minutes.' : 'Controls free: any button makes you the driver.';
  who.classList.toggle('is-watching', watching);
  const iso = state.isolation || {};
  $('#iso').textContent = !iso.proven ? 'Checking that neither app can read the other’s files…'
    : iso.by === 'users' ? '✓ Checked: each app runs as its own Linux user; neither can read the other’s files.'
    : '✓ Checked: the OS sandbox stops each app reading the other’s files.';
  const status = $('#ctl-status');
  if (state.autoplay) status.textContent = `Autoplay running: ${SCENARIOS[state.autoplay]}`;
  else if (status.textContent.startsWith('Autoplay running')) status.textContent = 'Autoplay finished';
  // A stopped app shows a notice; a restarted app or a new trade reloads its frame.
  for (const role of ['alice', 'bob']) {
    const up = !state.running || state.running[role] !== false;
    const frame = $(`#${role}-frame`);
    const key = driver && driver.mine ? lease.get() : '';
    frame.closest('.stage-app').classList.toggle('is-down', !up);
    if (up && (shown.generation !== state.generation || shown.running[role] === false || shown.lease[role] !== key)) {
      frame.src = `${state.apps[role]}/?embed=1${key ? '&lease=' + encodeURIComponent(key) : ''}`;
      shown.lease[role] = key;
    }
    shown.running[role] = up;
  }
  shown.generation = state.generation;
  const names = {};
  for (const [role, address] of Object.entries(state.owners)) names[address.toLowerCase()] = role === 'alice' ? 'Alice' : 'Bob';
  names.alice = 'Alice'; names.bob = 'Bob';
  $('#network-dot').className = 'online';
  $('#network-status').textContent = `ZEC #${state.zcash_height}`;
  const story = narrate(state.events);
  state.finished = story.done;
  if ($('#stage-step').textContent !== story.step) $('#stage-step').textContent = story.step;
  if ($('#stage-caption').textContent !== story.caption) $('#stage-caption').textContent = story.caption;
  // What the middle column offers: a scenario to start, a running clock, a
  // nudge for a trade left part-way, or the result.
  const begun = state.events.some(e => e.chain === 'relay' && e.kind === 'sealed');
  const last = state.events.length ? state.events[state.events.length - 1].at : state.now;
  const s = state.scenario;
  $('#start').hidden = watching || Boolean(state.autoplay) || begun || story.done;
  $('#resume').hidden = watching || Boolean(state.autoplay) || !begun || story.done || state.now - last < 90;
  $('#stage-clock').hidden = !state.autoplay || !s;
  if (state.autoplay && s) $('#stage-clock').textContent = `Autoplay · ${SCENARIOS[s.path]} · ${clock(Math.max(0, state.now - s.started))}`;
  $('#result').hidden = !story.done;
  $('.stage-wire').classList.toggle('is-start', !$('#start').hidden);
  $('.stage-wire').classList.toggle('is-done', story.done);
  if (story.done) {
    const {title, lines} = summary(state, story);
    $('#result-title').textContent = title;
    if ($('#result-list').dataset.key !== JSON.stringify(lines)) {
      $('#result-list').dataset.key = JSON.stringify(lines);
      $('#result-list').replaceChildren(...lines.map(line => el('li', '', line)));
    }
    const ran = s ? s.path : (story.refund ? 'refund' : 'success');
    $('[data-again]').dataset.again = ran;
    Object.keys(SCENARIOS).filter(p => p !== ran).forEach((path, i) => {
      const b = document.querySelector(`[data-other="${i}"]`);
      b.dataset.path = path;
      b.textContent = `Try: ${SCENARIOS[path]}`;
    });
    for (const b of document.querySelectorAll('#result button')) b.disabled = watching;
  }
  const wire = $('#wire');
  // Events only accumulate; a shorter list means a new network, so start over.
  if (wire.childElementCount > state.events.length) wire.replaceChildren();
  if (wire.childElementCount < state.events.length) {
    for (const e of state.events.slice(wire.childElementCount)) {
      const [kind, title, detail] = describe(e, names);
      const item = el('li', `wire-item is-${kind.split(' ').join(' is-')}`);
      item.append(el('span', 'wire-badge', kind.split(' ')[0].toUpperCase()));
      const text = el('div'); text.append(el('p', 'wire-title', title));
      if (detail) text.append(el('p', 'wire-detail', detail));
      item.append(text);
      wire.append(item);
    }
    wire.scrollTop = wire.scrollHeight;
  }
  const zcash = state.events.filter(e => e.chain === 'zcash');
  const ethEvents = state.events.filter(e => e.chain === 'ethereum');
  const sealed = state.events.filter(e => e.chain === 'relay' && e.kind === 'sealed').length;
  const transparent = zcash.filter(e => e.transparent_outputs.length).length;
  $('#obs-zec').textContent = `${zcash.length} transaction${zcash.length === 1 ? '' : 's'}`;
  $('#obs-zec-note').textContent = transparent ? 'refund path: one transparent coin appeared' : 'all shielded: no amount, address or transparent output';
  const locked = ethEvents.find(e => e.event === 'locked');
  $('#obs-eth').textContent = locked ? eth(locked.amount_wei) : 'nothing yet';
  $('#obs-eth-note').textContent = ethEvents.map(e => e.event).join(' → ') || 'public by design';
  $('#obs-relay').textContent = `${sealed} sealed`;
}

async function poll() {
  try {
    const held = lease.get();
    render(await (await fetch('/api/public' + (held ? '?lease=' + encodeURIComponent(held) : ''), {cache: 'no-store'})).json());
  } catch {
    $('#network-dot').className = 'offline';
    $('#network-status').textContent = 'Network offline';
  }
}
poll();
setInterval(poll, 2000);
