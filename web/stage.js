'use strict';
// The stage shows the two real owner apps and, between them, only public data:
// relay envelopes, Zcash transactions as an observer decodes them, and escrow
// events. Its narration is inferred from that public data alone.
const $ = (s) => document.querySelector(s);
let latest = null;
const shown = {generation: null, running: {}};

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
  const done = steps.filter(s => s[0]).length;
  if (done === steps.length) return [`Settled · ${steps.length} of ${steps.length}`, steps[steps.length - 1][2]];
  const next = steps.findIndex(s => !s[0]);
  return [`Step ${next + 1} of ${steps.length} · ${steps[next][1]}`, steps[next][2]];
}

async function control(body, label) {
  const status = $('#ctl-status');
  try {
    status.textContent = `${label}…`;
    const response = await fetch('/api/control', {method: 'POST', headers: {'Content-Type': 'application/json',
      'X-Latch-Token': latest.token}, body: JSON.stringify(body)});
    const result = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(result.error || 'Refused.');
    status.textContent = `${label}: done`;
  } catch (error) {
    status.textContent = error.message;
  }
  poll();
}
document.querySelectorAll('[data-play]').forEach(b => b.addEventListener('click', () =>
  control({action: 'autoplay', path: b.dataset.play}, b.textContent.replace('▶ ', ''))));
document.querySelectorAll('[data-control]').forEach(b => b.addEventListener('click', () => {
  if (b.dataset.control === 'new-trade' && !confirm('Start a new trade? The current one stays on disk.')) return;
  control(b.dataset.role ? {action: b.dataset.control, role: b.dataset.role} : {action: b.dataset.control}, b.textContent);
}));

function render(state) {
  latest = state;
  for (const b of document.querySelectorAll('[data-play]')) b.disabled = Boolean(state.autoplay);
  const bob = state.running ? state.running.bob : true;
  document.querySelector('[data-control="crash"]').disabled = !bob;
  document.querySelector('[data-control="restart"]').disabled = bob;
  const status = $('#ctl-status');
  if (state.autoplay) status.textContent = `Autoplay running (${state.autoplay === 'refund' ? 'refund path' : 'swap'})`;
  else if (status.textContent.startsWith('Autoplay running')) status.textContent = 'Autoplay finished';
  // A stopped app shows a notice; a restarted app or a new trade reloads its frame.
  for (const role of ['alice', 'bob']) {
    const up = !state.running || state.running[role] !== false;
    const frame = $(`#${role}-frame`);
    frame.closest('.stage-app').classList.toggle('is-down', !up);
    if (up && (shown.generation !== state.generation || shown.running[role] === false))
      frame.src = `http://127.0.0.1:${state.apps[role]}/?embed=1`;
    shown.running[role] = up;
  }
  shown.generation = state.generation;
  const names = {};
  for (const [role, address] of Object.entries(state.owners)) names[address.toLowerCase()] = role === 'alice' ? 'Alice' : 'Bob';
  names.alice = 'Alice'; names.bob = 'Bob';
  $('#network-dot').className = 'online';
  $('#network-status').textContent = `ZEC #${state.zcash_height}`;
  const [step, caption] = narrate(state.events);
  if ($('#stage-step').textContent !== step) $('#stage-step').textContent = step;
  if ($('#stage-caption').textContent !== caption) $('#stage-caption').textContent = caption;
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
    render(await (await fetch('/api/public', {cache: 'no-store'})).json());
  } catch {
    $('#network-dot').className = 'offline';
    $('#network-status').textContent = 'Network offline';
  }
}
poll();
setInterval(poll, 2000);
