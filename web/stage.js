'use strict';
// The stage shows the two real owner apps and, between them, only public data:
// relay envelopes, Zcash transactions as an observer decodes them, and escrow
// events. Its narration is inferred from that public data alone.
const $ = (s) => document.querySelector(s);
let latest = null;
const shown = {generation: null, ready: {}, lease: {}, events: new Set()};
// Hosted demo: one visitor drives at a time. The lease is a per-browser
// convenience; the server decides who holds the controls.
const lease = {
  get() { try { return localStorage.getItem('latch-lease') || ''; } catch { return ''; } },
  set(value) { try { value ? localStorage.setItem('latch-lease', value) : localStorage.removeItem('latch-lease'); } catch {} },
};
const utc = (seconds) => new Date(seconds * 1000).toISOString().slice(11, 16);

// One wire row; rows already on screen do not animate in again. The step is
// the diagram's number for the row (↩ for the refund branch).
function item([kind, title, detail], seen, step) {
  const node = el('li', `wire-item is-${kind.split(' ').join(' is-')}${seen ? ' is-seen' : ''}`);
  if (step) node.append(el('span', 'wire-step', step));
  node.append(el('span', 'wire-badge', kind.split(' ')[0].toUpperCase()));
  const text = el('div'); text.append(el('p', 'wire-title', title));
  if (detail) text.append(el('p', 'wire-detail', detail));
  node.append(text);
  return node;
}
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

function describe(e, names, role) {
  const who = (address) => names[(address || '').toLowerCase()] || short(address || '0x');
  if (e.chain === 'relay') {
    if (e.kind === 'manifest') return ['relay', `${who(e.from)} posts an identity: public keys only`, ''];
    return ['relay', `${who(e.from)} → ${who(e.to)}: sealed message`, `${(e.bytes || 0).toLocaleString()} bytes · the relay cannot open it`];
  }
  if (e.chain === 'zcash') {
    // A transaction is listed once Zebra has mined it, so it passed the node's
    // proof, signature and lock-time checks.
    const mined = `Mined in block #${e.height}`, id = `tx ${short(e.txid || '')}`;
    if (role === 'R') return ['zec warn', 'Zcash · R: Alice’s time-locked refund',
      `${mined} once its lock time passed, which Zebra enforces · her ZEC returns shielded${e.transparent_outputs.length ? ` · ${e.transparent_outputs.map(zec).join(', ')} change to the coin’s transparent address` : ''} · ${id}`];
    if (role === 'A') return ['zec warn', 'Zcash · A: the coin Alice’s refund needs', `${mined} · ${e.transparent_outputs.map(zec).join(', ')} to a transparent address, from her own change · only on the refund path · ${id}`];
    if (role === 'F') return ['zec', 'Zcash · F: Alice funds the shared note', `${mined}: Zebra checked its proof and signatures · amount, sender and recipient hidden · ${id}`];
    if (role === 'C') return ['zec', 'Zcash · C: Bob claims the ZEC', `${mined}: Zebra checked Bob’s completed signature and the proof · amount hidden · ${id}`];
    return ['zec', 'Zcash: shielded transaction', `${mined} · amount, sender and recipient hidden · ${id}`];
  }
  const at = `Block ${e.block}`, id = `tx ${short(e.tx || '')}`;
  if (e.event === 'locked') return ['eth', `Ethereum · lock: ${who(e.maker)} locks ${eth(e.amount_wei)} for ${who(e.recipient)}`, `${at} · claimable only with the secret t · ${id}`];
  if (e.event === 'claimed') return ['eth key', 'Ethereum · claim(t): t is now public', `${at}: the escrow checked t·G = T on Pallas · t = ${short(e.witness)} completes the FROST pre-signature on Bob’s claim · ${id}`];
  if (e.event === 'refunded') return ['eth', 'Ethereum · refund: Bob’s ETH back after the expiry', `${at} · no secret was revealed · ${id}`];
  return ['eth', `Ethereum · withdraw: ${eth(e.amount_wei)} paid out to ${who(e.owner)}`, `${at} · ${id}`];
}

// When each chain's events were observed gives no reliable order across the
// two chains, so the list follows what the protocol fixes: F before the lock,
// claim or refund then its withdrawal, C after the claim, A and R after the
// refund. Each entry keeps its index in events.
function inOrder(events) {
  const chain = events.map((e, i) => ({e, i})).filter(x => x.e.chain !== 'relay');
  const shielded = chain.filter(x => x.e.chain === 'zcash' && !x.e.transparent_outputs.length && !x.e.transparent_inputs)
    .sort((a, b) => a.e.height - b.e.height);
  const claimed = chain.some(x => x.e.event === 'claimed');
  const RANK = {F: 1, locked: 2, claimed: 3, refunded: 3, withdrawn: 4, C: 5, Z: 5, A: 6, R: 7};
  for (const x of chain) {
    if (x.e.chain !== 'zcash') x.role = x.e.event;
    else if (x.e.transparent_inputs) x.role = 'R';
    else if (x.e.transparent_outputs.length) x.role = 'A';
    else x.role = shielded[0] === x ? 'F' : shielded[1] === x && claimed ? 'C' : 'Z';
  }
  return chain.sort((a, b) => (RANK[a.role] || 5) - (RANK[b.role] || 5) || a.i - b.i);
}

// The step is inferred from public events only, in protocol order. Zcash
// transactions are ordered by block height, never by when they were observed:
// a restarted page or network can observe several at the same moment.
function narrate(events) {
  const relay = events.filter(e => e.chain === 'relay');
  const zcash = events.filter(e => e.chain === 'zcash').sort((a, b) => a.height - b.height);
  const find = (kind) => events.find(e => e.chain === 'ethereum' && e.event === kind);
  const locked = find('locked'), claimed = find('claimed'), refunded = find('refunded'), withdrawn = find('withdrawn');
  const shielded = zcash.filter(e => !e.transparent_outputs.length && !e.transparent_inputs);
  const coin = zcash.find(e => e.transparent_outputs.length && !e.transparent_inputs);  // Alice's refund coin A
  const back = zcash.find(e => e.transparent_inputs);  // Her refund R, which spends A
  const refund = Boolean(refunded || coin || back);
  const opening = [
    [relay.some(e => e.kind === 'manifest'), 'Owners exchange identities', 'Each app posts its public keys; the owners compare fingerprints out of band.'],
    [relay.some(e => e.kind === 'sealed'), 'Quote, terms and both exits', 'Sealed messages only. The apps run the FROST DKG and prepare both exits before any money moves: Alice’s refund is fully signed; Bob’s claim still needs t.'],
    [shielded.length > 0, 'Alice funds the shared note', 'Alice’s app builds and proves F; Zebra checks it and mines it. No amount or address is visible.'],
  ];
  const steps = refund ? [...opening,
    ...(locked ? [
      [true, 'Bob locks ETH', 'Public on Ethereum: amount, both addresses and the point T.'],
      [Boolean(refunded), 'No reveal: Bob takes his ETH back', 'Alice never published t, so Bob refunds after the expiry.'],
      [Boolean(refunded && withdrawn), 'Bob withdraws his ETH', 'The refund only credits him in the escrow; the withdrawal pays it out.'],
    ] : [
      [true, 'Bob never locks: the ETH deadline passes', 'Nothing moved on Ethereum, so there is nothing to claim.'],
    ]),
    [Boolean(coin), 'Alice creates the coin her refund needs', 'Her private auxiliary transaction appears only now, on the refund path.'],
    [Boolean(back), 'Alice’s ZEC comes back', 'Her pre-signed refund R is valid only after the refund time, which Zebra enforces.'],
  ] : [...opening,
    [Boolean(locked), 'Bob locks ETH', 'Bob’s app checks F on Zcash, then locks the ETH in the escrow. Public: amount, both addresses and the point T.'],
    [Boolean(claimed), 'Alice claims the ETH and reveals t', 'Alice’s app sends claim(t); the escrow checks t·G = T on Pallas. The same t completes the FROST pre-signature on Bob’s Zcash claim.'],
    // Bob's claim is the second shielded transaction, later in the chain than the funding.
    [Boolean(claimed) && shielded.length >= 2 && shielded[1].height > shielded[0].height, 'Bob claims his ZEC', 'Bob’s app reads t, completes its signature (s = ŝ + t), proves C and sends it; his own wallet decrypts the payout.'],
    [Boolean(withdrawn), 'Alice withdraws the ETH', 'Settled. No transparent output ever appeared on Zcash.'],
  ];
  const done = steps.every(s => s[0]);
  if (done) return {done, refund, locked: Boolean(locked), step: refund ? 'Refunded · both sides' : `Settled · ${steps.length} of ${steps.length}`, caption: steps[steps.length - 1][2]};
  const next = steps.findIndex(s => !s[0]);
  return {done, refund, locked: Boolean(locked), step: `Step ${next + 1} of ${steps.length} · ${steps[next][1]}`, caption: steps[next][2]};
}

const SCENARIOS = {success: 'The swap', crash: 'Bob’s app crashes', refund: 'Both refund'};
const RECORD = new URLSearchParams(location.search).has('record');
if (RECORD) document.body.classList.add('record');
// Each app reports its page height; outside ?record its frame takes that height,
// so the page scrolls once and no column scrolls on its own.
addEventListener('message', (event) => {
  if (RECORD || !event.data || event.data.zatomic !== 'height') return;
  for (const role of ['alice', 'bob']) {
    const frame = $(`#${role}-frame`);
    if (event.source !== frame.contentWindow || !frame.src || event.origin !== new URL(frame.src).origin) continue;
    const height = Number(event.data.height);
    if (Number.isFinite(height) && height > 0) frame.style.height = `${Math.min(Math.max(height, 320), 8000)}px`;
  }
});
const clock = (seconds) => `${Math.floor(seconds / 60)}:${String(seconds % 60).padStart(2, '0')}`;

// The end of a trade. The chain lines come from public data; the amounts and
// receive addresses stay inside the apps. An Autoplay that ran to the end
// waited for each app to confirm its own payout, so it can say so.
function summary(state, story) {
  const find = (kind) => state.events.find(e => e.chain === 'ethereum' && e.event === kind);
  const locked = find('locked');
  const relay = state.events.filter(e => e.chain === 'relay');
  const sealed = relay.filter(e => e.kind === 'sealed').length;
  const s = state.scenario;
  const took = s && s.ended && s.ended >= s.started ? ` · ${clock(s.ended - s.started)}` : '';
  const amount = locked ? eth(locked.amount_wei) : 'the ETH';
  const lines = !story.refund ? [
    `Alice: claimed ${amount} with t on Anvil and withdrew it.`,
    'Bob: his claim C, completed with that t, was mined on Zebra.',
  ] : locked ? [
    `Bob: refunded and withdrew ${amount} on Anvil. No secret was revealed.`,
    'Alice: her time-locked refund R was mined on Zebra after its lock time.',
  ] : [
    'Bob never locked, so nothing moved on Ethereum and no secret was revealed.',
    'Alice: her time-locked refund R was mined on Zebra after its lock time.',
  ];
  if (s && s.confirmed) lines.push(story.refund
    ? 'Both apps confirmed it themselves: Bob’s ETH is withdrawn, and Alice’s wallet decrypted her returned shielded ZEC.'
    : 'Both apps confirmed it themselves: Alice’s ETH withdrawal is checked, and Bob’s wallet decrypted his shielded ZEC.');
  if ((state.interrupted || []).includes('bob')) lines.push(story.refund
    ? 'Bob’s app was stopped during the trade. Neither refund needed anything from the other side.'
    : 'Bob’s app was killed mid-swap. It resumed from its own journal and claimed with t from Ethereum, needing nothing from Alice.');
  lines.push(`The relay carried ${sealed} sealed messages and never saw the trade amounts. The exact ZEC amount appears only inside the apps.`);
  return {title: (story.refund ? (locked ? 'Both assets recovered' : 'Alice’s ZEC recovered') : 'Swap settled') + took, lines};
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
// Starting one needs no controls; the server runs one scenario at a time.
let ownStart = 0, ownRun = 0;
async function play(path) {
  const fresh = Boolean(latest && latest.finished);
  const status = $('#ctl-status');
  try {
    status.textContent = `Starting: ${SCENARIOS[path]}${fresh ? ' (new trade)' : ''}…`;
    ownStart = latest ? latest.now - 5 : 0;
    await send({action: 'autoplay', path, fresh, lease: lease.get()});
  } catch (error) {
    status.textContent = error.message;
  }
  poll();
}
function newTrade(ask) {
  if (ask && !RECORD && !confirm('Start a new trade? The current one stays on disk.')) return;
  control({action: 'new-trade'}, 'New trade');
}
document.querySelectorAll('[data-play]').forEach(b => b.addEventListener('click', () => play(b.dataset.play)));
document.querySelectorAll('[data-scenario]').forEach(b => b.addEventListener('click', () => play(b.dataset.scenario)));
// /stage#crash (or #success, #refund) points at that scenario without starting it.
const PICK = Object.hasOwn(SCENARIOS, location.hash.slice(1)) ? location.hash.slice(1) : '';
document.querySelectorAll('[data-scenario], [data-play]').forEach(b => b.classList.toggle('is-pick', (b.dataset.scenario || b.dataset.play) === PICK));
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
  // Anyone may start a scenario while none is running. Operating the apps by
  // hand (Advanced controls) still goes to one visitor at a time.
  const running = Boolean(state.autoplay);
  const byHand = Boolean(state.public && driver && !driver.mine);
  if (state.public && !(driver && driver.mine)) lease.set('');
  for (const b of document.querySelectorAll('[data-play]')) b.disabled = running || byHand;
  for (const b of document.querySelectorAll('.ctl-advanced button')) b.disabled = byHand || (running && !(driver && driver.mine));
  const bob = state.running ? state.running.bob : true;
  document.querySelector('[data-control="crash"]').disabled ||= !bob;
  document.querySelector('[data-control="restart"]').disabled ||= bob;
  const who = $('#ctl-driver');
  who.hidden = !(state.public && driver && driver.mine && !running);
  who.textContent = 'You are operating the apps by hand; others can watch. This frees up after five idle minutes.';
  const iso = state.isolation || {};
  $('#iso').textContent = !iso.proven ? 'Checking that neither app can read the other’s files…'
    : iso.by === 'users' ? '✓ Checked: each app runs as its own Linux user; neither can read the other’s files.'
    : '✓ Checked: the OS sandbox stops each app reading the other’s files.';
  const status = $('#ctl-status');
  if (state.autoplay) status.textContent = `Autoplay running: ${SCENARIOS[state.autoplay]}`;
  else if (status.textContent.startsWith('Autoplay running')) status.textContent = 'Autoplay finished';
  // A stopped app shows a notice. A frame (re)loads only once its app's server
  // answers: after a restart or a new trade, and when the driver's lease changes.
  for (const role of ['alice', 'bob']) {
    const up = !state.running || state.running[role] !== false;
    const ready = state.ready ? state.ready[role] : up;
    const frame = $(`#${role}-frame`);
    const key = driver && driver.mine ? lease.get() : '';
    frame.closest('.stage-app').classList.toggle('is-down', !up);
    if (ready && (shown.generation !== state.generation || !shown.ready[role] || shown.lease[role] !== key)) {
      frame.src = `${state.apps[role]}/?embed=1${RECORD ? '' : '&fit=1'}${key ? '&lease=' + encodeURIComponent(key) : ''}`;
      shown.lease[role] = key;
    }
    shown.ready[role] = ready;
  }
  shown.generation = state.generation;
  const names = {};
  for (const [role, address] of Object.entries(state.owners)) names[address.toLowerCase()] = role === 'alice' ? 'Alice' : 'Bob';
  names.alice = 'Alice'; names.bob = 'Bob';
  $('#network-dot').className = 'online';
  $('#network-status').textContent = `Zebra regtest #${state.zcash_height}`;
  const story = narrate(state.events);
  state.finished = story.done;
  const begun = state.events.some(e => e.chain === 'relay' && e.kind === 'sealed');
  const ready = !begun && !story.done && !state.autoplay;
  const step = ready ? 'Both apps are ready' : story.step;
  const caption = ready ? 'Each has posted its public keys. Nothing else has crossed between them yet.' : story.caption;
  if ($('#stage-step').textContent !== step) $('#stage-step').textContent = step;
  if ($('#stage-caption').textContent !== caption) $('#stage-caption').textContent = caption;
  // What the middle column offers: a scenario to start, a running clock, a
  // nudge for a trade left part-way, or the result.
  const last = state.events.length ? state.events[state.events.length - 1].at : state.now;
  const s = state.scenario;
  // The scenario picker is the way in, also after a finished run. Someone
  // watching a run they did not start sees why the picker is locked.
  // A recording (?record, driven by keys 1-3) ends on the result, not the picker.
  $('#start').hidden = running || (begun && !story.done) || (RECORD && story.done);
  for (const b of document.querySelectorAll('[data-scenario]')) b.disabled = running || byHand;
  if (s && ownStart && s.started >= ownStart) ownRun = s.started;
  const theirs = running && !(s && s.started === ownRun);
  $('#watch-note').hidden = !(theirs || byHand);
  $('#watch-text').textContent = theirs ? `A live demo is running: “${SCENARIOS[state.autoplay]}”. You can watch it here; the scenarios free up when it ends.`
    : byHand ? `Someone is operating the apps by hand until ${utc(driver.until)} UTC. You can watch; the scenarios free up then.` : '';
  $('#start-lead').textContent = `${story.done ? 'Pick one to run a new trade.' : 'Pick what to see.'} It operates both owner apps for you: each signs with its own keys and sends real, proved transactions to private Zebra and Anvil chains. About two minutes, mostly proving.`;
  $('#start-note').hidden = story.done || running || byHand;
  $('#start-note').textContent = state.public ? 'Or open Advanced controls to operate both apps by hand.' : 'Or press the highlighted button in each app yourself.';
  $('#resume').hidden = running || byHand || !begun || story.done || state.now - last < 90;
  $('#stage-clock').hidden = !state.autoplay || !s;
  if (state.autoplay && s) $('#stage-clock').textContent = `Autoplay · ${SCENARIOS[s.path]} · ${clock(Math.max(0, state.now - s.started))}`;
  $('#result').hidden = !story.done;
  if (!story.done) shown.result = false;
  $('.stage-wire').classList.toggle('is-start', !$('#start').hidden && !story.done);
  $('.stage-wire').classList.toggle('is-done', story.done);
  if (story.done) {
    const {title, lines} = summary(state, story);
    $('#result-title').textContent = `Last run · ${title}`;
    if ($('#result-list').dataset.key !== JSON.stringify(lines)) {
      $('#result-list').dataset.key = JSON.stringify(lines);
      $('#result-list').replaceChildren(...lines.map(line => el('li', '', line)));
    }
    if (RECORD && !shown.result) requestAnimationFrame(() => $('#result').scrollIntoView({block: 'nearest'}));
    shown.result = true;
  }
  sequence(state, story);
  // Relay envelopes fold into one row; the chain events follow in protocol order.
  const relay = state.events.filter(e => e.chain === 'relay');
  const identities = relay.filter(e => e.kind === 'manifest').length;
  $('#relay-box').hidden = !relay.length;
  $('#relay-count').textContent = `Relay · ${relay.length} message${relay.length === 1 ? '' : 's'}`;
  $('#relay-split').textContent = `${identities} public ${identities === 1 ? 'identity' : 'identities'} · ${relay.length - identities} sealed`;
  const relayList = $('#relay-list');
  if (relayList.childElementCount !== relay.length) relayList.replaceChildren(...relay.map(e => item(describe(e, names), true)));
  const wire = $('#wire');
  const entries = inOrder(state.events);
  // A recording starts each trade at the top of the column.
  if (RECORD && !entries.length && !story.done && $('.stage-wire').scrollTop) $('.stage-wire').scrollTo({top: 0});
  const refunding = entries.some(x => x.role === 'refunded' || x.role === 'A' || x.role === 'R');
  const STEP = {F: '2', locked: '3', claimed: '4', C: '5', refunded: '↩', A: '↩', R: '↩', withdrawn: refunding ? '↩' : '4'};
  $('#receipts-head').hidden = !relay.length && !entries.length;
  const key = entries.map(x => x.i).join(',');
  if (wire.dataset.key !== key) {
    // Events only accumulate; fewer of them means a new network.
    if (entries.length < wire.childElementCount) shown.events = new Set();
    wire.dataset.key = key;
    wire.replaceChildren(...entries.map(x => item(describe(x.e, names, x.role), shown.events.has(x.i), STEP[x.role])));
    for (const x of entries) shown.events.add(x.i);
    wire.scrollTop = wire.scrollHeight;
    // A recording keeps the newest receipt in view, under the step it lit.
    if (RECORD && entries.length && !story.done) requestAnimationFrame(() => $('.stage-wire').scrollTo({top: $('.stage-wire').scrollHeight, behavior: 'smooth'}));
  }
  const zcash = state.events.filter(e => e.chain === 'zcash');
  const ethEvents = state.events.filter(e => e.chain === 'ethereum');
  const sealed = state.events.filter(e => e.chain === 'relay' && e.kind === 'sealed').length;
  const transparent = zcash.filter(e => e.transparent_outputs.length).length;
  $('#obs-zec').textContent = `${zcash.length} transaction${zcash.length === 1 ? '' : 's'}`;
  $('#obs-zec-note').textContent = transparent ? `refund path: ${transparent} transparent output${transparent === 1 ? '' : 's'} so far` : 'all shielded: no amount, address or transparent output';
  const locked = ethEvents.find(e => e.event === 'locked');
  $('#obs-eth').textContent = locked ? eth(locked.amount_wei) : 'nothing yet';
  $('#obs-eth-note').textContent = ethEvents.map(e => e.event).join(' → ') || 'public by design';
  $('#obs-relay').textContent = `${sealed} sealed`;
}

// The five-step diagram, lit from public events only: done, the step under
// way, still to come, or the branch this trade did not take.
function sequence(state, story) {
  const ev = state.events;
  const zcash = ev.filter(e => e.chain === 'zcash');
  const has = (kind) => ev.some(e => e.chain === 'ethereum' && e.event === kind);
  const funded = zcash.some(e => !e.transparent_outputs.length && !e.transparent_inputs);
  const shielded = zcash.filter(e => !e.transparent_outputs.length && !e.transparent_inputs).length;
  const coin = zcash.some(e => e.transparent_outputs.length && !e.transparent_inputs);
  const back = zcash.some(e => e.transparent_inputs);
  const sealed = ev.some(e => e.chain === 'relay' && e.kind === 'sealed');
  const begun = sealed || Boolean(state.autoplay);
  const path = story.refund || (state.scenario && state.scenario.path === 'refund' && !has('claimed')) ? 'refund'
    : has('claimed') || (state.scenario && state.scenario.path !== 'refund') ? 'swap' : '';
  const done = {1: sealed || funded, 2: funded, 3: has('locked'), 4: has('claimed'), 5: has('claimed') && shielded >= 2,
    settled: has('claimed') && shielded >= 2 && has('withdrawn'), refund: has('refunded') || coin || back,
    'eth-back': has('refunded'), 'zec-back': back};
  const order = path === 'refund' ? ['1', '2', '3', 'eth-back', 'zec-back'] : ['1', '2', '3', '4', '5'];
  const now = begun ? order.find(s => !done[s]) : undefined;
  const off = path === 'refund' ? ['4', '5', 'settled'] : path === 'swap' ? ['refund', 'eth-back', 'zec-back'] : [];
  for (const g of document.querySelectorAll('#stage-seq .sq-step')) {
    const s = g.dataset.step;
    const lit = done[s] || (s === 'refund' && path === 'refund') || (s === 'settled' && done.settled);
    g.setAttribute('class', `sq-step ${off.includes(s) ? 'is-off' : s === now ? 'is-now' : lit ? 'is-done' : 'is-todo'}`);
  }
  // An SVG element has no hidden property, so toggle the attribute itself.
  $('#sq-bob-down').toggleAttribute('hidden', !(state.running && state.running.bob === false));
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
