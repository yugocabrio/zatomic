'use strict';
// Every displayed state is derived from the server snapshot, which reads the
// run's own public stage records. Nothing here simulates progress.
const $ = (selector) => document.querySelector(selector);
const LIMITS = {
  zec: {decimals: 8, max: 10n ** 8n, unit: 'ZEC', cap: '1 ZEC'},
  eth: {decimals: 18, max: 10n * 10n ** 18n, unit: 'ETH', cap: '10 ETH'},
};
const SCENARIO_NAMES = {'success': 'Complete the exchange', 'claim-stop': 'Stop after the reveal', 'refund-stop': 'Stop before any reveal'};
let snapshot = null;
let offline = false;
let pending = null;
let drafting = false;
let shownQuote = null;
let receiptKey = '';
const touched = {zec: false, eth: false};

function setText(target, value) {
  const node = typeof target === 'string' ? $(target) : target;
  if (node.textContent !== value) node.textContent = value;
}
function show(selector, visible) { $(selector).hidden = !visible; }
function short(hash) { return hash && hash.length > 20 ? `${hash.slice(0, 10)}…${hash.slice(-6)}` : (hash || ''); }
function clock(seconds) {
  const m = Math.floor(seconds / 60);
  return m ? `${m}m ${String(seconds % 60).padStart(2, '0')}s` : `${seconds}s`;
}
function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

// Exact decimal parsing with BigInt; mirrors the server's canonical rules.
function parseAmount(raw, kind) {
  const {decimals, max, unit, cap} = LIMITS[kind];
  const text = raw.trim();
  if (!text) return {error: `Enter a ${unit} amount.`};
  if (!/^\d+(\.\d+)?$/.test(text)) return {error: 'Use a plain decimal number, such as 0.05.'};
  if (/^0\d/.test(text)) return {error: 'Remove the leading zero.'};
  const [whole, fraction = ''] = text.split('.');
  if (fraction.length > decimals) return {error: `${unit} supports at most ${decimals} decimal places.`};
  const value = BigInt(whole) * 10n ** BigInt(decimals) + BigInt(fraction.padEnd(decimals, '0') || '0');
  if (value === 0n) return {error: 'Must be more than zero.'};
  if (value > max) return {error: `This local demo allows at most ${cap}.`};
  return {text, value};
}
function formatScaled(value, decimals) {
  const base = 10n ** BigInt(decimals);
  const fraction = (value % base).toString().padStart(decimals, '0').replace(/0+$/, '');
  return `${value / base}${fraction ? '.' + fraction : ''}`;
}
function priceText(zat, wei) {
  // ETH per ZEC = wei / (zat * 1e10); shown truncated to 8 decimals.
  const scaled = wei / (zat * 100n);
  return scaled === 0n ? '< 0.00000001' : formatScaled(scaled, 8);
}

function validate(showAll) {
  const result = {};
  for (const kind of ['zec', 'eth']) {
    const input = $(`#${kind}-amount`);
    const parsed = parseAmount(input.value, kind);
    result[kind] = parsed;
    const visible = (showAll || touched[kind]) && parsed.error;
    input.closest('.field').classList.toggle('is-invalid', !!visible);
    input.setAttribute('aria-invalid', visible ? 'true' : 'false');
    show(`#${kind}-error`, !!visible);
    setText(`#${kind}-error`, visible ? parsed.error : '');
    input.classList.toggle('is-long', input.value.length > 13);
  }
  const preview = $('#price-preview');
  if (!result.zec.error && !result.eth.error) {
    preview.replaceChildren('Implied price ', el('b', '', `≈ ${priceText(result.zec.value, result.eth.value)} ETH per ZEC`), ' · set by the two peers');
  } else preview.textContent = '';
  return result;
}

function phaseOf(job) {
  if (!job) return 'draft';
  if (['offered', 'accepted', 'running', 'recovering', 'complete'].includes(job.state)) return job.state;
  return 'stopped';
}

function model(job) {
  const ev = new Map((job?.events || []).map(e => [e.stage, e.value]));
  const done = ev.get('08-complete');
  const cancelled = done?.unfunded_cancelled === true;
  const fundingOnly = (ev.get('09-recovered') || done)?.eth_not_locked === true;
  const refund = !cancelled && !fundingOnly && (ev.has('05-eth-refunded') || ev.has('06-zec-refunded') || done?.mode === 'refund'
    || (job?.scenario === 'refund-stop' && !ev.has('05-eth-claimed')));
  // 09-recovered is written by any recovery invocation, including a replay on
  // a run that never stopped. Only a stop scenario or a browser-started
  // recovery means the run was actually finished by recovery.
  const stopped = job?.scenario !== 'success' || !!job?.recovery_started_at;
  const recoveredRecord = ev.has('09-recovered');
  return {ev, cancelled, fundingOnly, refund, recovered: recoveredRecord && stopped, replayed: recoveredRecord && !stopped, milestones: job?.milestones || {}};
}

function stepsFor(job, m, phase) {
  const {ev, refund, fundingOnly, cancelled, milestones} = m;
  const legacy = job && !String(job.driver || '').startsWith('owner-consent');
  const prepared = ev.get('01-prepared');
  const consented = ev.get('01-consented');
  const funded = ev.get('02-funded');
  const locked = ev.get('04-eth-locked');
  const revealed = ev.get(refund ? '05-eth-refunded' : '05-eth-claimed');
  const exit = ev.get(refund ? '06-zec-refunded' : '06-zec-claimed')
    || (fundingOnly ? {txid: (ev.get('09-recovered') || ev.get('08-complete'))?.native_txid} : null);
  const complete = ev.get('08-complete');
  const receiver = refund || fundingOnly ? 'Alice' : 'Bob';
  const steps = [
    {key: 'prepare', title: 'Exits prepared and verified', done: !!prepared, label: 'Verified',
      detail: prepared ? `Claim pre-signed for Bob, refund signed and time-locked for Alice; both owners saved their bundle. Refund unlocks after local block #${prepared.refund_height}.` : '',
      sub: [['Run set up with both owners’ pinned identities', milestones.setup_started], ['Fresh 2-of-2 spend key from FROST DKG', milestones.dkg_complete], ['Claim and refund signed, proved and saved by both owners', !!prepared]]},
    {key: 'consent', title: legacy ? 'Owner signatures (not in this older run)' : 'Both owners signed the full terms', done: !!consented, skipped: legacy, label: 'Signed',
      detail: consented ? `Agreement ${short(consented.agreement_digest)} covers amounts, escrow, deadlines and both exits. Zebra rejected the unsigned funding preview.` : '',
      sub: [['Escrow deployed on the local Anvil chain', milestones.escrow_deployed], ['Alice and Bob signed the agreement', !!consented]]},
    {key: 'fund', title: 'ZEC funding confirmed', done: !!funded, label: 'Confirmed',
      detail: funded ? `Tx ${short(funded.txid)} · ${funded.confirmations} local confirmations` : ev.has('01-authorized') ? 'Alice’s wallet signed the funding after checking both consents.' : ''},
    {key: 'lock', title: fundingOnly ? 'ETH never locked' : 'ETH locked in escrow', done: !!locked, skipped: fundingOnly, label: 'Locked',
      detail: locked ? `Tx ${short(locked.txid)} · signed by Bob’s own client` : fundingOnly ? 'Bob kept his ETH; nothing to refund on Ethereum.' : ''},
    {key: 'reveal', title: refund ? 'ETH refunded to Bob at expiry' : fundingOnly ? 'No reveal needed' : 'Secret revealed on Ethereum', done: !!revealed, skipped: fundingOnly, label: refund ? 'Refunded' : 'Revealed',
      detail: revealed ? (refund ? `Tx ${short(revealed.txid)} · no secret was ever revealed` : `Tx ${short(revealed.txid)} · Alice’s claim made t public and credited her ETH`) : ''},
    {key: 'exit', title: `${receiver}’s ZEC ${refund || fundingOnly ? 'refund' : 'claim'} confirmed`, done: !!exit?.txid, label: 'Confirmed',
      detail: exit?.txid ? `Tx ${short(exit.txid)} · ${exit.confirmations || 2} local confirmations · decrypted by ${receiver}’s wallet` : ''},
    {key: 'verify', title: fundingOnly ? 'Refund verified' : 'Both receipts verified', done: !!complete && !cancelled, label: 'Verified',
      detail: complete?.eth_withdraw_tx ? `ETH withdrawal ${short(complete.eth_withdraw_tx)} · exact amount checked`
        : fundingOnly && complete ? 'Alice’s wallet decrypted the refund; no ETH transaction was needed.' : ''},
  ];
  if (cancelled) {
    for (const step of steps) if (!step.done) { step.skipped = true; step.detail = ''; }
    steps[6].title = 'Offer closed before funding'; steps[6].done = true; steps[6].skipped = false; steps[6].label = 'Closed';
    steps[6].detail = 'No swap funds were locked on either chain.';
  }
  const active = steps.findIndex(s => !s.done && !s.skipped);
  steps.forEach((step, i) => {
    step.state = step.done ? 'done' : step.skipped ? 'skipped'
      : i === active && (phase === 'running' || phase === 'recovering') ? 'active'
      : i === active && phase === 'stopped' ? 'paused' : 'waiting';
  });
  // The witness is public but Bob's claim is not yet confirmed: the one
  // window where the honest party must act. Make it unmistakable.
  if (!refund && !fundingOnly && ev.has('05-eth-claimed') && !ev.has('06-zec-claimed') && phase === 'stopped') steps[5].state = 'critical';
  return {steps, active};
}

function renderSteps(job, m, phase) {
  const {steps, active} = stepsFor(job, m, phase);
  const list = $('#steps');
  const key = JSON.stringify(steps.map(s => [s.title, s.state, s.detail, (s.sub || []).map(x => x[1])])) + phase;
  if (list.dataset.key !== key) {
    list.dataset.key = key;
    list.replaceChildren(...steps.map((step, i) => {
      const item = el('li', `step is-${step.state}`);
      const states = {done: step.label, active: phase === 'recovering' ? 'Recovering' : 'In progress', paused: 'Stopped here', critical: 'Bob must claim', skipped: 'Not needed', waiting: 'Waiting'};
      item.append(el('span', 'step-mark', step.done ? '✓' : String(i + 1)), el('span', 'step-title', step.title), el('span', 'step-state', states[step.state]));
      if (step.detail) item.append(el('span', 'step-detail', step.detail));
      if (step.sub && (step.state === 'active' || step.state === 'paused')) {
        const sub = el('ul', 'step-sub');
        const next = step.sub.findIndex(([, ok]) => !ok);
        step.sub.forEach(([label, ok], j) => sub.append(el('li', ok ? 'is-done' : j === next && step.state === 'active' ? 'is-active' : '', label)));
        item.append(sub);
      }
      if (step.state === 'active') item.setAttribute('aria-current', 'step');
      return item;
    }));
  }
  // Expanded while settling or stopped; collapsed to a summary once complete,
  // unless the viewer opened it themselves.
  const wrap = $('#steps-wrap');
  const done = steps.filter(s => s.done).length;
  setText('#steps-summary', phase === 'complete' ? `How it settled · ${done} recorded steps` : 'Settlement steps');
  if (wrap.dataset.phase !== phase) {
    wrap.dataset.phase = phase;
    if (!wrap.dataset.userToggled) wrap.open = phase !== 'complete';
  }
  const counted = steps.filter(s => s.done || s.skipped).length;
  $('#meter-fill').style.width = `${Math.round(counted / steps.length * 100)}%`;
  return {steps, active};
}

function recoveryView(job, m) {
  const {ev, milestones} = m;
  const prepared = ev.get('01-prepared');
  const height = snapshot?.node?.height;
  const deadline = prepared ? `Native refund deadline: local block #${prepared.refund_height}${height ? ` (now #${height})` : ''}.` : null;
  const error = job.state === 'error';
  const kicker = error ? 'Stopped by an error' : 'Stopped at the demo checkpoint';
  if (job.cancellable_setup) return {kicker, title: 'Stopped before the ZEC funding was released.', copy: 'Alice’s wallet never released the funding and Bob locked no ETH. Cancelling closes this offer for good; it can never be funded afterwards.', facts: ['Swap funds locked: none.', 'Setup files stay private on this machine.'], button: 'Cancel this offer', can: true};
  if (!job.recoverable) return {kicker, title: 'Stopped without a supported recovery point.', copy: 'State is preserved as it was. This checkpoint has no automatic action, so none is offered. Read the private runner log and docs/process-recovery.md before acting.', facts: [], can: false};
  if (ev.has('05-eth-claimed')) return {kicker, title: 'Stopped after the secret went public.', copy: 'Alice’s ETH claim is on Ethereum, so t is public. Bob’s prepared claim only needed t. Recovery restarts Bob’s client with Alice offline and completes his shielded ZEC claim.', facts: ['No new signature from Alice is needed.', deadline].filter(Boolean), button: 'Restart and recover', can: true};
  if (milestones.claim_intent) return {kicker, title: 'Stopped while Alice was claiming.', copy: 'Alice’s claim may already be public, so a refund is never chosen. Recovery replays her exact signed claim, then completes Bob’s ZEC claim.', facts: [deadline].filter(Boolean), button: 'Restart and recover', can: true};
  if (ev.has('04-eth-locked')) return {kicker, title: 'Stopped before any secret was revealed.', copy: 'Recovery first checks Alice’s own journal for any claim attempt. With none, Bob refunds his ETH at expiry and Alice broadcasts her prepared ZEC refund after the native deadline. This demo advances its local clocks to get there.', facts: [deadline].filter(Boolean), button: 'Restart and recover', can: true};
  if (milestones.lock_intent) return {kicker, title: 'Stopped while Bob was locking ETH.', copy: 'Bob’s lock may have been sent before its receipt was saved. Recovery replays his exact signed transaction and reconciles it before settling or refunding.', facts: [deadline].filter(Boolean), button: 'Restart and recover', can: true};
  if (milestones.source_released || ev.has('02-funded')) return {kicker, title: 'ZEC was funded; ETH was never locked.', copy: 'Funding was already committed. Recovery re-broadcasts the exact signed funding if needed, then returns Alice’s ZEC with her prepared refund after the deadline. No ETH transaction is sent.', facts: [deadline].filter(Boolean), button: 'Restart and recover', can: true};
  return {kicker, title: 'Stopped. Recovery data is in place.', copy: 'Recovery restarts the owners’ clients from their saved journals and reconciles both chains before acting.', facts: [deadline].filter(Boolean), button: 'Restart and recover', can: true};
}

function outcomeView(job, m) {
  const quote = job.quote || {};
  const zec = job.settled_amounts?.zec || quote.zec_amount || '—';
  const eth = job.settled_amounts?.eth || quote.eth_amount || '—';
  const replay = m.recovered ? 'Finished by recovery after the stop. Running recovery again sends no second payment.'
    : m.replayed ? 'Recovery was also replayed on this completed run; it reconciles instead of paying twice.'
    : 'Recovery can be replayed safely; it reconciles instead of paying twice.';
  if (m.cancelled) return {neutral: true, title: 'Offer closed before funding', cells: [['ZEC funded', 'None', 'Source authorization permanently disabled'], ['ETH locked', 'None', 'No escrow deposit was made']], note: 'No cancellation transaction is needed. A local wallet or empty escrow from setup may still exist.'};
  if (m.fundingOnly) return {title: 'ZEC returned; ETH never locked', cells: [['Alice got back', `${zec} ZEC`, 'Her prepared refund, decrypted by her wallet'], ['Bob kept', `${eth} ETH`, 'It was never locked']], note: replay};
  if (m.refund) return {title: 'Both original assets returned', cells: [['Alice got back', `${zec} ZEC`, 'Prepared refund; decrypted by her wallet'], ['Bob got back', `${eth} ETH`, 'Refunded at expiry, then withdrawn']], note: `No secret was revealed. ${replay}`};
  return {title: 'Exchange complete', cells: [['Bob received', `${zec} ZEC`, 'Shielded note, decrypted by Bob’s wallet'], ['Alice received', `${eth} ETH`, 'Withdrawn to her fixed address; exact amount']], note: replay};
}

function boardTitle(job, m, phase, active) {
  if (phase === 'draft') return 'Waiting for an accepted quote';
  if (phase === 'offered') return 'Waiting for Bob to accept';
  if (phase === 'accepted') return 'Ready to fund. Nothing is locked yet.';
  if (phase === 'running' || phase === 'recovering') {
    // cancellable_setup is also true mid-setup; only recovery cancels.
    if (phase === 'recovering' && job.cancellable_setup) return 'Closing the offer before funding…';
    const running = m.refund
      ? ['Preparing both exits…', 'Collecting both owners’ signatures…', 'Funding the shielded ZEC…', 'Locking ETH…', 'Waiting for ETH expiry, then refunding…', 'Returning Alice’s ZEC…', 'Verifying both refunds…']
      : ['Preparing both exits…', 'Collecting both owners’ signatures…', 'Funding the shielded ZEC…', 'Locking ETH…', 'Revealing the secret on Ethereum…', 'Completing Bob’s ZEC claim…', 'Verifying both receipts…'];
    return phase === 'recovering' ? `Recovery · ${running[active] || 'Reconciling…'}` : (running[active] || 'Settling…');
  }
  if (phase === 'complete') return outcomeView(job, m).title;
  return recoveryView(job, m).title;
}

function pillFor(job, m, phase) {
  if (offline) return ['Server offline', 'is-bad'];
  switch (phase) {
    case 'draft': return ['Idle', ''];
    case 'offered': return ['Quote signed', ''];
    case 'accepted': return ['Accepted', ''];
    case 'running': return ['Live · local chains', 'is-live'];
    case 'recovering': return ['Recovering', 'is-live'];
    case 'complete': return [m.cancelled ? 'Cancelled' : m.refund || m.fundingOnly ? 'Refunded' : 'Settled', m.cancelled ? '' : 'is-ok'];
    default: return [job.state === 'error' ? 'Needs attention' : 'Stopped', job.state === 'error' ? 'is-bad' : 'is-warn'];
  }
}

function renderTicket(job, phase) {
  const quote = job?.quote;
  const unresolved = (snapshot?.jobs || []).some(j => j.blocks_new_offer && j.state !== 'running' && j.state !== 'recovering');
  const settled = ['running', 'recovering', 'stopped', 'complete'].includes(phase);
  const canDraft = phase === 'draft' || drafting;
  const stage = canDraft ? 'quote' : phase === 'offered' ? 'accept' : phase === 'accepted' ? 'fund' : 'none';
  const order = ['quote', 'accept', 'fund'];
  const current = order.indexOf(stage);
  document.querySelectorAll('.agree-step').forEach((item, i) => {
    const isDone = settled && !drafting ? true : current >= 0 ? i < current : false;
    item.classList.toggle('is-current', i === current);
    item.classList.toggle('is-done', isDone);
    item.classList.toggle('is-locked', !isDone && i !== current);
    item.querySelector('.agree-mark').textContent = isDone ? '✓' : String(i + 1);
  });
  show('#quote-form', canDraft);
  show('#quote-body', canDraft);
  show('#review-body', stage === 'accept');
  show('#fund-body', stage === 'fund');

  const busy = !!pending || !!snapshot?.busy || offline;
  for (const id of ['#zec-amount', '#eth-amount']) $(id).disabled = !canDraft || busy;
  $('#create-offer').disabled = busy || !snapshot?.ready || unresolved;
  $('#accept-offer').disabled = busy;
  $('#new-offer').disabled = busy;
  $('#start').disabled = busy || !snapshot?.ready || unresolved;
  document.querySelectorAll('input[name="scenario"]').forEach(input => { input.disabled = busy; });
  setBusy('#create-offer', pending === 'offer', 'Signing as Alice…', 'Sign quote as Alice');
  setBusy('#accept-offer', pending === 'accept', 'Accepting…', 'Accept as Bob');
  setText('#start-label', pending === 'start' ? 'Starting…' : 'Authorize and fund');
  $('#start').classList.toggle('is-busy', pending === 'start');

  const summary = (selector, visible, nodes) => { show(selector, visible); if (visible) $(selector).replaceChildren(...nodes); };
  const quoteDone = quote && !canDraft;
  summary('#quote-summary', quoteDone, quoteDone ? [`Alice signed: Bob receives ${quote.zec_amount} ZEC, Alice receives ${quote.eth_amount} ETH. `, el('code', '', `quote ${short(quote.quote_digest)}`)] : []);
  summary('#accept-summary', !!quote?.bob_accepted && !canDraft, ['Bob verified Alice’s signature and signed his acceptance.']);
  // Starting a run is only a request; the owners' consent record is the authorization.
  const consented = (job?.events || []).some(e => e.stage === '01-consented');
  const outcome = SCENARIO_NAMES[job?.scenario] || job?.scenario || '';
  summary('#fund-summary', settled && !drafting, [consented ? `Both owners signed the full terms · demo outcome: ${outcome}` : `Funding requested; owners have not signed the full terms yet · demo outcome: ${outcome}`]);
  setText('#quote-state', quoteDone ? 'Signed' : '');
  setText('#accept-state', quote?.bob_accepted && !canDraft ? 'Accepted' : stage === 'accept' ? 'Bob to act' : '');
  setText('#fund-state', settled && !drafting ? (consented ? 'Signed' : 'Requested') : stage === 'fund' ? 'Both to act' : '');

  if (stage === 'accept' && quote) renderReview(quote);
  const chip = $('#ticket-chip');
  const [chipText, live] = drafting ? ['New draft', false] : {draft: ['Draft', false], offered: ['Awaiting Bob', true], accepted: ['Accepted', true],
    running: ['In settlement', true], recovering: ['Recovering', true], stopped: ['Stopped', false], complete: ['Closed', false]}[phase];
  setText(chip, chipText); chip.classList.toggle('is-live', live);

  const canStartFresh = !drafting && (phase === 'complete' || (phase === 'stopped' && !job.blocks_new_offer)) && !unresolved;
  show('#keep-offer', drafting && (phase === 'offered' || phase === 'accepted'));
  $('#keep-offer').disabled = busy;
  show('#fresh-offer', canStartFresh);
  $('#fresh-offer').disabled = busy;
  setText('#ticket-note', !snapshot ? 'Connecting to the local server…'
    : !snapshot.ready ? 'Local chains are not ready. Run make setup, then reload.'
    : snapshot.busy && !settled ? 'Another chain operation is running on this machine.'
    : unresolved && !settled ? 'An earlier run must be recovered before a new offer.'
    : phase === 'stopped' && job.blocks_new_offer ? (job.cancellable_setup ? 'Cancel or recover this run before starting another offer.' : 'Recover this run before starting another offer.')
    : 'No market price feed. Amounts are whatever the two peers agree.');
}

function setBusy(selector, active, busyLabel, label) {
  const button = $(selector);
  setText(button, active ? busyLabel : label);
  button.classList.toggle('is-busy', active);
}

function renderReview(quote) {
  const key = quote.quote_digest + String(quote.alice_address);
  const list = $('#review');
  if (list.dataset.key === key) return;
  list.dataset.key = key;
  const rows = [
    ['Bob receives', [el('strong', '', `${quote.zec_amount} ZEC`), ' shielded']],
    ['Alice receives', [el('strong', '', `${quote.eth_amount} ETH`)]],
    ['Implied price', [`${quote.indicative_eth_per_zec ? quote.indicative_eth_per_zec.replace(/\.?0+$/, '') : '—'} ETH per ZEC`]],
    ['ZEC network fees', [`${zecFees(quote.claim_fee_zec)} ZEC, paid by Alice`]],
    ['ETH goes to', [el('code', '', short(quote.alice_address || ''))]],
    ['ETH network', [quote.eth_chain_id === 31338 ? 'Local Anvil (31338)' : String(quote.eth_chain_id || '—')]],
    ['Alice’s signature', [el('span', 'verified', 'Verified ✓')]],
    ['Quote ID', [el('code', '', short(quote.quote_digest))]],
  ];
  list.replaceChildren(...rows.flatMap(([term, value]) => { const dd = el('dd'); dd.append(...value); return [el('dt', '', term), dd]; }));
}
function zecFees(claimFee) {
  // Alice pays the funding fee and the claim fee; both are the fixed
  // two-action ZIP-317 fee, so the total is twice the signed claim fee.
  if (!claimFee) return '—';
  const [whole, fraction = ''] = claimFee.split('.');
  return formatScaled(2n * (BigInt(whole) * 10n ** 8n + BigInt(fraction.padEnd(8, '0'))), 8);
}

function renderBoard(job, phase) {
  const m = model(job);
  const quote = job?.quote;
  setText('#leg-zec', quote ? `${quote.zec_amount} ZEC` : '—');
  setText('#leg-eth', quote ? `${quote.eth_amount} ETH` : '—');
  const {active} = renderSteps(job, m, phase);
  // While Alice drafts a new quote the board still shows the last run.
  setText('#board-kicker', drafting && (phase === 'complete' || phase === 'stopped') ? 'Previous run' : 'Settlement');
  setText('#live-title', boardTitle(job, m, phase, active));
  const [pill, tone] = pillFor(job, m, phase);
  const badge = $('#run-status');
  setText(badge, pill);
  badge.className = `pill ${tone}`;
  $('#board').setAttribute('aria-busy', String(phase === 'running' || phase === 'recovering'));

  show('#recovery', phase === 'stopped');
  if (phase === 'stopped') {
    const view = recoveryView(job, m);
    setText('#recovery-kicker', view.kicker);
    setText('#recovery-title', view.title);
    setText('#recovery-copy', view.copy);
    const facts = $('#recovery-facts');
    const key = view.facts.join('|');
    if (facts.dataset.key !== key) { facts.dataset.key = key; facts.replaceChildren(...view.facts.map(f => el('li', '', f))); }
    show('#recover', view.can);
    setText('#recover-label', pending === 'recover' ? 'Starting recovery…' : view.button || 'Restart and recover');
    $('#recover').disabled = !!pending || !!snapshot?.busy || offline || !job.recoverable;
    $('#recover').classList.toggle('is-busy', pending === 'recover');
  }
  show('#outcome', phase === 'complete');
  if (phase === 'complete') {
    const view = outcomeView(job, m);
    $('#outcome').classList.toggle('is-neutral', !!view.neutral);
    // The board heading already states the outcome; this panel shows the proof.
    setText('#outcome-title', view.neutral ? 'Nothing was funded' : m.refund || m.fundingOnly ? 'Verified refunds' : 'Verified on both chains');
    const grid = $('#outcome-grid');
    const key = JSON.stringify(view.cells);
    if (grid.dataset.key !== key) {
      grid.dataset.key = key;
      grid.replaceChildren(...view.cells.map(([label, value, note]) => { const cell = el('div'); cell.append(el('span', '', label), el('strong', '', value), el('small', '', note)); return cell; }));
    }
    setText('#outcome-note', view.note);
  }
  const caption = offline ? 'Connection to the local server lost. Settlement continues server-side; reload when it is back.'
    : phase === 'running' ? 'Owner clients are signing, proving and confirming on local chains.'
    : phase === 'recovering' ? 'A fresh process is restarting from the owners’ saved journals.'
    : phase === 'stopped' ? 'Runner and local EVM stopped. Recovery starts from saved state.'
    : phase === 'complete' ? 'Node confirmations, recipient decryption and the ETH withdrawal were checked.'
    : 'Every step below is read from the run’s own records.';
  setText('#live-caption', caption);
  // Settlement time excludes the time a stopped run waited for recovery.
  const now = Math.floor(Date.now() / 1000);
  const end = phase === 'running' || phase === 'recovering' ? now : (job?.updated_at || now);
  const since = job?.recovery_started_at;
  setText('#elapsed', !job?.started_at || !['running', 'recovering', 'stopped', 'complete'].includes(phase) ? ''
    : since && (phase === 'recovering' || phase === 'complete') ? `Recovery ${clock(Math.max(0, end - since))}`
    : `Elapsed ${clock(Math.max(0, end - job.started_at))}`);
  renderReceipt(job, m);
}

function renderReceipt(job, m) {
  const key = `${job?.id}:${[...m.ev.keys()].join(',')}`;
  if (key === receiptKey) return;
  receiptKey = key;
  const rows = [];
  const seen = new Set();
  const add = (chain, label, value) => { if (value && !seen.has(value)) { seen.add(value); rows.push([chain, label, value]); } };
  add('ZEC', 'Funding', m.ev.get('02-funded')?.txid);
  add('ETH', 'Escrow lock', m.ev.get('04-eth-locked')?.txid);
  add('ETH', 'Claim · reveals t', m.ev.get('05-eth-claimed')?.txid);
  add('ETH', 'Refund to Bob', m.ev.get('05-eth-refunded')?.txid);
  add('ZEC', 'Claim to Bob', m.ev.get('06-zec-claimed')?.txid);
  add('ZEC', 'Refund to Alice', m.ev.get('06-zec-refunded')?.txid);
  add('ZEC', 'Refund to Alice', (m.ev.get('09-recovered') || m.ev.get('08-complete'))?.native_txid);
  add('ETH', 'Withdrawal', m.ev.get('08-complete')?.eth_withdraw_tx);
  show('#receipt', rows.length > 0);
  setText('#receipt-detail', job ? `Run ${job.id.slice(-8)}${m.recovered ? ' · completed by recovery' : m.replayed ? ' · recovery replayed' : ''} · keys and journals stay on this machine` : '');
  $('#transactions').replaceChildren(...rows.map(([chain, label, value]) => {
    const row = el('tr');
    const chainCell = el('td'); chainCell.append(el('span', `chain chain-${chain.toLowerCase()}`, chain));
    const hashCell = el('td'); const code = el('code', '', value); code.title = value; hashCell.append(code);
    const copyCell = el('td'); const copy = el('button', 'copy', 'Copy'); copy.type = 'button';
    copy.setAttribute('aria-label', `Copy ${chain} ${label} transaction ID`);
    copy.addEventListener('click', async () => {
      try { await navigator.clipboard.writeText(value); copy.textContent = 'Copied'; }
      catch { const range = document.createRange(); range.selectNodeContents(code); const sel = getSelection(); sel.removeAllRanges(); sel.addRange(range); copy.textContent = 'Selected'; }
    });
    copyCell.append(copy);
    row.append(chainCell, el('td', '', label), hashCell, copyCell);
    return row;
  }));
}

function render() {
  const data = snapshot;
  const dot = $('#network-dot');
  dot.className = offline ? 'offline' : data?.ready ? 'online' : '';
  const status = $('#network-status');
  const label = offline ? 'Local server unreachable' : !data ? 'Checking local chains…' : !data.ready ? 'Local setup needed' : null;
  if (label) { setText(status, label); status.dataset.height = ''; status.removeAttribute('aria-label'); }
  else if (status.dataset.height !== String(data.node.height)) {
    // The long form is hidden on phones by CSS; the height stays visible.
    status.dataset.height = String(data.node.height);
    status.replaceChildren(el('span', 'net-long', 'Local chains · Zebra NU7 '), el('span', 'net-short', 'Local ZEC '), `#${data.node.height}`, el('span', 'net-long', ' · Anvil'));
    status.setAttribute('aria-label', `Local chains: Zebra NU7 regtest at height ${data.node.height}, plus Anvil`);
  }
  const job = data?.jobs?.[0] || null;
  const phase = phaseOf(job);
  if (job?.quote && shownQuote !== job.id && !drafting) {
    shownQuote = job.id;
    $('#zec-amount').value = job.quote.zec_amount;
    $('#eth-amount').value = job.quote.eth_amount;
    validate(false);
  }
  renderTicket(job, phase);
  renderBoard(job, phase);
}

let polling = false;
async function poll() {
  if (polling) return;
  polling = true;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 8000);
  try {
    const response = await fetch('/api/state', {cache: 'no-store', signal: controller.signal});
    if (!response.ok) throw new Error('state');
    snapshot = await response.json();
    offline = false;
  } catch {
    offline = true;
  } finally {
    clearTimeout(timer);
    polling = false;
  }
  render();
}

async function action(kind, path, body) {
  if (pending || !snapshot || offline) return;
  pending = kind;
  show('#action-error', false);
  render();
  try {
    const response = await fetch(path, {method: 'POST', headers: {'Content-Type': 'application/json', 'X-Latch-Token': snapshot.token}, body: JSON.stringify(body)});
    let result = {};
    try { result = await response.json(); } catch { /* non-JSON error body */ }
    if (!response.ok) throw new Error(result.error || 'The operation could not start.');
    if (kind === 'offer') drafting = false;
    return true;
  } catch (error) {
    setText('#action-error', error.message === 'Failed to fetch' ? 'The local server did not respond. Nothing new was authorized.' : error.message);
    show('#action-error', true);
    return false;
  } finally {
    pending = null;
    await poll();
  }
}

for (const kind of ['zec', 'eth']) {
  const input = $(`#${kind}-amount`);
  input.addEventListener('input', () => validate(false));
  input.addEventListener('blur', () => { touched[kind] = true; validate(false); });
}
$('#quote-form').addEventListener('submit', (event) => {
  event.preventDefault();
  touched.zec = touched.eth = true;
  const parsed = validate(true);
  if (parsed.zec.error) return $('#zec-amount').focus();
  if (parsed.eth.error) return $('#eth-amount').focus();
  action('offer', '/api/offer', {zec_amount: parsed.zec.text, eth_amount: parsed.eth.text});
});
$('#accept-offer').addEventListener('click', () => action('accept', '/api/accept', {id: snapshot?.jobs?.[0]?.id}));
$('#new-offer').addEventListener('click', () => { drafting = true; render(); $('#zec-amount').focus(); });
$('#keep-offer').addEventListener('click', () => { drafting = false; shownQuote = null; render(); });
$('#fresh-offer').addEventListener('click', () => { drafting = true; touched.zec = touched.eth = false; render(); validate(false); $('#zec-amount').focus(); });
$('#start').addEventListener('click', () => {
  const scenario = document.querySelector('input[name="scenario"]:checked')?.value || 'success';
  action('start', '/api/start', {scenario, id: snapshot?.jobs?.[0]?.id});
});
$('#recover').addEventListener('click', () => action('recover', '/api/recover', {id: snapshot?.jobs?.[0]?.id}));
// Only a click on the summary is the viewer's choice; keep it from then on.
$('#steps-summary').addEventListener('click', () => { $('#steps-wrap').dataset.userToggled = '1'; });

validate(false);
poll();
setInterval(poll, 1500);
