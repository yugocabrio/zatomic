'use strict';
const $ = (selector) => document.querySelector(selector);
let snapshot = null;
let pending = false;
let selected = 'success';
let currentId = null;
let receiptKey = '';
let drafting = false;
let displayedQuote = null;

function text(selector, value) { $(selector).textContent = value; }
function displayError(message) {
  text('#action-error', message);
  $('#action-error').hidden = !message;
}
function eventMap(job) { return new Map((job?.events || []).map(e => [e.stage, e.value])); }
function compactTime(seconds) {
  const minutes = Math.floor(seconds / 60);
  return minutes ? `${minutes}m ${seconds % 60}s` : `${seconds}s`;
}
function render(data) {
  snapshot = data;
  $('#network-dot').classList.toggle('online', data.ready);
  text('#network-status', data.ready ? `Local chains · ZEC #${data.node.height}` : 'Local setup needed');
  const job = data.jobs[0];
  currentId = job?.id || null;
  const events = eventMap(job);
  const running = job && ['running', 'recovering'].includes(job.state);
  const interrupted = job && ['interrupted', 'error'].includes(job.state);
  const complete = job?.state === 'complete';
  const offered = job?.state === 'offered';
  const accepted = job?.state === 'accepted';
  if (job?.quote && displayedQuote !== job.id) {
    displayedQuote = job.id; drafting = false;
    $('#zec-amount').value = job.quote.zec_amount; $('#eth-amount').value = job.quote.eth_amount;
  }
  const editable = (!offered && !accepted && !running && !interrupted) || drafting;
  for (const id of ['#zec-amount', '#eth-amount']) $(id).disabled = pending || running || data.busy || !editable;
  $('#create-offer').disabled = pending || running || data.busy || interrupted || !data.ready || !editable;
  $('#accept-offer').disabled = pending || data.busy || !offered || drafting;
  $('#new-offer').hidden = !(offered || accepted) || drafting;
  $('#new-offer').disabled = pending || data.busy;
  text('#quote-status', drafting ? 'Drafting a new offer' : accepted ? 'Bob accepted · ready to prepare' : offered ? 'Alice signed · Bob must review' : job?.quote && running ? 'Accepted quote · settlement in progress' : 'Choose your exact amounts');
  text('#quote-copy', (offered || accepted) && !drafting ? `Alice sends ${job.quote.zec_amount} ZEC. Bob sends ${job.quote.eth_amount} ETH. ${accepted ? 'Both quote signatures verified. Funding is still a separate action.' : 'Bob: check both amounts before accepting. No funds are locked.'}` : 'Exact decimal amounts. Up to 1 ZEC and 10 ETH with local test funds; no market price feed.');
  $('#quote-digest').hidden = !job?.quote || drafting;
  text('#quote-digest', job?.quote ? `Quote ${job.quote.quote_digest}` : '');
  if (job && (running || interrupted)) {
    selected = job.scenario;
    document.querySelectorAll('input[name="scenario"]').forEach(input => { input.checked = input.value === selected; });
    document.querySelectorAll('.scenario').forEach(label => label.classList.toggle('selected', label.querySelector('input').checked));
  }
  const refund = job?.scenario === 'refund-stop';
  const recovered = events.has('09-recovered');
  const cancelled = events.get('08-complete')?.unfunded_cancelled === true;
  const cancellable = job?.cancellable_setup === true;
  const closing = running && cancellable && job.state === 'recovering';
  const fundingOnly = (events.get('09-recovered') || events.get('08-complete'))?.eth_not_locked === true;
  $('#start').disabled = pending || running || data.busy || !data.ready || !accepted || drafting;
  text('#start span:first-child', running ? (closing ? 'Closing this offer…' : job.state === 'recovering' ? 'Recovering on local chains…' : 'Swap in progress…') : 'Prepare exits & fund this swap');
  document.querySelectorAll('input[name="scenario"]').forEach(input => { input.disabled = !!running || pending; });
  const badge = $('#run-status');
  badge.className = `status-pill ${job?.state || ''}`;
  badge.textContent = !job ? 'Ready when you are' : running ? (closing ? 'Closing setup' : job.state === 'recovering' ? 'Recovery running' : 'Live on local chains') : complete ? (cancelled ? 'Setup cancelled' : fundingOnly ? 'ZEC refund verified' : 'Verified on both chains') : job.state === 'error' ? 'Needs recovery' : offered ? 'Offer signed' : accepted ? 'Offer accepted' : 'Stopped at checkpoint';
  text('#live-title', complete ? (cancelled ? 'No swap funds were locked.' : fundingOnly ? 'ZEC returned before ETH lock.' : refund ? 'Both assets returned.' : 'The exchange is complete.') : interrupted ? (cancellable ? 'Stopped before funding.' : job.recoverable ? 'Stopped. Still recoverable.' : 'Stopped. State preserved.') : running ? (closing ? 'Closing before funding.' : job.state === 'recovering' ? 'Resuming from the chain.' : 'The agreement is in motion.') : offered ? 'Bob, review the exact exchange.' : accepted ? 'Agreed. Funding has not started.' : 'Two chains. One agreement.');
  text('#timeline li[data-step="lock"] strong', fundingOnly ? 'ETH remains with Bob' : 'Lock the ETH');
  text('#timeline li[data-step="verify"] small', cancelled ? 'Confirm the offer is closed before funding.' : 'Confirm payment, decrypt the note, check recovery.');
  text('#resolution-title', refund || fundingOnly ? 'Wait for expiry & refund' : 'Reveal & settle');
  text('#resolution-copy', refund || fundingOnly ? 'No secret revealed. Each owner recovers their asset.' : 'Public witness completes the prepared ZEC signature.');
  const finished = [events.has(job?.driver?.startsWith('owner-consent-') ? '01-consented' : '01-prepared'), events.has('02-funded'), events.has('04-eth-locked') || fundingOnly, events.has('06-zec-claimed') || events.has('06-zec-refunded') || (complete && !cancelled), complete];
  let active = finished.findIndex(value => !value);
  const items = [...document.querySelectorAll('#timeline li')];
  items.forEach((item, i) => {
    item.classList.toggle('done', !!finished[i]);
    item.classList.toggle('active', !!running && i === active);
    item.querySelector('.step-mark').textContent = finished[i] ? '✓' : String(i + 1);
    item.querySelector('.step-state').textContent = cancelled ? (i === 4 ? 'Cancelled' : finished[i] ? 'Verified' : i === 0 ? 'Incomplete' : 'Not started') : finished[i] ? (fundingOnly && i === 2 ? 'Not locked' : 'Verified') : (running && i === active) ? 'Working' : interrupted && i === active ? 'Paused' : 'Waiting';
  });
  $('#progress-fill').style.width = `${finished.filter(Boolean).length * 20}%`;
  $('#recovery-box').hidden = !interrupted;
  text('#recover', cancellable ? 'Cancel uncommitted setup' : 'Restart & recover');
  $('#recover').disabled = pending || !job?.recoverable || data.busy;
  if (interrupted) {
    text('#recovery-title', cancellable ? 'Funding authorization was never released.' : job.recoverable ? 'The way out is already prepared.' : 'State preserved for inspection.');
    text('#recovery-copy', cancellable ? 'Permanently close this offer without locking swap funds. Setup files remain private; start a fresh offer when ready.' : !job.recoverable ? 'The run stopped before its ETH checkpoint. State is preserved; inspect the local runner log and recovery guide before continuing.' : !events.has('04-eth-locked') && job.eth_setup_started ? 'An ETH send may have happened before its receipt was saved. Reconcile the signed transaction before deciding whether to settle or refund.' : !events.has('04-eth-locked') ? 'ETH setup never started. Recover the prepared ZEC refund after its local deadline; no new funding will be submitted.' : refund ? 'No secret was revealed. Restart the local node, advance the test clocks and recover both original assets.' : 'The ETH claim is recorded. Bob can use its public witness to finish the ZEC claim without another signature from Alice.');
  }
  $('#outcome').hidden = !complete;
  if (complete) {
    text('#outcome-title', cancelled ? 'Both owners kept their swap funds.' : fundingOnly ? 'Alice recovered ZEC. Bob never locked ETH.' : refund ? 'Alice recovered ZEC. Bob recovered ETH.' : 'Bob received ZEC. Alice received ETH.');
    text('#outcome-copy', cancelled ? 'Source authorization is permanently disabled for this offer. No cancellation transaction; local wallet or escrow setup may already exist.' : fundingOnly ? 'The existing native funding was reconciled and refunded. No new ETH transaction.' : `${recovered ? 'Recovered from a durable checkpoint. ' : ''}${job.settled_amounts?.zec || '—'} ZEC note decrypted · ${job.settled_amounts?.eth || '—'} ETH withdrawn.`);
  }
  text('#live-caption', running ? (closing ? 'Recording cancellation. No funding will be signed or sent.' : 'Owner clients are signing and confirming on local chains.') : interrupted ? (cancellable ? 'Setup can be closed without signing or sending funding.' : job.eth_setup_started ? 'Runner and local EVM stopped. Recovery uses saved state.' : 'Runner stopped before ETH setup. Native recovery remains prepared.') : complete ? (cancelled ? 'Cancellation recorded before source authorization.' : 'Node confirmation + recipient decryption verified.') : 'Actual transactions on disposable local chains.');
  const elapsed = job ? Math.max(0, (running ? Math.floor(Date.now() / 1000) : (job.updated_at || Math.floor(Date.now() / 1000))) - job.started_at) : 0;
  text('#elapsed', job ? compactTime(elapsed) : '—');
  renderReceipt(job, events);
}
function renderReceipt(job, events) {
  const key = `${job?.id}:${[...events.keys()].join(',')}`;
  if (key === receiptKey) return;
  receiptKey = key;
  const rows = [];
  const add = (label, value) => { if (value) rows.push([label, value]); };
  add('ZEC funding', events.get('02-funded')?.txid);
  add('ETH escrow', events.get('04-eth-locked')?.txid);
  add('ETH claim', events.get('05-eth-claimed')?.txid);
  add('ETH refund', events.get('05-eth-refunded')?.txid);
  add('ZEC claim', events.get('06-zec-claimed')?.txid);
  add('ZEC refund', events.get('06-zec-refunded')?.txid);
  add('Recovered ZEC', events.get('09-recovered')?.native_txid);
  add('ETH withdrawal', events.get('08-complete')?.eth_withdraw_tx);
  $('#receipt').hidden = !rows.length;
  text('#receipt-detail', job ? `Run ${job.id.slice(-8)} · ${events.has('01-consented') ? 'both owners signed before funding' : job.driver === 'owner-clients-v1' ? 'each owner signs locally' : 'legacy local fixture'} · private artifacts stay on this machine` : '');
  const container = $('#transactions');
  container.replaceChildren();
  for (const [label, value] of rows) {
    const row = document.createElement('div'); row.className = 'transaction';
    const heading = document.createElement('label'); heading.textContent = label;
    const hash = document.createElement('code'); hash.textContent = value; hash.title = value;
    const copy = document.createElement('button'); copy.textContent = 'COPY'; copy.setAttribute('aria-label', `Copy ${label} transaction ID`);
    copy.addEventListener('click', async () => {
      try { await navigator.clipboard.writeText(value); copy.textContent = 'COPIED'; }
      catch { copy.textContent = 'SELECT'; const range = document.createRange(); range.selectNodeContents(hash); const selection = getSelection(); selection.removeAllRanges(); selection.addRange(range); }
    });
    row.append(heading, hash, copy); container.append(row);
  }
}
async function poll() {
  try {
    const response = await fetch('/api/state', {cache: 'no-store'});
    if (!response.ok) throw new Error('Local server unavailable.');
    render(await response.json());
  } catch {
    text('#network-status', 'Local connection lost');
    $('#network-dot').classList.remove('online');
    $('#start').disabled = true;
    $('#recover').disabled = true;
  }
}
async function action(path, body) {
  if (pending || !snapshot) return;
  pending = true; displayError(''); render(snapshot);
  try {
    const response = await fetch(path, {method: 'POST', headers: {'Content-Type': 'application/json', 'X-Latch-Token': snapshot.token}, body: JSON.stringify(body)});
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || 'The operation could not start.');
  } catch (error) { displayError(error.message); }
  finally { pending = false; await poll(); }
}
document.querySelectorAll('input[name="scenario"]').forEach(input => input.addEventListener('change', () => {
  selected = input.value;
  document.querySelectorAll('.scenario').forEach(label => label.classList.toggle('selected', label.querySelector('input').checked));
}));
$('#create-offer').addEventListener('click', () => action('/api/offer', {zec_amount: $('#zec-amount').value, eth_amount: $('#eth-amount').value}));
$('#accept-offer').addEventListener('click', () => action('/api/accept', {id: currentId}));
$('#new-offer').addEventListener('click', () => { drafting = true; render(snapshot); $('#zec-amount').focus(); });
$('#start').addEventListener('click', () => action('/api/start', {scenario: selected, id: currentId}));
$('#recover').addEventListener('click', () => action('/api/recover', {id: currentId}));
poll(); setInterval(poll, 1500);
