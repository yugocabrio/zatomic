'use strict';
const $ = (selector) => document.querySelector(selector);
let snapshot = null;
let pending = false;
let selected = 'success';
let currentId = null;
let receiptKey = '';

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
  if (job && !complete) {
    selected = job.scenario;
    document.querySelectorAll('input[name="scenario"]').forEach(input => { input.checked = input.value === selected; });
    document.querySelectorAll('.scenario').forEach(label => label.classList.toggle('selected', label.querySelector('input').checked));
  }
  const refund = job?.scenario === 'refund-stop';
  const recovered = events.has('09-recovered');
  $('#start').disabled = pending || running || data.busy || !data.ready || (interrupted && events.has('02-funded'));
  text('#start span:first-child', running ? (job.state === 'recovering' ? 'Recovering on local chains…' : 'Swap in progress…') : (complete ? 'Run another swap' : 'Start local swap'));
  document.querySelectorAll('input[name="scenario"]').forEach(input => { input.disabled = !!running || pending; });
  const badge = $('#run-status');
  badge.className = `status-pill ${job?.state || ''}`;
  badge.textContent = !job ? 'Ready when you are' : running ? (job.state === 'recovering' ? 'Recovery running' : 'Live on local chains') : complete ? 'Verified on both chains' : job.state === 'error' ? 'Needs recovery' : 'Stopped at checkpoint';
  text('#live-title', complete ? (refund ? 'Both assets returned.' : 'The exchange is complete.') : interrupted ? 'Stopped. Still recoverable.' : running ? (job.state === 'recovering' ? 'Resuming from the chain.' : 'The agreement is in motion.') : 'Two chains. One agreement.');
  text('#resolution-title', refund ? 'Wait for expiry & refund' : 'Reveal & settle');
  text('#resolution-copy', refund ? 'No secret revealed. Each owner recovers their asset.' : 'Public witness completes the prepared ZEC signature.');
  const finished = [events.has('01-prepared'), events.has('02-funded'), events.has('04-eth-locked'), events.has('06-zec-claimed') || events.has('06-zec-refunded') || complete, complete];
  let active = finished.findIndex(value => !value);
  const items = [...document.querySelectorAll('#timeline li')];
  items.forEach((item, i) => {
    item.classList.toggle('done', !!finished[i]);
    item.classList.toggle('active', !!running && i === active);
    item.querySelector('.step-mark').textContent = finished[i] ? '✓' : String(i + 1);
    item.querySelector('.step-state').textContent = finished[i] ? 'Verified' : (running && i === active) ? 'Working' : interrupted && i === active ? 'Paused' : 'Waiting';
  });
  $('#progress-fill').style.width = `${finished.filter(Boolean).length * 20}%`;
  $('#recovery-box').hidden = !interrupted;
  $('#recover').disabled = pending || !job?.recoverable || data.busy;
  if (interrupted) {
    text('#recovery-title', job.recoverable ? 'The way out is already prepared.' : 'State preserved for inspection.');
    text('#recovery-copy', !job.recoverable ? 'The run stopped before its ETH checkpoint. State is preserved; inspect the local runner log and recovery guide before continuing.' : refund ? 'No secret was revealed. Restart the local node, advance the test clocks and recover both original assets.' : 'The ETH claim is recorded. Bob can use its public witness to finish the ZEC claim without another signature from Alice.');
  }
  $('#outcome').hidden = !complete;
  if (complete) {
    text('#outcome-title', refund ? 'Alice recovered ZEC. Bob recovered ETH.' : 'Bob received ZEC. Alice received ETH.');
    text('#outcome-copy', `${recovered ? 'Recovered from a durable checkpoint. ' : ''}0.010000 ZEC note decrypted · 0.0100 ETH withdrawn.`);
  }
  text('#live-caption', running ? 'Local proof generation and chain confirmation are running.' : interrupted ? 'Runner and local EVM stopped. Recovery uses saved state.' : complete ? 'Node confirmation + recipient decryption verified.' : 'Actual local-chain transactions. No simulated balances.');
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
  $('#receipt').hidden = !rows.length;
  text('#receipt-detail', job ? `Run ${job.id.slice(-8)} · private artifacts stay on this machine` : '');
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
$('#start').addEventListener('click', () => action('/api/start', {scenario: selected}));
$('#recover').addEventListener('click', () => action('/api/recover', {id: currentId}));
poll(); setInterval(poll, 1500);
