'use strict';
// Shows whether the live demo is up and whether a trade is in progress.
async function poll() {
  const dot = document.getElementById('network-dot'), text = document.getElementById('network-status');
  try {
    const state = await (await fetch('/api/network', {cache: 'no-store'})).json();
    const running = Object.values(state.apps).every(a => a.running);
    dot.className = running ? 'online' : 'offline';
    text.textContent = running ? `Live demo ready · regtest #${state.zcash.height}` : 'Live demo restarting';
  } catch {
    dot.className = 'offline';
    text.textContent = 'Live demo offline';
  }
}
poll();
setInterval(poll, 5000);

// Copy a full transaction ID from the shortened public testnet table.
document.querySelectorAll('button.copy').forEach(button => button.addEventListener('click', async () => {
  try {
    await navigator.clipboard.writeText(button.dataset.copy);
    button.textContent = 'Copied';
  } catch {
    window.prompt('Copy the full transaction ID:', button.dataset.copy);  // No clipboard permission.
  }
  setTimeout(() => { button.textContent = 'Copy'; }, 1500);
}));
