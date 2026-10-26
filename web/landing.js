'use strict';
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
