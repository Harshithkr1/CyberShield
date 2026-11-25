/**
 * health.js – Non-blocking server wake-up probe for GET /api/health.
 *
 * Shows a non-blocking banner after 3s if the server is waking up, retries with
 * backoff, displays status spinners in Check & Verify until ready, and keeps
 * Learn functional even if the server is offline or unreachable.
 */

import { initI18n, t, onLangChange } from './i18n.js';

const listeners = new Set();
let currentStatus = 'checking'; // 'checking' | 'waking' | 'ready' | 'static' | 'unreachable'
let showBanner = false;
let wakeTimer = null;

function notify() {
  window.USS = window.USS || {};
  window.USS.serverStatus = currentStatus;
  renderWakeBanner();
  renderCheckSpinner();
  listeners.forEach((cb) => {
    try { cb(currentStatus); } catch {}
  });
}

export function getServerStatus() {
  return currentStatus;
}

export function onServerStatusChange(cb) {
  if (typeof cb !== 'function') return () => {};
  listeners.add(cb);
  return () => listeners.delete(cb);
}

function renderWakeBanner() {
  const banner = document.getElementById('wake-banner');
  const textEl = document.getElementById('wake-banner-text');
  const spinnerEl = document.getElementById('wake-banner-spinner');
  if (!banner || !textEl) return;

  if (!showBanner || currentStatus === 'ready') {
    banner.classList.add('hidden');
    return;
  }

  if (currentStatus === 'waking' || currentStatus === 'checking') {
    banner.classList.remove('hidden', 'is-error');
    if (spinnerEl) spinnerEl.classList.remove('hidden');
    textEl.textContent = t('health.waking');
  } else if (currentStatus === 'unreachable') {
    banner.classList.remove('hidden');
    banner.classList.add('is-error');
    if (spinnerEl) spinnerEl.classList.add('hidden');
    textEl.textContent = t('health.unreachable');
  } else {
    // 'static' (e.g. GitHub Pages): hide top alarm banner; Verify handles its own message
    banner.classList.add('hidden');
  }
}

function renderCheckSpinner() {
  const checkStatus = document.getElementById('check-server-status');
  const checkText = document.getElementById('check-server-text');
  const checkSpinner = document.getElementById('check-server-spinner');
  if (!checkStatus || !checkText) return;

  if (currentStatus === 'ready' || currentStatus === 'static') {
    checkStatus.classList.add('hidden');
    return;
  }

  checkStatus.classList.remove('hidden');
  if (currentStatus === 'unreachable') {
    checkStatus.classList.add('is-error');
    if (checkSpinner) checkSpinner.classList.add('hidden');
    checkText.textContent = t('health.unreachable');
  } else {
    checkStatus.classList.remove('is-error');
    if (checkSpinner) checkSpinner.classList.remove('hidden');
    checkText.textContent = currentStatus === 'waking' ? t('health.waking') : t('health.checking');
  }
}

async function pingOnce() {
  const controller = typeof AbortController !== 'undefined' ? new AbortController() : null;
  const timeout = controller ? setTimeout(() => controller.abort(), 5000) : null;
  try {
    const res = await fetch('/api/health', {
      method: 'GET',
      cache: 'no-store',
      signal: controller ? controller.signal : undefined
    });
    if (res.ok) {
      const data = await res.json().catch(() => ({}));
      if (data && data.status === 'UP') {
        return 'ok';
      }
    }
    if (res.status === 404 || res.status === 405) {
      return 'static';
    }
    return 'retry';
  } catch {
    return 'retry';
  } finally {
    if (timeout) clearTimeout(timeout);
  }
}

async function runHealthLoop() {
  await initI18n();
  onLangChange(() => {
    renderWakeBanner();
    renderCheckSpinner();
  });

  // If no answer in 3 seconds, surface non-blocking waking banner
  wakeTimer = setTimeout(() => {
    if (currentStatus === 'checking') {
      currentStatus = 'waking';
      showBanner = true;
      notify();
    }
  }, 3000);

  notify();

  const backoffs = [0, 2000, 4000, 8000, 12000];
  for (let i = 0; i < backoffs.length; i++) {
    if (backoffs[i] > 0) {
      await new Promise((r) => setTimeout(r, backoffs[i]));
    }
    const outcome = await pingOnce();
    if (outcome === 'ok') {
      clearTimeout(wakeTimer);
      currentStatus = 'ready';
      showBanner = false;
      notify();
      return;
    }
    if (outcome === 'static') {
      clearTimeout(wakeTimer);
      currentStatus = 'static';
      showBanner = false;
      notify();
      return;
    }
  }

  clearTimeout(wakeTimer);
  currentStatus = 'unreachable';
  showBanner = true;
  notify();
}

window.USS = window.USS || {};
window.USS.getServerStatus = getServerStatus;
window.USS.onServerStatusChange = onServerStatusChange;

runHealthLoop();

