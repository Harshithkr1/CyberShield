/**
 * pay-demo.js – Customer verification screen for signed DemoPay links.
 *
 * Reads ?p=...&s=... from URLSearchParams, calls POST /api/verify/check,
 * and renders a large VALID / TAMPERED / EXPIRED / MALFORMED result using
 * textContent only (no inline scripts, zero innerHTML).
 */

import { initI18n, t, getLang, setLang, onLangChange } from './i18n.js';

const root = document.getElementById('pay-demo-root');

const state = {
  loading: true,
  missingParams: false,
  error: '',
  checkResult: null
};

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = text;
  return node;
}

function applyModeClass() {
  try {
    if (localStorage.getItem('uss.mode') === 'simple') {
      document.body.classList.add('uss-simple');
    }
  } catch {
    // ignore
  }
}

async function inspectUrlToken() {
  const params = new URLSearchParams(window.location.search);
  const payload = params.get('p') || '';
  const signature = params.get('s') || '';

  if (!payload || !signature) {
    state.loading = false;
    state.missingParams = true;
    return;
  }

  try {
    const res = await fetch('/api/verify/check', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ payload, signature })
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      throw new Error(data.error || `HTTP ${res.status}`);
    }
    state.checkResult = data;
  } catch (err) {
    state.error = err.message;
  } finally {
    state.loading = false;
  }
}

function render() {
  if (!root) return;
  root.replaceChildren();

  // Language bar
  const langBar = el('div', 'pay-demo-langbar');
  const active = getLang();
  for (const code of ['en', 'kn', 'hi']) {
    const btn = el('button', `learn-toggle-pill${active === code ? ' is-active' : ''}`, t(`lang.${code}`));
    btn.type = 'button';
    btn.addEventListener('click', () => setLang(code));
    langBar.appendChild(btn);
  }
  root.appendChild(langBar);

  // Permanent DEMO Banner
  const banner = el('div', 'verify-demo-banner');
  banner.appendChild(el('span', 'verify-demo-pill', t('verify.demoNoMoney')));
  banner.appendChild(el('strong', '', t('verify.demoBanner')));
  root.appendChild(banner);

  const card = el('div', 'learn-card-shell pay-demo-card');
  card.appendChild(el('h1', 'pay-demo-title', t('verify.payDemo.title')));
  card.appendChild(el('p', 'pay-demo-sub', t('verify.payDemo.subtitle')));

  if (state.loading) {
    card.appendChild(el('p', 'pay-demo-status-msg', t('verify.payDemo.checking')));
  } else if (state.missingParams) {
    const box = el('div', 'pay-demo-verdict verdict-malformed');
    box.appendChild(el('div', 'pay-demo-verdict-big', t('verify.payDemo.verdictTitles.MALFORMED')));
    box.appendChild(el('p', '', t('verify.payDemo.missingParams')));
    card.appendChild(box);
  } else if (state.error) {
    const box = el('div', 'pay-demo-verdict verdict-malformed');
    box.appendChild(el('div', 'pay-demo-verdict-big', t('verify.payDemo.verdictTitles.MALFORMED')));
    box.appendChild(el('p', '', state.error));
    card.appendChild(box);
  } else if (state.checkResult) {
    const r = state.checkResult;
    const status = r.status || 'MALFORMED';
    const box = el('div', `pay-demo-verdict verdict-${status.toLowerCase()}`);
    box.appendChild(el('div', 'pay-demo-verdict-big', t(`verify.payDemo.verdictTitles.${status}`)));

    if (Array.isArray(r.reasons)) {
      for (const reason of r.reasons) {
        box.appendChild(el('p', 'pay-demo-reason', reason));
      }
    }

    if (r.merchantId || r.upiId || r.amountRupees) {
      const dl = el('dl', 'pay-demo-details');
      const rows = [
        [t('verify.payDemo.merchantField'), r.merchantId],
        [t('verify.payDemo.upiField'), r.upiId],
        [t('verify.payDemo.amountField'), r.amountRupees ? `Rs.${r.amountRupees}` : ''],
        [t('verify.payDemo.orderField'), r.orderId],
        [t('verify.payDemo.expiryField'), r.expiresAtEpochSec ? new Date(r.expiresAtEpochSec * 1000).toLocaleString() : '']
      ];
      for (const [k, v] of rows) {
        if (!v) continue;
        const row = el('div', 'pay-demo-detail-row');
        row.appendChild(el('dt', '', k));
        row.appendChild(el('dd', '', v));
        dl.appendChild(row);
      }
      box.appendChild(dl);
    }
    card.appendChild(box);
  }

  const back = el('a', 'learn-btn-secondary pay-demo-back', t('verify.payDemo.backLink'));
  back.href = 'index.html#verify';
  card.appendChild(back);
  root.appendChild(card);
}

(async () => {
  applyModeClass();
  await initI18n();
  onLangChange(() => render());
  render();
  await inspectUrlToken();
  render();
})();

