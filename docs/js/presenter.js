/**
 * presenter.js – Optional collapsible presenter panel shown ONLY when URL has ?present=1.
 *
 * Buttons & hotkeys 1..5:
 *   1: Load fake KYC sample into Check and run it
 *   2: Open Learn in Challenge mode on the kyc-sms scenario
 *   3: Cycle language en -> kn -> hi -> en
 *   4: Open Verify and generate a Ravi Stores Rs.500 QR
 *   5: Delete only localStorage keys starting with "uss." and reset state
 */

import { initI18n, t, getLang, setLang, onLangChange } from './i18n.js';

const params = new URLSearchParams(window.location.search);
const isPresenter = params.get('present') === '1';

const state = {
  collapsed: false,
  note: ''
};

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = text;
  return node;
}

function action1KycCheck() {
  const checkSection = document.getElementById('check');
  if (checkSection) checkSection.scrollIntoView({ behavior: 'smooth' });
  const kycChip = document.querySelector('.btn-sample[data-sample="kyc"]');
  if (kycChip) kycChip.click();
}

function action2LearnKyc() {
  if (window.USS && typeof window.USS.setMode === 'function') {
    window.USS.setMode('challenge');
  }
  if (window.USS && typeof window.USS.startScenario === 'function') {
    window.USS.startScenario('kyc-sms');
  }
}

async function action3CycleLang() {
  const order = ['en', 'kn', 'hi'];
  const cur = getLang();
  const next = order[(order.indexOf(cur) + 1) % order.length];
  await setLang(next);
}

function action4VerifyQr() {
  if (window.USS && typeof window.USS.verifyGenerateDemo === 'function') {
    window.USS.verifyGenerateDemo('ravi-stores', 500);
  }
}

async function action5ResetState() {
  try {
    const toDelete = [];
    for (let i = 0; i < localStorage.length; i++) {
      const k = localStorage.key(i);
      if (k && k.startsWith('uss.')) toDelete.push(k);
    }
    for (const k of toDelete) {
      localStorage.removeItem(k);
    }
  } catch {
    // ignore storage errors
  }
  if (window.USS && typeof window.USS.resetDemoState === 'function') {
    window.USS.resetDemoState();
  }
  await setLang('en');
  if (window.USS && typeof window.USS.setMode === 'function') {
    window.USS.setMode('challenge');
  }
  state.note = t('presenter.resetDone');
  render();
  setTimeout(() => {
    state.note = '';
    render();
  }, 2400);
}

function render() {
  let host = document.getElementById('presenter-panel');
  if (!host) {
    host = document.createElement('aside');
    host.id = 'presenter-panel';
    host.className = 'presenter-panel';
    host.setAttribute('aria-label', t('presenter.title'));
    document.body.appendChild(host);
  }
  host.replaceChildren();
  host.classList.toggle('is-collapsed', state.collapsed);

  const head = el('div', 'presenter-head');
  head.appendChild(el('span', 'presenter-title', t('presenter.title')));
  const toggleBtn = el('button', 'presenter-toggle', state.collapsed ? t('presenter.expand') : t('presenter.collapse'));
  toggleBtn.type = 'button';
  toggleBtn.setAttribute('aria-expanded', String(!state.collapsed));
  toggleBtn.addEventListener('click', () => {
    state.collapsed = !state.collapsed;
    render();
  });
  head.appendChild(toggleBtn);
  host.appendChild(head);

  if (state.collapsed) return;

  const actions = el('div', 'presenter-actions');
  const specs = [
    ['b1', action1KycCheck],
    ['b2', action2LearnKyc],
    ['b3', action3CycleLang],
    ['b4', action4VerifyQr],
    ['b5', action5ResetState]
  ];
  for (const [key, fn] of specs) {
    const btn = el('button', 'presenter-btn', t(`presenter.${key}`));
    btn.type = 'button';
    btn.addEventListener('click', fn);
    actions.appendChild(btn);
  }
  host.appendChild(actions);

  if (state.note) {
    host.appendChild(el('p', 'presenter-note', state.note));
  }
}

if (isPresenter) {
  (async () => {
    await initI18n();
    onLangChange(() => render());
    render();

    document.addEventListener('keydown', (e) => {
      if (e.ctrlKey || e.metaKey || e.altKey) return;
      const tag = document.activeElement?.tagName;
      if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') return;
      if (e.key === '1') action1KycCheck();
      else if (e.key === '2') action2LearnKyc();
      else if (e.key === '3') action3CycleLang();
      else if (e.key === '4') action4VerifyQr();
      else if (e.key === '5') action5ResetState();
    });
  })();
}
