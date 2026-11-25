/**
 * verify.js – Frontend for the #verify module ("1 Before", "2 During", "3 After").
 *
 * Calls /api/verify/* endpoints, builds all DOM nodes via createElement + textContent
 * (zero innerHTML), routes all text through i18n, and stores only the demo receipt
 * trail under localStorage key "uss.trail" (inside try/catch).
 */

import { initI18n, t, onLangChange } from './i18n.js';
import { getServerStatus, onServerStatusChange } from './health.js';

const TRAIL_STORAGE_KEY = 'uss.trail';
const verifyRoot = document.getElementById('verify-root');

const state = {
  activeTab: 't1', // 't1' | 't2' | 't3'
  merchants: [],
  merchantsLoaded: false,
  // Tab 1 (Before)
  upiInput: '',
  nameInput: '',
  tab1Loading: false,
  tab1Error: '',
  tab1Result: null,
  // Tab 2 (During)
  selectedMerchantId: 'ravi-stores',
  amountInput: '500',
  tab2Loading: false,
  tab2Error: '',
  qrData: null, // { paymentLink, qrDataUri, payload, signature, merchant, amountPaise, amountRupees, orderId, expiresAtEpochSec }
  tamperAmountInput: '5000',
  tamperCheckLoading: false,
  tamperCheckResult: null, // { checkResult, originalRupees, receivedRupees }
  // Tab 3 (After)
  trail: readStoredTrail(),
  tamperedIndex: null,
  tab3Loading: false,
  tab3Message: '',
  trailCheckResult: null
};

// ── Storage helpers (try/catch, key prefixed with "uss.") ───────────────────

function readStoredTrail() {
  try {
    const raw = localStorage.getItem(TRAIL_STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function writeStoredTrail(trail) {
  try {
    localStorage.setItem(TRAIL_STORAGE_KEY, JSON.stringify(trail));
  } catch {
    // ignore storage limits
  }
}

// ── DOM & Base64url helpers ───────────────────────────────────────────────

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = text;
  return node;
}

function encodeBase64UrlUtf8(str) {
  const bytes = new TextEncoder().encode(str);
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function decodeBase64UrlUtf8(b64u) {
  let b64 = b64u.replace(/-/g, '+').replace(/_/g, '/');
  while (b64.length % 4 !== 0) b64 += '=';
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return new TextDecoder().decode(bytes);
}

function buildTamperedPayload(originalPayload, newAmountRupeesStr) {
  const canonical = decodeBase64UrlUtf8(originalPayload);
  const parts = canonical.split('|');
  if (parts.length !== 7) return originalPayload;
  const newRupees = Number(newAmountRupeesStr);
  if (!Number.isFinite(newRupees) || newRupees <= 0) return originalPayload;
  const newPaise = Math.round(newRupees * 100);
  parts[3] = String(newPaise);
  return encodeBase64UrlUtf8(parts.join('|'));
}

async function apiJson(url, options) {
  const res = await fetch(url, options);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error(data.error || `Request failed (${res.status})`);
  }
  return data;
}

async function loadMerchants() {
  try {
    const list = await apiJson('/api/verify/merchants', { method: 'GET' });
    if (Array.isArray(list) && list.length > 0) {
      state.merchants = list;
      state.merchantsLoaded = true;
      if (!list.some((m) => m.id === state.selectedMerchantId)) {
        state.selectedMerchantId = list[0].id;
      }
    }
  } catch {
    state.merchantsLoaded = false;
  }
}

// ── Tab 1: Before payment (Receiver Verification) ─────────────────────────

async function runReceiverVerify(upiOverride, nameOverride) {
  const upi = (upiOverride !== undefined ? upiOverride : state.upiInput).trim();
  const name = (nameOverride !== undefined ? nameOverride : state.nameInput).trim();
  state.upiInput = upi;
  state.nameInput = name;

  if (!upi) {
    state.tab1Error = t('verify.tab1.upiRequired');
    state.tab1Result = null;
    render();
    return;
  }

  state.tab1Loading = true;
  state.tab1Error = '';
  render();

  try {
    state.tab1Result = await apiJson('/api/verify/receiver', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ upiId: upi, name: name || null })
    });
  } catch (err) {
    state.tab1Error = err.message;
    state.tab1Result = null;
  } finally {
    state.tab1Loading = false;
    render();
  }
}

function renderTab1(panel) {
  panel.appendChild(el('p', 'verify-tab-explainer', t('verify.tab1.explainer')));

  // Example chips
  const samplesRow = el('div', 'verify-samples-row');
  samplesRow.appendChild(el('span', 'verify-samples-lbl', t('verify.tab1.samplesLabel')));

  const examples = [
    { key: 'sampleVerified', upi: 'ravi@demobank', name: 'Ravi Stores' },
    { key: 'sampleMismatch', upi: 'ravi@demobank', name: 'Ramesh Traders' },
    { key: 'sampleLookalike', upi: 'ravl@demobank', name: '' },
    { key: 'sampleUnknown', upi: 'randomshop@otherbank', name: '' }
  ];

  for (const ex of examples) {
    const chip = el('button', 'verify-chip', t(`verify.tab1.${ex.key}`));
    chip.type = 'button';
    chip.addEventListener('click', () => runReceiverVerify(ex.upi, ex.name));
    samplesRow.appendChild(chip);
  }
  panel.appendChild(samplesRow);

  // Inputs
  const form = el('form', 'verify-form');
  form.addEventListener('submit', (e) => {
    e.preventDefault();
    runReceiverVerify();
  });

  const grid = el('div', 'verify-input-grid');

  const upiField = el('div', 'verify-field');
  const upiLbl = el('label', 'verify-label', t('verify.tab1.upiLabel'));
  upiLbl.setAttribute('for', 'verify-upi-input');
  const upiInp = el('input', 'verify-input');
  upiInp.id = 'verify-upi-input';
  upiInp.type = 'text';
  upiInp.placeholder = t('verify.tab1.upiPlaceholder');
  upiInp.value = state.upiInput;
  upiInp.maxLength = 120;
  upiInp.addEventListener('input', (e) => { state.upiInput = e.target.value; });
  upiField.appendChild(upiLbl);
  upiField.appendChild(upiInp);

  const nameField = el('div', 'verify-field');
  const nameLbl = el('label', 'verify-label', t('verify.tab1.nameLabel'));
  nameLbl.setAttribute('for', 'verify-name-input');
  const nameInp = el('input', 'verify-input');
  nameInp.id = 'verify-name-input';
  nameInp.type = 'text';
  nameInp.placeholder = t('verify.tab1.namePlaceholder');
  nameInp.value = state.nameInput;
  nameInp.maxLength = 120;
  nameInp.addEventListener('input', (e) => { state.nameInput = e.target.value; });
  nameField.appendChild(nameLbl);
  nameField.appendChild(nameInp);

  grid.appendChild(upiField);
  grid.appendChild(nameField);
  form.appendChild(grid);

  const submitBtn = el('button', 'learn-btn-primary', t('verify.tab1.verifyBtn'));
  submitBtn.type = 'submit';
  submitBtn.disabled = state.tab1Loading;
  form.appendChild(submitBtn);
  panel.appendChild(form);

  if (state.tab1Error) {
    panel.appendChild(el('p', 'verify-inline-error', state.tab1Error));
  }

  if (state.tab1Result) {
    const res = state.tab1Result;
    const status = res.status || 'UNKNOWN';
    const card = el('div', `verify-verdict-card status-${status.toLowerCase()}`);
    card.appendChild(el('span', 'verify-verdict-badge', t(`verify.tab1.verdicts.${status}`)));
    card.appendChild(el('p', 'verify-verdict-desc', t(`verify.tab1.verdictDesc.${status}`)));
    if (res.reason) {
      card.appendChild(el('p', 'verify-verdict-reason', res.reason));
    }
    if (res.closestMatch) {
      card.appendChild(
        el('p', 'verify-verdict-match', `${t('verify.tab1.closestLabel')} ${res.closestMatch.name} (${res.closestMatch.upiId})`)
      );
    }
    panel.appendChild(card);
  }
}

// ── Tab 2: During payment (Signed QR & Tamper Check) ──────────────────────

async function generateSignedQr() {
  const num = Number(state.amountInput);
  if (!Number.isFinite(num) || num < 0.01 || num > 100000) {
    state.tab2Error = t('verify.tab2.invalidAmount');
    render();
    return;
  }

  state.tab2Loading = true;
  state.tab2Error = '';
  state.tamperCheckResult = null;
  render();

  try {
    const data = await apiJson('/api/verify/qr', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        merchantId: state.selectedMerchantId,
        amountRupees: Number(num.toFixed(2))
      })
    });
    state.qrData = data;
    // Pre-populate Try-It-Yourself field to demonstrate amount tampering (e.g. 500 -> 5000)
    state.tamperAmountInput = Number(data.amountRupees) === 500 ? '5000' : String(Number(data.amountRupees) * 10);
  } catch (err) {
    state.tab2Error = err.message;
  } finally {
    state.tab2Loading = false;
    render();
  }
}

async function runTamperCheck() {
  if (!state.qrData) return;
  const num = Number(state.tamperAmountInput);
  if (!Number.isFinite(num) || num < 0.01 || num > 100000) {
    state.tab2Error = t('verify.tab2.invalidAmount');
    render();
    return;
  }

  state.tamperCheckLoading = true;
  state.tab2Error = '';
  render();

  try {
    const editedPaise = Math.round(num * 100);
    const payloadToSend = editedPaise === state.qrData.amountPaise
      ? state.qrData.payload
      : buildTamperedPayload(state.qrData.payload, num.toFixed(2));

    const checkResult = await apiJson('/api/verify/check', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        payload: payloadToSend,
        signature: state.qrData.signature
      })
    });

    state.tamperCheckResult = {
      checkResult,
      originalRupees: `Rs.${Number(state.qrData.amountRupees).toLocaleString('en-IN', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`,
      receivedRupees: `Rs.${num.toLocaleString('en-IN', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`
    };
  } catch (err) {
    state.tab2Error = err.message;
  } finally {
    state.tamperCheckLoading = false;
    render();
  }
}

function renderTab2(panel) {
  panel.appendChild(el('p', 'verify-tab-explainer', t('verify.tab2.explainer')));

  const form = el('form', 'verify-form');
  form.addEventListener('submit', (e) => {
    e.preventDefault();
    generateSignedQr();
  });

  const grid = el('div', 'verify-input-grid');

  const merchField = el('div', 'verify-field');
  const merchLbl = el('label', 'verify-label', t('verify.tab2.merchantLabel'));
  merchLbl.setAttribute('for', 'verify-merchant-select');
  const select = el('select', 'verify-input');
  select.id = 'verify-merchant-select';
  for (const m of state.merchants) {
    const opt = el('option', '', `${m.name} (${m.upiId})`);
    opt.value = m.id;
    if (m.id === state.selectedMerchantId) opt.selected = true;
    select.appendChild(opt);
  }
  select.addEventListener('change', (e) => { state.selectedMerchantId = e.target.value; });
  merchField.appendChild(merchLbl);
  merchField.appendChild(select);

  const amtField = el('div', 'verify-field');
  const amtLbl = el('label', 'verify-label', t('verify.tab2.amountLabel'));
  amtLbl.setAttribute('for', 'verify-amount-input');
  const amtInp = el('input', 'verify-input');
  amtInp.id = 'verify-amount-input';
  amtInp.type = 'number';
  amtInp.step = '0.01';
  amtInp.min = '0.01';
  amtInp.max = '100000';
  amtInp.value = state.amountInput;
  amtInp.addEventListener('input', (e) => { state.amountInput = e.target.value; });
  amtField.appendChild(amtLbl);
  amtField.appendChild(amtInp);

  grid.appendChild(merchField);
  grid.appendChild(amtField);
  form.appendChild(grid);

  const genBtn = el('button', 'learn-btn-primary', t('verify.tab2.generateBtn'));
  genBtn.type = 'submit';
  genBtn.disabled = state.tab2Loading || !state.merchantsLoaded;
  form.appendChild(genBtn);
  panel.appendChild(form);

  if (state.tab2Error) {
    panel.appendChild(el('p', 'verify-inline-error', state.tab2Error));
  }

  if (state.qrData) {
    const qrBox = el('div', 'verify-qr-result');

    const qrVisual = el('div', 'verify-qr-visual');
    const img = document.createElement('img');
    img.className = 'verify-qr-img';
    img.src = state.qrData.qrDataUri;
    img.alt = `${state.qrData.merchant.name} QR`;
    img.width = 220;
    img.height = 220;
    qrVisual.appendChild(img);
    qrVisual.appendChild(el('span', 'verify-demo-pill', t('verify.demoNoMoney')));

    const qrInfo = el('div', 'verify-qr-info');
    qrInfo.appendChild(el('p', 'verify-seal-line', t('verify.tab2.sealLine')));
    qrInfo.appendChild(el('span', 'verify-link-lbl', t('verify.tab2.linkLabel')));
    qrInfo.appendChild(el('code', 'verify-link-code', state.qrData.paymentLink));

    const openLink = el('a', 'learn-btn-secondary verify-open-customer', t('verify.tab2.openCustomerBtn'));
    openLink.href = `pay-demo.html?p=${encodeURIComponent(state.qrData.payload)}&s=${encodeURIComponent(state.qrData.signature)}`;
    openLink.target = '_blank';
    openLink.rel = 'noopener noreferrer';
    qrInfo.appendChild(openLink);

    qrBox.appendChild(qrVisual);
    qrBox.appendChild(qrInfo);
    panel.appendChild(qrBox);

    // Try it yourself box
    const tryBox = el('div', 'verify-try-box');
    tryBox.appendChild(el('h3', 'verify-try-title', t('verify.tab2.tryTitle')));
    tryBox.appendChild(el('p', 'verify-try-hint', t('verify.tab2.tryHint')));

    const tryRow = el('div', 'verify-try-row');
    const editLbl = el('label', 'verify-label', t('verify.tab2.editAmountLabel'));
    editLbl.setAttribute('for', 'verify-tamper-amount');
    const editInp = el('input', 'verify-input');
    editInp.id = 'verify-tamper-amount';
    editInp.type = 'number';
    editInp.step = '0.01';
    editInp.min = '0.01';
    editInp.max = '100000';
    editInp.value = state.tamperAmountInput;
    editInp.addEventListener('input', (e) => { state.tamperAmountInput = e.target.value; });

    const checkBtn = el('button', 'learn-btn-primary', t('verify.tab2.checkBtn'));
    checkBtn.type = 'button';
    checkBtn.disabled = state.tamperCheckLoading;
    checkBtn.addEventListener('click', runTamperCheck);

    tryRow.appendChild(editLbl);
    tryRow.appendChild(editInp);
    tryRow.appendChild(checkBtn);
    tryBox.appendChild(tryRow);

    if (state.tamperCheckResult) {
      const { checkResult, originalRupees, receivedRupees } = state.tamperCheckResult;
      const st = checkResult.status;
      const resCard = el('div', `verify-verdict-card status-${st.toLowerCase()}`);
      const msgKey = st === 'VALID' ? 'statusValid' : st === 'TAMPERED' ? 'statusTampered' : st === 'EXPIRED' ? 'statusExpired' : 'statusMalformed';
      resCard.appendChild(el('p', 'verify-tamper-headline', t(`verify.tab2.${msgKey}`)));

      const comp = el('div', 'verify-side-by-side');
      const colOrig = el('div', 'verify-comp-col');
      colOrig.appendChild(el('span', 'verify-comp-lbl', t('verify.tab2.originalLabel')));
      colOrig.appendChild(el('strong', 'verify-comp-val', originalRupees));
      const colRecv = el('div', 'verify-comp-col');
      colRecv.appendChild(el('span', 'verify-comp-lbl', t('verify.tab2.receivedLabel')));
      colRecv.appendChild(el('strong', 'verify-comp-val', receivedRupees));
      comp.appendChild(colOrig);
      comp.appendChild(colRecv);
      resCard.appendChild(comp);

      tryBox.appendChild(resCard);
    }

    panel.appendChild(tryBox);
  }
}

// ── Tab 3: After payment (Hash-Chained Receipt Trail) ─────────────────────

async function confirmDemoPayment() {
  state.tab3Loading = true;
  state.tab3Message = '';
  state.trailCheckResult = null;
  render();

  try {
    let token = state.qrData;
    if (!token) {
      const mId = state.selectedMerchantId || 'ravi-stores';
      token = await apiJson('/api/verify/qr', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ merchantId: mId, amountRupees: Number(state.amountInput) || 500 })
      });
      state.qrData = token;
    }

    const prevHash = state.trail.length > 0 ? state.trail[state.trail.length - 1].hash : null;
    const entry = await apiJson('/api/verify/receipt', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        payload: token.payload,
        signature: token.signature,
        prevHash
      })
    });

    state.trail = [...state.trail, entry];
    writeStoredTrail(state.trail);
  } catch (err) {
    state.tab3Message = err.message;
  } finally {
    state.tab3Loading = false;
    render();
  }
}

function tamperEntryTwo() {
  state.trailCheckResult = null;
  if (state.trail.length < 2) {
    state.tab3Message = t('verify.tab3.needTwoForTamper');
    render();
    return;
  }
  const copy = state.trail.map((item) => ({ ...item }));
  const orig = Number(copy[1].amount) || 500;
  copy[1].amount = (orig + 1000).toFixed(2);
  state.trail = copy;
  state.tamperedIndex = 1;
  writeStoredTrail(state.trail);
  state.tab3Message = t('verify.tab3.tamperDone');
  render();
}

async function verifyTrail() {
  if (state.trail.length === 0) return;
  state.tab3Loading = true;
  state.tab3Message = '';
  render();

  try {
    state.trailCheckResult = await apiJson('/api/verify/trail/check', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ entries: state.trail })
    });
  } catch (err) {
    state.tab3Message = err.message;
    state.trailCheckResult = null;
  } finally {
    state.tab3Loading = false;
    render();
  }
}

function clearTrail() {
  state.trail = [];
  state.tamperedIndex = null;
  state.trailCheckResult = null;
  state.tab3Message = '';
  writeStoredTrail([]);
  render();
}

function renderTab3(panel) {
  panel.appendChild(el('p', 'verify-tab-explainer', t('verify.tab3.explainer')));

  const demoTagRow = el('div', 'verify-demo-row');
  demoTagRow.appendChild(el('span', 'verify-demo-pill', t('verify.demoNoMoney')));
  panel.appendChild(demoTagRow);

  const btnRow = el('div', 'verify-tab3-actions');

  const btnConfirm = el('button', 'learn-btn-primary', t('verify.tab3.confirmBtn'));
  btnConfirm.type = 'button';
  btnConfirm.disabled = state.tab3Loading;
  btnConfirm.addEventListener('click', confirmDemoPayment);

  const btnTamper = el('button', 'learn-btn-secondary', t('verify.tab3.tamperBtn'));
  btnTamper.type = 'button';
  btnTamper.disabled = state.tab3Loading;
  btnTamper.addEventListener('click', tamperEntryTwo);

  const btnVerify = el('button', 'learn-btn-secondary', t('verify.tab3.verifyBtn'));
  btnVerify.type = 'button';
  btnVerify.disabled = state.tab3Loading || state.trail.length === 0;
  btnVerify.addEventListener('click', verifyTrail);

  const btnReport = el('button', 'learn-btn-secondary verify-report-jump', t('verify.tab3.reportBtn'));
  btnReport.type = 'button';
  btnReport.addEventListener('click', () => {
    const rep = document.getElementById('report');
    if (rep) rep.scrollIntoView({ behavior: 'smooth' });
  });

  btnRow.appendChild(btnConfirm);
  btnRow.appendChild(btnTamper);
  btnRow.appendChild(btnVerify);
  btnRow.appendChild(btnReport);

  if (state.trail.length > 0) {
    const btnClear = el('button', 'learn-btn-link', t('verify.tab3.clearBtn'));
    btnClear.type = 'button';
    btnClear.addEventListener('click', clearTrail);
    btnRow.appendChild(btnClear);
  }
  panel.appendChild(btnRow);

  if (state.tab3Message) {
    panel.appendChild(el('p', 'verify-inline-note', state.tab3Message));
  }

  if (state.trailCheckResult) {
    const tc = state.trailCheckResult;
    const verdict = el('div', `verify-verdict-card ${tc.valid ? 'status-valid' : 'status-tampered'}`);
    const title = tc.valid
      ? t('verify.tab3.chainIntact')
      : t('verify.tab3.chainBroken', { index: (tc.brokenAtIndex ?? 0) + 1 });
    verdict.appendChild(el('strong', 'verify-verdict-badge', title));
    if (tc.reason) verdict.appendChild(el('p', 'verify-verdict-reason', tc.reason));
    panel.appendChild(verdict);
  }

  if (state.trail.length === 0) {
    panel.appendChild(el('p', 'verify-empty-trail', t('verify.tab3.emptyTrail')));
    return;
  }

  const tableWrap = el('div', 'verify-table-wrap');
  const table = el('table', 'verify-trail-table');
  const thead = document.createElement('thead');
  const headRow = document.createElement('tr');
  for (const colKey of ['colId', 'colMerchant', 'colAmount', 'colTime', 'colHash']) {
    headRow.appendChild(el('th', '', t(`verify.tab3.${colKey}`)));
  }
  thead.appendChild(headRow);
  table.appendChild(thead);

  const tbody = document.createElement('tbody');
  state.trail.forEach((entry, idx) => {
    const tr = document.createElement('tr');
    if (state.trailCheckResult && !state.trailCheckResult.valid && state.trailCheckResult.brokenAtIndex === idx) {
      tr.classList.add('is-broken-row');
    } else if (state.tamperedIndex === idx) {
      tr.classList.add('is-edited-row');
    }

    tr.appendChild(el('td', '', entry.receiptId || ''));
    tr.appendChild(el('td', '', entry.merchant || ''));
    tr.appendChild(el('td', '', `Rs.${entry.amount || ''}`));
    const shortTime = (entry.timestamp || '').replace('T', ' ').slice(0, 19);
    tr.appendChild(el('td', '', shortTime));
    const shortHash = entry.hash ? `${entry.hash.slice(0, 12)}…` : '';
    tr.appendChild(el('td', 'verify-hash-cell', shortHash));
    tbody.appendChild(tr);
  });
  table.appendChild(tbody);
  tableWrap.appendChild(table);
  panel.appendChild(tableWrap);
}

// ── Main Render ───────────────────────────────────────────────────────────

function render() {
  if (!verifyRoot) return;
  verifyRoot.replaceChildren();

  // Header
  const header = el('div', 'section-header');
  header.appendChild(el('span', 'section-tag', t('verify.tag')));
  const h2 = el('h2', 'section-heading', t('verify.title'));
  h2.id = 'verify-heading';
  header.appendChild(h2);
  header.appendChild(el('p', 'section-sub', t('verify.subtitle')));
  verifyRoot.appendChild(header);

  // Permanent Demo Banner
  const banner = el('div', 'verify-demo-banner');
  banner.setAttribute('role', 'note');
  banner.appendChild(el('strong', '', t('verify.demoBanner')));
  verifyRoot.appendChild(banner);

  // Shell Card with 3 Tabs (or Server Waking Spinner / Needs Server message)
  const serverStatus = getServerStatus();
  if (!state.merchantsLoaded && (serverStatus === 'checking' || serverStatus === 'waking')) {
    const waitCard = el('div', 'learn-card-shell verify-status-box');
    waitCard.appendChild(el('span', 'uss-spinner', ''));
    waitCard.appendChild(el('p', 'verify-status-msg', t(serverStatus === 'waking' ? 'health.waking' : 'health.checking')));
    verifyRoot.appendChild(waitCard);
  } else if (!state.merchantsLoaded && (serverStatus === 'static' || serverStatus === 'unreachable')) {
    const offCard = el('div', 'learn-card-shell verify-status-box is-offline');
    offCard.appendChild(el('p', 'verify-needs-server', t('verify.needsServer')));
    verifyRoot.appendChild(offCard);
  } else {
    const shell = el('div', 'learn-card-shell verify-shell');

    const tabList = el('div', 'verify-tablist');
    tabList.setAttribute('role', 'tablist');

    const tabDefs = ['t1', 't2', 't3'];
    for (const key of tabDefs) {
      const active = state.activeTab === key;
      const btn = el('button', `verify-tab-btn${active ? ' is-active' : ''}`, t(`verify.tabs.${key}`));
      btn.type = 'button';
      btn.setAttribute('role', 'tab');
      btn.setAttribute('aria-selected', String(active));
      btn.id = `verify-tab-${key}`;
      btn.setAttribute('aria-controls', `verify-panel-${key}`);
      btn.addEventListener('click', () => {
        state.activeTab = key;
        render();
      });
      btn.addEventListener('keydown', (e) => {
        const idx = tabDefs.indexOf(key);
        if (e.key === 'ArrowRight') {
          state.activeTab = tabDefs[(idx + 1) % tabDefs.length];
          render();
          document.getElementById(`verify-tab-${state.activeTab}`)?.focus();
        } else if (e.key === 'ArrowLeft') {
          state.activeTab = tabDefs[(idx - 1 + tabDefs.length) % tabDefs.length];
          render();
          document.getElementById(`verify-tab-${state.activeTab}`)?.focus();
        }
      });
      tabList.appendChild(btn);
    }
    shell.appendChild(tabList);

    const panel = el('div', 'verify-tabpanel');
    panel.setAttribute('role', 'tabpanel');
    panel.id = `verify-panel-${state.activeTab}`;
    panel.setAttribute('aria-labelledby', `verify-tab-${state.activeTab}`);

    if (state.activeTab === 't1') renderTab1(panel);
    else if (state.activeTab === 't2') renderTab2(panel);
    else renderTab3(panel);

    shell.appendChild(panel);
    verifyRoot.appendChild(shell);
  }

  // "What this can and cannot do" card
  const limitsCard = el('div', 'learn-card-shell verify-limits-card');
  limitsCard.appendChild(el('h3', 'verify-limits-title', t('verify.limits.title')));
  const limitsGrid = el('div', 'verify-limits-grid');

  const canBox = el('div', 'verify-limit-col can-col');
  canBox.appendChild(el('h4', 'verify-limit-head', t('verify.limits.canTitle')));
  canBox.appendChild(el('p', 'verify-limit-body', t('verify.limits.canText')));

  const cannotBox = el('div', 'verify-limit-col cannot-col');
  cannotBox.appendChild(el('h4', 'verify-limit-head', t('verify.limits.cannotTitle')));
  cannotBox.appendChild(el('p', 'verify-limit-body', t('verify.limits.cannotText')));

  limitsGrid.appendChild(canBox);
  limitsGrid.appendChild(cannotBox);
  limitsCard.appendChild(limitsGrid);
  verifyRoot.appendChild(limitsCard);
}

// ── Boot & Global Presenter / Reset Hooks ─────────────────────────────────

window.USS = window.USS || {};
window.USS.verifyGenerateDemo = async (merchantId = 'ravi-stores', amount = 500) => {
  await initI18n();
  if (!state.merchantsLoaded) await loadMerchants();
  const verifySection = document.getElementById('verify');
  if (verifySection) verifySection.scrollIntoView({ behavior: 'smooth' });
  state.activeTab = 't2';
  state.selectedMerchantId = merchantId;
  state.amountInput = String(amount);
  if (state.merchantsLoaded) {
    await generateSignedQr();
  } else {
    render();
  }
};
window.USS.resetVerifyState = () => {
  state.trail = [];
  state.tamperedIndex = null;
  state.trailCheckResult = null;
  state.qrData = null;
  state.tamperCheckResult = null;
  state.tab1Result = null;
  state.tab1Error = '';
  state.tab2Error = '';
  state.tab3Message = '';
  render();
};

onServerStatusChange(async (status) => {
  if (status === 'ready' && !state.merchantsLoaded) {
    await loadMerchants();
  }
  render();
});

(async () => {
  await Promise.all([initI18n(), loadMerchants()]);
  onLangChange(() => render());
  render();
})();

