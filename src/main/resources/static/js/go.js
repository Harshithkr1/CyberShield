/**
 * go.js – "Check before you go" client-side link gate for go.html.
 * Static & browser-only: never sends destination URLs to any server, never logs
 * or stores inspected URLs, and never redirects automatically.
 */

import { initI18n, t, getLang, setLang, onLangChange } from './i18n.js';
import { runClientSideAnalysis } from './client-engine.js';
import {
  encodeBase64UrlUtf8,
  decodeBase64UrlUtf8,
  validateDestinationUrl,
  extractFragmentParam,
  splitUrlHostParts
} from './go-utils.js';

const MODE_STORAGE_KEY = 'uss.mode';
const DEMO_RISKY_URL = 'https://upi-kyc-in.top/update';

const root = document.getElementById('go-root');

const state = {
  mode: readMode(),
  status: 'loading', // 'empty' | 'blocked' | 'analyzing' | 'ready'
  url: '',
  parsed: null,
  analysis: null,
  mediumAccepted: false,
  highStep: 0 // 0 = hidden, 1 = confirm shown, 2 = link revealed
};

function readMode() {
  try {
    return localStorage.getItem(MODE_STORAGE_KEY) === 'simple' ? 'simple' : 'challenge';
  } catch {
    return 'challenge';
  }
}

function setMode(next) {
  state.mode = next === 'simple' ? 'simple' : 'challenge';
  try {
    localStorage.setItem(MODE_STORAGE_KEY, state.mode);
  } catch {
    // ignore storage errors
  }
  applyModeClass();
  render();
}

function applyModeClass() {
  document.body.classList.toggle('uss-simple', state.mode === 'simple');
}

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = text;
  return node;
}

function mapUrlResultToScenario(result) {
  const signals = Array.isArray(result?.signals) ? result.signals : [];
  if (result?.scamType === 'MALICIOUS_APP' || signals.some((s) => s.id === 'maliciousApp.apkLink')) {
    return 'cloned-app';
  }
  if (signals.some((s) => s.id === 'text.prizeBait')) return 'lottery-fee';
  return 'kyc-sms';
}

function translateSignalReason(sig) {
  const key = `go.signals.${sig.id}`;
  const mapped = t(key);
  if (mapped && mapped !== key) return mapped;
  return sig.explanation || t('go.signals.generic');
}

function goBackAction() {
  try {
    if (window.history.length > 1 && document.referrer) {
      const refOrigin = new URL(document.referrer).origin;
      if (refOrigin === window.location.origin) {
        window.history.back();
        return;
      }
    }
  } catch {
    // fallback below
  }
  window.location.href = './index.html#check';
}

async function inspectCurrentHash() {
  state.mediumAccepted = false;
  state.highStep = 0;
  state.analysis = null;
  state.url = '';
  state.parsed = null;

  const rawParam = extractFragmentParam(window.location.hash, 'u');
  if (!rawParam) {
    state.status = 'empty';
    render();
    return;
  }

  let decoded = '';
  try {
    decoded = decodeBase64UrlUtf8(rawParam);
  } catch {
    state.status = 'blocked';
    render();
    return;
  }

  const checked = validateDestinationUrl(decoded);
  if (!checked.valid) {
    state.status = 'blocked';
    render();
    return;
  }

  state.status = 'analyzing';
  state.url = checked.url;
  state.parsed = checked.parsed;
  render();

  const targetSnapshot = checked.url;
  const result = await runClientSideAnalysis(targetSnapshot, true);
  if (state.url !== targetSnapshot) return;

  state.analysis = result;
  state.status = 'ready';
  render();
}

function renderTopControls() {
  const bar = el('div', 'go-topbar');

  const modeWrap = el('div', 'go-mode-group');
  modeWrap.setAttribute('role', 'group');
  for (const m of ['simple', 'challenge']) {
    const btn = el('button', `learn-toggle-pill${state.mode === m ? ' is-active' : ''}`, t(`mode.${m}`));
    btn.type = 'button';
    btn.addEventListener('click', () => setMode(m));
    modeWrap.appendChild(btn);
  }

  const langWrap = el('div', 'pay-demo-langbar');
  const activeLang = getLang();
  for (const code of ['en', 'kn', 'hi']) {
    const btn = el('button', `learn-toggle-pill${activeLang === code ? ' is-active' : ''}`, t(`lang.${code}`));
    btn.type = 'button';
    btn.addEventListener('click', () => setLang(code));
    langWrap.appendChild(btn);
  }

  bar.appendChild(modeWrap);
  bar.appendChild(langWrap);
  return bar;
}

function renderDemoLinkBar() {
  const box = el('div', 'go-demo-box');
  const demoBtn = el('button', 'verify-chip go-demo-btn', t('go.tryRiskyBtn'));
  demoBtn.type = 'button';
  demoBtn.addEventListener('click', () => {
    window.location.hash = `u=${encodeBase64UrlUtf8(DEMO_RISKY_URL)}`;
  });
  box.appendChild(demoBtn);
  box.appendChild(el('span', 'go-demo-hint', t('go.tryRiskyHint')));
  return box;
}

function renderContinueControl(level) {
  const wrap = el('div', 'go-continue-wrap');
  const buildContinueAnchor = () => {
    const a = document.createElement('a');
    a.className = 'go-continue-link learn-btn-secondary';
    a.href = state.url;
    a.rel = 'noopener noreferrer';
    a.textContent = t('go.continueBtn');
    return a;
  };

  if (level === 'LOW') {
    wrap.appendChild(buildContinueAnchor());
    return wrap;
  }

  if (level === 'MEDIUM') {
    if (!state.mediumAccepted) {
      const ackBtn = el('button', 'learn-btn-secondary go-friction-btn', t('go.ackMediumBtn'));
      ackBtn.type = 'button';
      ackBtn.addEventListener('click', () => {
        state.mediumAccepted = true;
        render();
      });
      wrap.appendChild(ackBtn);
    } else {
      wrap.appendChild(buildContinueAnchor());
    }
    return wrap;
  }

  // HIGH or CRITICAL: hidden behind two deliberate taps
  if (state.highStep === 0) {
    const revealBtn = el('button', 'learn-btn-link go-friction-btn', t('go.showAnywayBtn'));
    revealBtn.type = 'button';
    revealBtn.addEventListener('click', () => {
      state.highStep = 1;
      render();
    });
    wrap.appendChild(revealBtn);
  } else if (state.highStep === 1) {
    const confirmBox = el('div', 'go-confirm-box');
    confirmBox.appendChild(el('p', 'go-confirm-text', t('go.highConfirmPrompt')));
    const confirmBtn = el('button', 'learn-btn-secondary go-friction-btn', t('go.highConfirmBtn'));
    confirmBtn.type = 'button';
    confirmBtn.addEventListener('click', () => {
      state.highStep = 2;
      render();
    });
    confirmBox.appendChild(confirmBtn);
    wrap.appendChild(confirmBox);
  } else {
    wrap.appendChild(buildContinueAnchor());
  }

  return wrap;
}

function render() {
  if (!root) return;
  root.replaceChildren();

  root.appendChild(renderTopControls());

  const card = el('div', 'learn-card-shell pay-demo-card go-gate-card');
  card.appendChild(el('span', 'verify-honesty-badge', t('go.tag')));
  card.appendChild(el('h1', 'pay-demo-title', t('go.title')));
  card.appendChild(el('p', 'pay-demo-sub', t('go.subtitle')));

  if (state.status === 'empty') {
    card.appendChild(el('p', 'go-status-note', t('go.emptyNote')));
    card.appendChild(renderDemoLinkBar());
    const actions = el('div', 'go-actions-row');
    const backLink = el('a', 'learn-btn-primary go-btn-link', t('go.goCheckBtn'));
    backLink.href = './index.html#check';
    actions.appendChild(backLink);
    card.appendChild(actions);
    root.appendChild(card);
    return;
  }

  if (state.status === 'blocked') {
    const box = el('div', 'pay-demo-verdict verdict-tampered go-verdict-box');
    box.appendChild(el('div', 'go-level-badge level-critical', t('go.blockedBadge')));
    box.appendChild(el('h2', 'go-blocked-title', t('go.blockedTitle')));
    box.appendChild(el('p', 'pay-demo-reason', t('go.blockedBody')));
    card.appendChild(box);
    card.appendChild(renderDemoLinkBar());

    const actions = el('div', 'go-actions-row');
    const backBtn = el('button', 'learn-btn-primary', t('go.goBackBtn'));
    backBtn.type = 'button';
    backBtn.addEventListener('click', goBackAction);
    actions.appendChild(backBtn);
    card.appendChild(actions);
    root.appendChild(card);
    return;
  }

  // Destination box (always plain textContent, host highlighted in <strong>)
  if (state.parsed) {
    const destWrap = el('div', 'go-dest-box');
    destWrap.appendChild(el('span', 'go-dest-label', t('go.destinationLabel')));
    const destText = el('div', 'go-dest-url');
    const parts = splitUrlHostParts(state.parsed);
    destText.appendChild(document.createTextNode(parts.beforeHost));
    destText.appendChild(el('strong', 'go-dest-host', parts.host));
    destText.appendChild(document.createTextNode(parts.afterHost));
    destWrap.appendChild(destText);
    card.appendChild(destWrap);
  }

  if (state.status === 'analyzing' || !state.analysis) {
    card.appendChild(el('p', 'pay-demo-status-msg', t('go.analyzing')));
    root.appendChild(card);
    return;
  }

  const res = state.analysis;
  const level = String(res.level || 'LOW').toUpperCase();
  const isLow = level === 'LOW';
  const verdictCls = isLow
    ? 'verdict-valid'
    : level === 'MEDIUM'
      ? 'verdict-expired'
      : 'verdict-tampered';

  const verdict = el('div', `pay-demo-verdict ${verdictCls} go-verdict-box`);
  const levelRow = el('div', 'go-level-row');
  levelRow.appendChild(el('span', `go-level-badge level-${level.toLowerCase()}`, t(`go.levels.${level}`)));
  levelRow.appendChild(el('span', 'go-score-pill', t('go.scoreText', { score: res.score ?? 0 })));
  verdict.appendChild(levelRow);

  const summaryText = isLow ? t('go.lowSummary') : t(`go.riskSummary.${level}`);
  verdict.appendChild(el('p', 'go-verdict-summary', summaryText));

  const reasons = [];
  const seen = new Set();
  for (const sig of Array.isArray(res.signals) ? res.signals : []) {
    const txt = translateSignalReason(sig);
    if (!seen.has(txt)) {
      seen.add(txt);
      reasons.push(txt);
    }
  }
  if (res.ml && typeof res.ml.urlProbability === 'number' && res.ml.urlProbability >= 0.5) {
    reasons.push(t('go.mlFlag', { pct: Math.round(res.ml.urlProbability * 100) }));
  }

  if (reasons.length > 0) {
    const ul = el('ul', 'go-reasons-list');
    for (const r of reasons) {
      ul.appendChild(el('li', 'go-reason-item', r));
    }
    verdict.appendChild(ul);
  }
  card.appendChild(verdict);

  // Action buttons
  const actions = el('div', 'go-actions-row');

  const backBtn = el('button', isLow ? 'learn-btn-secondary' : 'learn-btn-primary', t('go.goBackBtn'));
  backBtn.type = 'button';
  backBtn.addEventListener('click', goBackAction);
  actions.appendChild(backBtn);

  const checkMsgLink = el('a', 'learn-btn-secondary go-btn-link', t('go.checkWholeBtn'));
  checkMsgLink.href = `./index.html#check-u=${encodeBase64UrlUtf8(state.url)}`;
  actions.appendChild(checkMsgLink);

  const scenarioId = mapUrlResultToScenario(res);
  const practiseLink = el('a', 'learn-btn-secondary go-btn-link', t('go.practiseBtn'));
  practiseLink.href = `./index.html?mode=challenge&scam=${encodeURIComponent(scenarioId)}&lang=${encodeURIComponent(getLang())}#learn`;
  actions.appendChild(practiseLink);

  const reportLink = el('a', 'learn-btn-secondary go-btn-link', t('go.reportBtn'));
  reportLink.href = './index.html#report';
  actions.appendChild(reportLink);

  card.appendChild(actions);
  card.appendChild(renderContinueControl(level));
  card.appendChild(renderDemoLinkBar());

  card.appendChild(el('p', 'go-disclaimer', t('go.disclaimer')));
  root.appendChild(card);
}

window.addEventListener('hashchange', inspectCurrentHash);

(async () => {
  applyModeClass();
  await initI18n();
  onLangChange(() => render());
  await inspectCurrentHash();
})();
