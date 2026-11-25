/**
 * go.js – "Check before you go" client-side link gate for go.html.
 * Controls real DOM elements defined in go.html via .hidden class toggles.
 * Never auto-redirects, never logs/stores inspected URLs, never sends URLs to a server.
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

const $ = (id) => document.getElementById(id);

const state = {
  mode: readMode(),
  status: 'empty', // 'empty' | 'blocked' | 'analyzing' | 'ready' | 'analysis_failed'
  url: '',
  parsed: null,
  analysis: null,
  mediumAccepted: false,
  highStep: 0
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

function tOr(key, fallback, vars) {
  try {
    const val = t(key, vars);
    return val && val !== key ? val : fallback;
  } catch {
    return fallback;
  }
}

function setHidden(el, hidden) {
  if (el) el.classList.toggle('hidden', Boolean(hidden));
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
  return tOr(key, sig.explanation || tOr('go.signals.generic', 'Suspicious link pattern identified.'));
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

function bindStaticListeners() {
  $('go-mode-simple')?.addEventListener('click', () => setMode('simple'));
  $('go-mode-challenge')?.addEventListener('click', () => setMode('challenge'));
  $('go-lang-en')?.addEventListener('click', () => { Promise.resolve(setLang('en')).catch(() => {}); });
  $('go-lang-kn')?.addEventListener('click', () => { Promise.resolve(setLang('kn')).catch(() => {}); });
  $('go-lang-hi')?.addEventListener('click', () => { Promise.resolve(setLang('hi')).catch(() => {}); });
  $('go-back-btn')?.addEventListener('click', goBackAction);

  $('go-demo-risky-btn')?.addEventListener('click', () => {
    window.location.hash = `u=${encodeBase64UrlUtf8(DEMO_RISKY_URL)}`;
  });

  $('go-ack-btn')?.addEventListener('click', () => {
    state.mediumAccepted = true;
    render();
  });

  $('go-show-anyway-btn')?.addEventListener('click', () => {
    state.highStep = 1;
    render();
  });

  $('go-confirm-btn')?.addEventListener('click', () => {
    state.highStep = 2;
    render();
  });
}

async function inspectCurrentHash() {
  state.mediumAccepted = false;
  state.highStep = 0;
  state.analysis = null;
  state.url = '';
  state.parsed = null;

  let rawParam = '';
  try {
    rawParam = extractFragmentParam(window.location.hash, 'u');
  } catch {
    state.status = 'blocked';
    render();
    return;
  }

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
  try {
    const result = await runClientSideAnalysis(targetSnapshot, true);
    if (state.url !== targetSnapshot) return;
    if (!result || typeof result.level !== 'string') {
      throw new Error('Invalid analysis response');
    }
    state.analysis = result;
    state.status = 'ready';
  } catch {
    if (state.url !== targetSnapshot) return;
    state.analysis = null;
    state.status = 'analysis_failed';
  }
  render();
}

function renderTopBarState() {
  $('go-mode-simple')?.classList.toggle('is-active', state.mode === 'simple');
  $('go-mode-challenge')?.classList.toggle('is-active', state.mode === 'challenge');
  const lang = getLang();
  for (const code of ['en', 'kn', 'hi']) {
    $(`go-lang-${code}`)?.classList.toggle('is-active', lang === code);
  }
}

function renderDestinationBox() {
  const destBox = $('go-dest-box');
  if (!state.url || !state.parsed) {
    setHidden(destBox, true);
    return;
  }
  const beforeEl = $('go-dest-before');
  const hostEl = $('go-dest-host');
  const afterEl = $('go-dest-after');

  try {
    const parts = splitUrlHostParts(state.parsed);
    if (beforeEl) beforeEl.textContent = parts.beforeHost;
    if (hostEl) hostEl.textContent = parts.host;
    if (afterEl) afterEl.textContent = parts.afterHost;
  } catch {
    if (beforeEl) beforeEl.textContent = state.url;
    if (hostEl) hostEl.textContent = '';
    if (afterEl) afterEl.textContent = '';
  }
  setHidden(destBox, false);
}

function renderContinueControls(hasValidHttpUrl, level) {
  const wrap = $('go-continue-wrap');
  const ackBtn = $('go-ack-btn');
  const showAnywayBtn = $('go-show-anyway-btn');
  const confirmBox = $('go-confirm-box');
  const continueLink = $('go-continue-link');

  setHidden(ackBtn, true);
  setHidden(showAnywayBtn, true);
  setHidden(confirmBox, true);
  setHidden(continueLink, true);

  if (!hasValidHttpUrl || !state.url) {
    setHidden(wrap, true);
    if (continueLink) continueLink.href = './index.html#check';
    return;
  }

  setHidden(wrap, false);
  if (continueLink) continueLink.href = state.url;

  if (state.status === 'ready' && level === 'LOW') {
    setHidden(continueLink, false);
    return;
  }

  if (state.status === 'ready' && (level === 'HIGH' || level === 'CRITICAL')) {
    if (state.highStep === 0) {
      setHidden(showAnywayBtn, false);
    } else if (state.highStep === 1) {
      setHidden(confirmBox, false);
    } else {
      setHidden(continueLink, false);
    }
    return;
  }

  // MEDIUM, analyzing fallback, or analysis_failed: require "I understand the risks" confirm first
  if (!state.mediumAccepted) {
    setHidden(ackBtn, false);
  } else {
    setHidden(continueLink, false);
  }
}

function render() {
  renderTopBarState();

  const emptyNote = $('go-empty-note');
  const blockedBox = $('go-blocked-box');
  const analyzingMsg = $('go-analyzing-msg');
  const verdictBox = $('go-verdict-box');
  const levelBadge = $('go-level-badge');
  const scorePill = $('go-score-pill');
  const summaryEl = $('go-verdict-summary');
  const reasonsList = $('go-reasons-list');

  const backBtn = $('go-back-btn');
  const checkWholeLink = $('go-check-whole-link');
  const practiseLink = $('go-practise-link');
  const reportLink = $('go-report-link');

  setHidden(emptyNote, state.status !== 'empty');
  setHidden(blockedBox, state.status !== 'blocked');
  setHidden(analyzingMsg, state.status !== 'analyzing');

  renderDestinationBox();

  const hasValidUrl = Boolean(
    state.url &&
    (state.status === 'analyzing' || state.status === 'ready' || state.status === 'analysis_failed')
  );

  // Action choices: Go back is always visible; helper links show whenever a valid URL exists
  const isMediumOrAbove =
    state.status === 'blocked' ||
    state.status === 'analysis_failed' ||
    (state.status === 'ready' && String(state.analysis?.level || '').toUpperCase() !== 'LOW');

  if (backBtn) {
    backBtn.className = isMediumOrAbove || state.status === 'empty' ? 'learn-btn-primary' : 'learn-btn-secondary';
    setHidden(backBtn, false);
  }

  if (checkWholeLink) {
    checkWholeLink.href = hasValidUrl
      ? `./index.html#check-u=${encodeBase64UrlUtf8(state.url)}`
      : './index.html#check';
    setHidden(checkWholeLink, !hasValidUrl);
  }

  if (practiseLink) {
    const scenarioId = mapUrlResultToScenario(state.analysis);
    practiseLink.href = `./index.html?mode=challenge&scam=${encodeURIComponent(scenarioId)}&lang=${encodeURIComponent(getLang())}#learn`;
    setHidden(practiseLink, !hasValidUrl);
  }

  setHidden(reportLink, !hasValidUrl && state.status !== 'blocked');

  // Verdict card for ready or analysis_failed
  if (state.status === 'analysis_failed') {
    if (verdictBox) verdictBox.className = 'pay-demo-verdict verdict-expired go-verdict-box';
    if (levelBadge) {
      levelBadge.className = 'go-level-badge level-medium';
      levelBadge.textContent = tOr('go.analysisFailedBadge', 'UNCHECKED');
    }
    if (scorePill) scorePill.textContent = '';
    if (summaryEl) summaryEl.textContent = tOr('go.analysisFailedMsg', 'We could not check this link');
    if (reasonsList) {
      reasonsList.replaceChildren();
      setHidden(reasonsList, true);
    }
    setHidden(verdictBox, false);
    renderContinueControls(true, 'MEDIUM');
    return;
  }

  if (state.status === 'ready' && state.analysis) {
    const res = state.analysis;
    const level = String(res.level || 'LOW').toUpperCase();
    const isLow = level === 'LOW';
    const verdictCls = isLow
      ? 'verdict-valid'
      : level === 'MEDIUM'
        ? 'verdict-expired'
        : 'verdict-tampered';

    if (verdictBox) verdictBox.className = `pay-demo-verdict ${verdictCls} go-verdict-box`;
    if (levelBadge) {
      levelBadge.className = `go-level-badge level-${level.toLowerCase()}`;
      levelBadge.textContent = tOr(`go.levels.${level}`, `${level} RISK`);
    }
    if (scorePill) {
      scorePill.textContent = tOr('go.scoreText', `Risk score: ${res.score ?? 0}/100`, { score: res.score ?? 0 });
    }
    if (summaryEl) {
      summaryEl.textContent = isLow
        ? tOr('go.lowSummary', 'No strong red flags found. Still be careful.')
        : tOr(`go.riskSummary.${level}`, res.summary || '');
    }

    if (reasonsList) {
      reasonsList.replaceChildren();
      const seen = new Set();
      for (const sig of Array.isArray(res.signals) ? res.signals : []) {
        const txt = translateSignalReason(sig);
        if (!seen.has(txt)) {
          seen.add(txt);
          const li = document.createElement('li');
          li.className = 'go-reason-item';
          li.textContent = txt;
          reasonsList.appendChild(li);
        }
      }
      if (res.ml && typeof res.ml.urlProbability === 'number' && res.ml.urlProbability >= 0.5) {
        const pct = Math.round(res.ml.urlProbability * 100);
        const li = document.createElement('li');
        li.className = 'go-reason-item';
        li.textContent = tOr('go.mlFlag', `On-device URL model flagged ${pct}% similarity to scam links.`, { pct });
        reasonsList.appendChild(li);
      }
      setHidden(reasonsList, reasonsList.childElementCount === 0);
    }

    setHidden(verdictBox, false);
    renderContinueControls(true, level);
    return;
  }

  setHidden(verdictBox, true);
  renderContinueControls(hasValidUrl, 'MEDIUM');
}

bindStaticListeners();
window.addEventListener('hashchange', inspectCurrentHash);

(async () => {
  applyModeClass();
  render();
  try {
    await initI18n();
  } catch {
    // Keep built-in fallback copy rendered if dictionary fetch fails
  }
  onLangChange(() => render());
  await inspectCurrentHash();
})();
