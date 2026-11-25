/**
 * learn.js – Interactive UPI Scam Simulator (#learn module).
 *
 * Fully client-side (reads static/data/scenarios.json + static/i18n/{lang}.json),
 * works with the Spring Boot server off, uses createElement + textContent only
 * (zero innerHTML), and adapts live when language or mode changes.
 */

import { initI18n, t, getLang, setLang, onLangChange } from './i18n.js';

const STORAGE_MODE = 'uss.mode';
const STORAGE_BEST = 'uss.best';
const TIMER_TOTAL_SEC = 20;

const learnRoot = document.getElementById('learn-root');

const state = {
  loaded: false,
  loadError: false,
  scenarios: [],
  byId: new Map(),
  mode: readMode(),
  bestScore: readBestScore(),
  screen: 'start', // 'start' | 'play' | 'result'
  queue: [],
  queueIdx: 0,
  totalUnique: 0,
  initialAttempts: new Map(), // scenarioId -> boolean (true if correct on first encounter)
  missedIds: [],              // unique scenarioIds missed on first encounter (for weak spots)
  requeuedOnceIds: new Set(), // scenarioIds already re-queued once
  // Active scenario state
  phase: 1, // 1 = spot red flags, 2 = choose action, 'feedback' = post-answer
  foundFlagIndices: new Set(),
  wrongTapCount: 0,
  wrongTapMsgVisible: false,
  selectedOptionId: null,
  simpleChoice: null, // 'trust' | 'dont-trust' | null
  timedOut: false,
  lastPointsDelta: 0,
  wasRequeuedThisTurn: false,
  score: 0,
  streak: 0,
  bestRunSavedNew: false,
  // Timer state
  timerRemainingMs: TIMER_TOTAL_SEC * 1000,
  timerStartedAt: 0,
  timerHandle: null,
  // Single-scenario launch flag
  focusedSingle: false
};

// DOM refs updated per play render so timer updates don't rebuild the whole DOM every 100ms
let liveTimerBar = null;
let liveTimerLabel = null;
let toastTimeout = null;

// ── Storage helpers (always wrapped in try/catch, keys prefixed with "uss.") ──

function readMode() {
  try {
    const val = localStorage.getItem(STORAGE_MODE);
    return val === 'simple' ? 'simple' : 'challenge';
  } catch {
    return 'challenge';
  }
}

function writeMode(mode) {
  try {
    localStorage.setItem(STORAGE_MODE, mode);
  } catch {
    // ignore storage limits
  }
}

function readBestScore() {
  try {
    const raw = localStorage.getItem(STORAGE_BEST);
    if (raw === null) return null;
    const num = Number(raw);
    return Number.isFinite(num) && num >= 0 && num <= 100 ? Math.round(num) : null;
  } catch {
    return null;
  }
}

function writeBestScore(score) {
  try {
    localStorage.setItem(STORAGE_BEST, String(score));
  } catch {
    // ignore storage limits
  }
}

function applyModeBodyClass() {
  const isSimple = state.mode === 'simple';
  document.body.classList.toggle('uss-simple', isSimple);
  if (window.cyberVortex && isSimple) {
    window.cyberVortex.setMood('calm');
  }
}

function setMode(nextMode) {
  const normalized = nextMode === 'simple' ? 'simple' : 'challenge';
  if (state.mode === normalized) return;
  state.mode = normalized;
  writeMode(normalized);
  applyModeBodyClass();
  stopTimer();
  if (state.screen === 'play') {
    // Keep current scenario cleanly reset for the newly selected mode UX
    const currentId = state.queue[state.queueIdx];
    prepareScenarioState(currentId);
  }
  render();
}

// ── Utility helpers (textContent-safe) ────────────────────────────────────

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = text;
  return node;
}

const SVG_NS = 'http://www.w3.org/2000/svg';

function svgIcon(viewBox, paths, className) {
  const svg = document.createElementNS(SVG_NS, 'svg');
  svg.setAttribute('viewBox', viewBox);
  svg.setAttribute('fill', 'none');
  svg.setAttribute('stroke', 'currentColor');
  svg.setAttribute('stroke-width', '2');
  svg.setAttribute('stroke-linecap', 'round');
  svg.setAttribute('stroke-linejoin', 'round');
  svg.setAttribute('aria-hidden', 'true');
  if (className) svg.setAttribute('class', className);
  for (const spec of paths) {
    const child = document.createElementNS(SVG_NS, spec.tag || 'path');
    for (const [k, v] of Object.entries(spec.attrs || {})) {
      child.setAttribute(k, v);
    }
    svg.appendChild(child);
  }
  return svg;
}

function formatRupees(n) {
  const num = Number(n) || 0;
  return `Rs.${num.toLocaleString('en-IN')}`;
}

function prefersReducedMotion() {
  return Boolean(
    window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches
  );
}

// ── Scenario data loading ─────────────────────────────────────────────────

async function loadScenarios() {
  try {
    const res = await fetch('data/scenarios.json');
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const list = await res.json();
    if (!Array.isArray(list) || list.length === 0) throw new Error('Empty scenarios');
    state.scenarios = list;
    state.byId = new Map(list.map((s) => [s.id, s]));
    state.loaded = true;
    state.loadError = false;
  } catch (err) {
    console.error('[learn] Failed to load scenarios:', err);
    state.loaded = false;
    state.loadError = true;
  }
}

// ── Red-flag offset tokenization ──────────────────────────────────────────

function computeFlagRanges(message, flags) {
  const ranges = [];
  if (!message || !Array.isArray(flags)) return ranges;
  flags.forEach((flagText, idx) => {
    if (!flagText) return;
    const start = message.indexOf(flagText);
    if (start !== -1) {
      ranges.push({ index: idx, text: flagText, start, end: start + flagText.length });
    }
  });
  return ranges;
}

function tokenizeMessage(message) {
  const tokens = [];
  const regex = /\S+|\s+/g;
  let match;
  while ((match = regex.exec(message)) !== null) {
    tokens.push({
      text: match[0],
      start: match.index,
      end: match.index + match[0].length,
      isSpace: /^\s+$/.test(match[0])
    });
  }
  return tokens;
}

function matchingFlagIndices(token, flagRanges) {
  const hits = [];
  for (const fr of flagRanges) {
    if (token.start < fr.end && token.end > fr.start) {
      hits.push(fr.index);
    }
  }
  return hits;
}

// ── Session & Timer lifecycle ─────────────────────────────────────────────

function startRun(scenarioIds, focusedSingle = false) {
  stopTimer();
  state.queue = [...scenarioIds];
  state.queueIdx = 0;
  state.totalUnique = new Set(scenarioIds).size;
  state.initialAttempts = new Map();
  state.missedIds = [];
  state.requeuedOnceIds = new Set();
  state.score = 0;
  state.streak = 0;
  state.bestRunSavedNew = false;
  state.focusedSingle = focusedSingle;
  state.screen = 'play';
  prepareScenarioState(state.queue[0]);
  render();
}

function prepareScenarioState(scenarioId) {
  stopTimer();
  const sc = state.byId.get(scenarioId);
  const lang = getLang();
  const flags = sc && sc.redFlags ? (sc.redFlags[lang] || sc.redFlags.en || []) : [];
  state.phase = (state.mode === 'simple' || flags.length === 0) ? 2 : 1;
  state.foundFlagIndices = new Set();
  state.wrongTapCount = 0;
  state.wrongTapMsgVisible = false;
  state.selectedOptionId = null;
  state.simpleChoice = null;
  state.timedOut = false;
  state.lastPointsDelta = 0;
  state.wasRequeuedThisTurn = false;
  state.timerRemainingMs = TIMER_TOTAL_SEC * 1000;

  if (state.mode === 'challenge' && state.screen === 'play' && scenarioId) {
    startTimer();
  }
}

function startTimer() {
  stopTimer();
  state.timerStartedAt = Date.now();
  state.timerRemainingMs = TIMER_TOTAL_SEC * 1000;

  state.timerHandle = setInterval(() => {
    const elapsed = Date.now() - state.timerStartedAt;
    const rem = Math.max(0, TIMER_TOTAL_SEC * 1000 - elapsed);
    state.timerRemainingMs = rem;
    updateLiveTimerDom();

    if (rem <= 0) {
      handleTimeout();
    }
  }, 100);
}

function stopTimer() {
  if (state.timerHandle !== null) {
    clearInterval(state.timerHandle);
    state.timerHandle = null;
  }
}

function updateLiveTimerDom() {
  if (!liveTimerBar || !liveTimerLabel) return;
  const pct = Math.max(0, Math.min(100, (state.timerRemainingMs / (TIMER_TOTAL_SEC * 1000)) * 100));
  const sec = Math.ceil(state.timerRemainingMs / 1000);
  liveTimerBar.style.width = `${pct}%`;
  liveTimerBar.classList.toggle('is-urgent', sec <= 5);
  liveTimerLabel.textContent = t('learn.game.timerLabel', { sec });
}

function handleTimeout() {
  if (state.phase === 'feedback' || state.mode !== 'challenge') return;
  stopTimer();
  const scenario = state.byId.get(state.queue[state.queueIdx]);
  if (!scenario) return;

  state.timedOut = true;
  state.phase = 'feedback';
  state.streak = 0;
  state.lastPointsDelta = 0;
  recordAttempt(scenario, false);
  render();
}

function recordAttempt(scenario, isCorrect) {
  if (!state.initialAttempts.has(scenario.id)) {
    state.initialAttempts.set(scenario.id, isCorrect);
  }
  if (!isCorrect) {
    if (!state.missedIds.includes(scenario.id)) {
      state.missedIds.push(scenario.id);
    }
    if (state.mode === 'challenge' && !state.requeuedOnceIds.has(scenario.id)) {
      state.requeuedOnceIds.add(scenario.id);
      const insertAt = Math.min(state.queue.length, state.queueIdx + 3);
      state.queue.splice(insertAt, 0, scenario.id);
      state.wasRequeuedThisTurn = true;
    }
  }
}

function handleChallengeOptionClick(option) {
  if (state.phase === 'feedback') return;
  stopTimer();
  const scenario = state.byId.get(state.queue[state.queueIdx]);
  if (!scenario) return;

  state.selectedOptionId = option.id;
  state.phase = 'feedback';

  if (option.correct) {
    state.score += 10;
    state.streak += 1;
    state.lastPointsDelta = 10;
    recordAttempt(scenario, true);
  } else {
    state.streak = 0;
    state.lastPointsDelta = 0;
    recordAttempt(scenario, false);
  }
  render();
}

function handleSimpleChoiceClick(choice) {
  if (state.phase === 'feedback') return;
  const scenario = state.byId.get(state.queue[state.queueIdx]);
  if (!scenario) return;

  state.simpleChoice = choice; // 'trust' | 'dont-trust'
  const isCorrect = choice === 'dont-trust';
  state.phase = 'feedback';
  recordAttempt(scenario, isCorrect);
  render();
}

function advanceScenario() {
  stopTimer();
  if (state.queueIdx + 1 < state.queue.length) {
    state.queueIdx += 1;
    prepareScenarioState(state.queue[state.queueIdx]);
    render();
  } else {
    finishRun();
  }
}

function finishRun() {
  stopTimer();
  state.screen = 'result';
  if (state.mode === 'challenge' && state.totalUnique > 0) {
    const correctCount = countInitialCorrect();
    const safetyScore = Math.round((100 * correctCount) / state.totalUnique);
    if (!state.focusedSingle && (state.bestScore === null || safetyScore > state.bestScore)) {
      state.bestScore = safetyScore;
      state.bestRunSavedNew = true;
      writeBestScore(safetyScore);
    }
  }
  render();
}

function countInitialCorrect() {
  let count = 0;
  state.initialAttempts.forEach((ok) => {
    if (ok) count += 1;
  });
  return count;
}

// ── Top Controls (Language + Challenge/Simple Mode) ───────────────────────

function buildControlsBar() {
  const bar = el('div', 'learn-controls-bar');

  // Mode toggle group
  const modeGroup = el('div', 'learn-control-group');
  modeGroup.setAttribute('role', 'group');
  modeGroup.setAttribute('aria-label', t('mode.label'));

  const modeLbl = el('span', 'learn-control-label', `${t('mode.label')}:`);
  modeGroup.appendChild(modeLbl);

  const btnChallenge = el('button', `learn-toggle-pill${state.mode === 'challenge' ? ' is-active' : ''}`, t('mode.challenge'));
  btnChallenge.type = 'button';
  btnChallenge.setAttribute('aria-pressed', String(state.mode === 'challenge'));
  btnChallenge.title = t('mode.switchToChallenge');
  btnChallenge.addEventListener('click', () => setMode('challenge'));

  const btnSimple = el('button', `learn-toggle-pill${state.mode === 'simple' ? ' is-active' : ''}`, t('mode.simple'));
  btnSimple.type = 'button';
  btnSimple.setAttribute('aria-pressed', String(state.mode === 'simple'));
  btnSimple.title = t('mode.switchToSimple');
  btnSimple.addEventListener('click', () => setMode('simple'));

  modeGroup.appendChild(btnChallenge);
  modeGroup.appendChild(btnSimple);

  // Language switcher group
  const langGroup = el('div', 'learn-control-group');
  langGroup.setAttribute('role', 'group');
  langGroup.setAttribute('aria-label', t('lang.label'));

  const langLbl = el('span', 'learn-control-label', `${t('lang.label')}:`);
  langGroup.appendChild(langLbl);

  const activeLang = getLang();
  for (const code of ['en', 'kn', 'hi']) {
    const btn = el('button', `learn-toggle-pill${activeLang === code ? ' is-active' : ''}`, t(`lang.${code}`));
    btn.type = 'button';
    btn.setAttribute('aria-pressed', String(activeLang === code));
    btn.addEventListener('click', () => {
      if (getLang() !== code) {
        setLang(code);
      }
    });
    langGroup.appendChild(btn);
  }

  bar.appendChild(modeGroup);
  bar.appendChild(langGroup);
  return bar;
}

// ── Start Screen ──────────────────────────────────────────────────────────

function renderStartScreen(container) {
  const header = el('div', 'section-header');
  header.appendChild(el('span', 'section-tag', t('learn.tag')));
  const h2 = el('h2', 'section-heading', t('learn.start.title'));
  h2.id = 'learn-heading';
  header.appendChild(h2);
  header.appendChild(el('p', 'section-sub', t('learn.start.subtitle')));
  container.appendChild(header);

  container.appendChild(buildControlsBar());

  if (state.loadError) {
    const errCard = el('div', 'learn-card-shell learn-error-card');
    errCard.appendChild(el('p', 'learn-error-text', t('learn.game.loadError')));
    const retryBtn = el('button', 'learn-btn-primary', t('learn.game.retryLoad'));
    retryBtn.type = 'button';
    retryBtn.addEventListener('click', async () => {
      await loadScenarios();
      render();
    });
    errCard.appendChild(retryBtn);
    container.appendChild(errCard);
    return;
  }

  const card = el('div', 'learn-card-shell learn-start-card');

  const metaGrid = el('div', 'learn-start-meta');
  const modePill = el('div', 'learn-stat-box');
  modePill.appendChild(el('span', 'learn-stat-label', t('learn.start.currentMode')));
  modePill.appendChild(el('strong', 'learn-stat-value', t(`mode.${state.mode}`)));
  metaGrid.appendChild(modePill);

  const bestPill = el('div', 'learn-stat-box');
  bestPill.appendChild(el('span', 'learn-stat-label', t('learn.start.bestScore')));
  const bestText = state.bestScore !== null
    ? `${state.bestScore} ${t('learn.start.scoreSuffix')}`
    : t('learn.start.noBest');
  bestPill.appendChild(el('strong', 'learn-stat-value', bestText));
  metaGrid.appendChild(bestPill);

  card.appendChild(metaGrid);

  const actionsRow = el('div', 'learn-start-actions');
  const startBtn = el('button', 'learn-btn-primary', t('learn.start.startBtn'));
  startBtn.type = 'button';
  startBtn.id = 'learn-start-btn';
  startBtn.disabled = !state.loaded;
  startBtn.addEventListener('click', () => {
    if (!state.loaded) return;
    startRun(state.scenarios.map((s) => s.id), false);
  });
  actionsRow.appendChild(startBtn);
  card.appendChild(actionsRow);

  // Quick tips panel (preserved & translated from the original #learn section)
  const tipsPanel = el('details', 'learn-quick-tips');
  const tipsSummary = el('summary', 'learn-quick-tips-summary', t('learn.start.quickTipsTitle'));
  tipsPanel.appendChild(tipsSummary);

  const tipsList = el('ul', 'learn-quick-tips-list');
  for (const key of ['pin', 'links', 'arrest', 'apps']) {
    tipsList.appendChild(el('li', '', t(`learn.start.tips.${key}`)));
  }
  tipsPanel.appendChild(tipsList);
  card.appendChild(tipsPanel);

  container.appendChild(card);
}

// ── Phone Card Renderer (channel-aware) ───────────────────────────────────

function buildPhoneCard(scenario, lang, flagRanges, interactiveTokens, autoRevealAllFlags) {
  const ch = scenario.channel || 'sms';
  const card = el('div', `phone-mockup phone-channel-${ch}`);

  // Phone top bar
  const topBar = el('div', 'phone-topbar');
  topBar.appendChild(buildChannelIcon(ch));
  const titleGroup = el('div', 'phone-topbar-text');
  titleGroup.appendChild(el('span', 'phone-channel-name', t(`learn.channels.${ch}`)));

  if (ch === 'call') {
    titleGroup.appendChild(el('span', 'phone-caller-sub', t('learn.phone.unknownCaller')));
  } else if (ch === 'whatsapp' || ch === 'qr') {
    titleGroup.appendChild(el('span', 'phone-caller-sub', t('learn.phone.unknownSender')));
  } else if (ch === 'payment') {
    const demoBadge = el('span', 'phone-demo-badge', t('learn.phone.demoPaymentBadge'));
    titleGroup.appendChild(demoBadge);
  }
  topBar.appendChild(titleGroup);
  card.appendChild(topBar);

  // Channel body
  const body = el('div', 'phone-body');
  if (ch === 'qr') {
    body.appendChild(buildDemoQrGraphic());
  }

  const msgText = scenario.message[lang] || scenario.message.en || '';
  const bubble = el('div', `phone-bubble bubble-${ch}`);
  const tokens = tokenizeMessage(msgText);

  for (const tok of tokens) {
    if (tok.isSpace) {
      bubble.appendChild(document.createTextNode(tok.text));
      continue;
    }

    const hits = matchingFlagIndices(tok, flagRanges);
    const isHitFound = hits.some((idx) => state.foundFlagIndices.has(idx));
    const isMissedReveal = autoRevealAllFlags && hits.length > 0 && !isHitFound;

    if (interactiveTokens) {
      const btn = el('button', 'msg-token', tok.text);
      btn.type = 'button';
      if (isHitFound) {
        btn.classList.add('is-flag-hit');
        btn.setAttribute('aria-pressed', 'true');
      } else {
        btn.setAttribute('aria-pressed', 'false');
      }
      btn.addEventListener('click', () => handleTokenTap(btn, hits, flagRanges));
      bubble.appendChild(btn);
    } else {
      const span = el('span', 'msg-token-static', tok.text);
      if (isHitFound) {
        span.classList.add('is-flag-hit');
      } else if (isMissedReveal) {
        span.classList.add('is-flag-missed');
      }
      bubble.appendChild(span);
    }
  }

  body.appendChild(bubble);
  card.appendChild(body);
  return card;
}

function buildChannelIcon(channel) {
  switch (channel) {
    case 'call':
      return svgIcon('0 0 24 24', [
        { tag: 'path', attrs: { d: 'M22 16.92v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07 19.5 19.5 0 0 1-6-6 19.79 19.79 0 0 1-3.07-8.67A2 2 0 0 1 4.11 2h3a2 2 0 0 1 2 1.72c.13.96.36 1.9.7 2.81a2 2 0 0 1-.45 2.11L8.09 9.91a16 16 0 0 0 6 6l1.27-1.27a2 2 0 0 1 2.11-.45c.91.34 1.85.57 2.81.7A2 2 0 0 1 22 16.92z' } }
      ], 'phone-channel-svg');
    case 'whatsapp':
      return svgIcon('0 0 24 24', [
        { tag: 'path', attrs: { d: 'M21 11.5a8.38 8.38 0 0 1-.9 3.8 8.5 8.5 0 0 1-7.6 4.7 8.38 8.38 0 0 1-3.8-.9L3 21l1.9-5.7a8.38 8.38 0 0 1-.9-3.8 8.5 8.5 0 0 1 4.7-7.6 8.38 8.38 0 0 1 3.8-.9h.5a8.48 8.48 0 0 1 8 8v.5z' } }
      ], 'phone-channel-svg');
    case 'payment':
      return svgIcon('0 0 24 24', [
        { tag: 'rect', attrs: { x: '2', y: '5', width: '20', height: '14', rx: '2' } },
        { tag: 'line', attrs: { x1: '2', y1: '10', x2: '22', y2: '10' } }
      ], 'phone-channel-svg');
    case 'qr':
      return svgIcon('0 0 24 24', [
        { tag: 'rect', attrs: { x: '3', y: '3', width: '7', height: '7' } },
        { tag: 'rect', attrs: { x: '14', y: '3', width: '7', height: '7' } },
        { tag: 'rect', attrs: { x: '3', y: '14', width: '7', height: '7' } },
        { tag: 'path', attrs: { d: 'M14 14h3v3h-3zM18 18h3v3h-3zM14 20h2' } }
      ], 'phone-channel-svg');
    case 'app':
      return svgIcon('0 0 24 24', [
        { tag: 'rect', attrs: { x: '5', y: '2', width: '14', height: '20', rx: '2' } },
        { tag: 'path', attrs: { d: 'M12 7v6m-3-3 3 3 3-3' } }
      ], 'phone-channel-svg');
    default: // sms
      return svgIcon('0 0 24 24', [
        { tag: 'path', attrs: { d: 'M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z' } },
        { tag: 'polyline', attrs: { points: '22,6 12,13 2,6' } }
      ], 'phone-channel-svg');
  }
}

function buildDemoQrGraphic() {
  const wrap = el('div', 'demo-qr-box');
  // Non-scannable stylized SVG placeholder — zero real QR data
  const svg = svgIcon('0 0 64 64', [
    { tag: 'rect', attrs: { x: '4', y: '4', width: '18', height: '18', rx: '2' } },
    { tag: 'rect', attrs: { x: '42', y: '4', width: '18', height: '18', rx: '2' } },
    { tag: 'rect', attrs: { x: '4', y: '42', width: '18', height: '18', rx: '2' } },
    { tag: 'path', attrs: { d: 'M28 10h8M28 18h4M10 28h12M30 28h12M48 28h12M28 42h8M44 42h10M30 52h18' } }
  ], 'demo-qr-svg');
  wrap.appendChild(svg);
  wrap.appendChild(el('span', 'demo-qr-caption', t('learn.phone.demoQrCaption')));
  return wrap;
}

function handleTokenTap(btnEl, hitIndices, flagRanges) {
  if (state.phase !== 1) return;

  if (hitIndices.length === 0) {
    state.wrongTapCount += 1;
    state.wrongTapMsgVisible = true;
    if (!prefersReducedMotion() && state.mode !== 'simple') {
      btnEl.classList.remove('is-token-shake');
      void btnEl.offsetWidth; // trigger reflow for shake replay
      btnEl.classList.add('is-token-shake');
    }
    const hintEl = document.getElementById('learn-phase1-wrong');
    if (hintEl) {
      hintEl.textContent = t('learn.game.wrongTap');
      hintEl.classList.remove('hidden');
    }
    return;
  }

  let addedNew = false;
  for (const idx of hitIndices) {
    if (!state.foundFlagIndices.has(idx)) {
      state.foundFlagIndices.add(idx);
      state.score += 2;
      addedNew = true;
    }
  }
  state.wrongTapMsgVisible = false;

  if (addedNew && state.foundFlagIndices.size >= flagRanges.length) {
    // All red flags found — move cleanly to Phase 2 while preserving timer
    state.phase = 2;
  }
  render();
}

// ── Play Screen (Challenge & Simple Modes) ────────────────────────────────

function renderPlayScreen(container) {
  const scenario = state.byId.get(state.queue[state.queueIdx]);
  if (!scenario) {
    finishRun();
    return;
  }

  const lang = getLang();
  const msgText = scenario.message[lang] || scenario.message.en || '';
  const flags = (scenario.redFlags && (scenario.redFlags[lang] || scenario.redFlags.en)) || [];
  const flagRanges = computeFlagRanges(msgText, flags);

  container.appendChild(buildControlsBar());

  const card = el('div', 'learn-card-shell learn-play-card');

  // Top HUD row
  const hud = el('div', 'learn-hud');
  const currentNum = Math.min(state.queueIdx + 1, state.queue.length);
  const progressSpan = el(
    'span',
    'learn-progress-pill',
    t('learn.game.progress', { current: currentNum, total: state.queue.length })
  );
  hud.appendChild(progressSpan);

  if (state.mode === 'challenge') {
    const stats = el('div', 'learn-hud-stats');
    stats.appendChild(el('span', 'learn-hud-stat', `${t('learn.game.scoreLabel')}: ${state.score}`));
    stats.appendChild(el('span', 'learn-hud-stat', `${t('learn.game.streakLabel')}: ${state.streak}`));
    hud.appendChild(stats);
  }
  card.appendChild(hud);

  // Draining 20-second timer (Challenge mode only)
  if (state.mode === 'challenge') {
    const timerWrap = el('div', 'learn-timer-wrap');
    const sec = Math.ceil(state.timerRemainingMs / 1000);
    const pct = Math.max(0, Math.min(100, (state.timerRemainingMs / (TIMER_TOTAL_SEC * 1000)) * 100));

    const timerRow = el('div', 'learn-timer-row');
    liveTimerLabel = el('span', 'learn-timer-text', t('learn.game.timerLabel', { sec }));
    timerRow.appendChild(liveTimerLabel);
    timerWrap.appendChild(timerRow);

    const track = el('div', 'learn-timer-track');
    track.setAttribute('aria-hidden', 'true');
    liveTimerBar = el('div', 'learn-timer-fill');
    liveTimerBar.style.width = `${pct}%`;
    if (sec <= 5) liveTimerBar.classList.add('is-urgent');
    track.appendChild(liveTimerBar);
    timerWrap.appendChild(track);
    card.appendChild(timerWrap);
  } else {
    liveTimerBar = null;
    liveTimerLabel = null;
  }

  // Phone mockup (interactive tokens in Challenge Phase 1; auto-highlighted on feedback/Simple post-choice)
  const isInteractiveTokens = state.mode === 'challenge' && state.phase === 1;
  const autoRevealAllFlags = state.phase === 'feedback';
  card.appendChild(buildPhoneCard(scenario, lang, flagRanges, isInteractiveTokens, autoRevealAllFlags));

  // Interaction phase area
  if (state.mode === 'challenge') {
    renderChallengeInteraction(card, scenario, lang, flagRanges);
  } else {
    renderSimpleInteraction(card, scenario, lang, flags);
  }

  // Secondary escape hatch back to start screen
  const bottomNav = el('div', 'learn-bottom-nav');
  const backBtn = el('button', 'learn-btn-link', t('learn.game.backToStart'));
  backBtn.type = 'button';
  backBtn.addEventListener('click', () => {
    stopTimer();
    state.screen = 'start';
    render();
  });
  bottomNav.appendChild(backBtn);
  card.appendChild(bottomNav);

  container.appendChild(card);
}

function renderChallengeInteraction(card, scenario, lang, flagRanges) {
  if (state.phase === 1) {
    const p1 = el('div', 'learn-phase-box');
    p1.appendChild(el('h3', 'learn-phase-title', t('learn.game.phase1Title')));
    p1.appendChild(
      el('p', 'learn-phase-hint', t('learn.game.phase1Hint', {
        found: state.foundFlagIndices.size,
        total: flagRanges.length
      }))
    );

    const wrongEl = el('p', `learn-wrong-tap${state.wrongTapMsgVisible ? '' : ' hidden'}`, t('learn.game.wrongTap'));
    wrongEl.id = 'learn-phase1-wrong';
    wrongEl.setAttribute('role', 'status');
    p1.appendChild(wrongEl);

    const nextBtn = el('button', 'learn-btn-secondary', t('learn.game.skipToAction'));
    nextBtn.type = 'button';
    nextBtn.addEventListener('click', () => {
      state.phase = 2;
      render();
    });
    p1.appendChild(nextBtn);
    card.appendChild(p1);
    return;
  }

  if (state.phase === 2) {
    const p2 = el('div', 'learn-phase-box');
    if (flagRanges.length > 0 && state.foundFlagIndices.size >= flagRanges.length) {
      p2.appendChild(el('p', 'learn-flags-complete', t('learn.game.phase1Done', { total: flagRanges.length })));
    }
    p2.appendChild(el('h3', 'learn-phase-title', t('learn.game.phase2Title')));

    const optionsList = el('div', 'learn-options-grid');
    for (const opt of scenario.options) {
      const label = opt.labelKey
        ? t(opt.labelKey)
        : ((opt.label && (opt.label[lang] || opt.label.en)) || '');
      const btn = el('button', 'learn-option-btn', label);
      btn.type = 'button';
      btn.addEventListener('click', () => handleChallengeOptionClick(opt));
      optionsList.appendChild(btn);
    }
    p2.appendChild(optionsList);
    card.appendChild(p2);
    return;
  }

  // Feedback phase
  renderChallengeFeedback(card, scenario, lang, flagRanges);
}

function renderChallengeFeedback(card, scenario, lang, flagRanges) {
  const chosenOption = scenario.options.find((o) => o.id === state.selectedOptionId) || null;
  const isCorrect = !state.timedOut && Boolean(chosenOption && chosenOption.correct);

  const fb = el('div', `learn-feedback-card ${isCorrect ? 'is-correct' : 'is-miss'}`);

  const headRow = el('div', 'learn-feedback-head');
  const titleText = state.timedOut
    ? t('learn.game.timeoutHeadline')
    : isCorrect
      ? t('learn.game.correctHeadline')
      : t('learn.game.wrongHeadline');
  headRow.appendChild(el('h3', 'learn-feedback-title', titleText));

  if (state.lastPointsDelta > 0) {
    headRow.appendChild(el('span', 'learn-points-badge', t('learn.game.pointsEarned', { pts: state.lastPointsDelta })));
  }
  fb.appendChild(headRow);

  // Scam type tag
  const typeLine = el('p', 'learn-scam-type');
  typeLine.appendChild(el('strong', '', `${t('learn.game.scamTypeLabel')} `));
  typeLine.appendChild(document.createTextNode(t(`learn.scamTypes.${scenario.scamType}`)));
  fb.appendChild(typeLine);

  // Feedback message
  if (state.timedOut) {
    fb.appendChild(el('p', 'learn-feedback-body', t('learn.game.timeoutDesc')));
  } else if (chosenOption) {
    const fbMsg = chosenOption.feedbackKey
      ? t(chosenOption.feedbackKey)
      : (chosenOption.feedbackText || (chosenOption.feedback && (chosenOption.feedback[lang] || chosenOption.feedback.en)) || '');
    fb.appendChild(el('p', 'learn-feedback-body', fbMsg));
  }

  // Consequence card on loss-making wrong option
  if (chosenOption && chosenOption.consequence) {
    fb.appendChild(buildConsequenceBox(chosenOption.consequence, lang));
  }

  // Missed flags summary
  const missedFlags = flagRanges.filter((fr) => !state.foundFlagIndices.has(fr.index));
  const flagsBox = el('div', 'learn-missed-flags');
  if (missedFlags.length === 0) {
    flagsBox.appendChild(el('p', 'learn-all-flags-caught', t('learn.game.allFlagsCaught')));
  } else {
    flagsBox.appendChild(el('span', 'learn-missed-label', t('learn.game.missedFlagsTitle')));
    const chips = el('div', 'learn-flag-chips');
    for (const mf of missedFlags) {
      chips.appendChild(el('span', 'learn-flag-chip', mf.text));
    }
    flagsBox.appendChild(chips);
  }
  fb.appendChild(flagsBox);

  // Highlighted Rule to remember
  const ruleText = scenario.ruleKey
    ? t(scenario.ruleKey)
    : ((scenario.rule && (scenario.rule[lang] || scenario.rule.en)) || '');
  const ruleBox = el('div', 'learn-rule-box');
  ruleBox.appendChild(el('span', 'learn-rule-title', t('learn.game.ruleTitle')));
  ruleBox.appendChild(el('p', 'learn-rule-text', ruleText));
  fb.appendChild(ruleBox);

  if (state.wasRequeuedThisTurn) {
    fb.appendChild(el('p', 'learn-requeue-note', t('learn.game.requeueNote')));
  }

  const isLast = state.queueIdx + 1 >= state.queue.length;
  const nextBtn = el('button', 'learn-btn-primary', isLast ? t('learn.game.finishBtn') : t('learn.game.nextBtn'));
  nextBtn.type = 'button';
  nextBtn.addEventListener('click', advanceScenario);
  fb.appendChild(nextBtn);

  card.appendChild(fb);
}

function buildConsequenceBox(cons, lang) {
  const box = el('div', 'learn-consequence-card');

  const topRow = el('div', 'learn-consequence-top');
  topRow.appendChild(el('h4', 'learn-consequence-title', t('learn.game.consequenceTitle')));
  topRow.appendChild(el('span', 'learn-demo-tag', t('learn.game.demoBadge')));
  box.appendChild(topRow);

  const balanceRow = el('div', 'learn-balance-drop');
  const beforeEl = el('div', 'learn-balance-col');
  beforeEl.appendChild(el('span', 'learn-balance-lbl', t('learn.game.beforeLabel')));
  beforeEl.appendChild(el('span', 'learn-balance-before', formatRupees(cons.amountBefore)));

  const arrowEl = el('span', 'learn-balance-arrow', '→');
  arrowEl.setAttribute('aria-hidden', 'true');

  const afterEl = el('div', 'learn-balance-col');
  afterEl.appendChild(el('span', 'learn-balance-lbl', t('learn.game.afterLabel')));
  afterEl.appendChild(el('span', 'learn-balance-after', formatRupees(cons.amountAfter)));

  balanceRow.appendChild(beforeEl);
  balanceRow.appendChild(arrowEl);
  balanceRow.appendChild(afterEl);
  box.appendChild(balanceRow);

  const noteText = (cons.note && (cons.note[lang] || cons.note.en)) || '';
  if (noteText) {
    box.appendChild(el('p', 'learn-consequence-note', noteText));
  }
  box.appendChild(el('p', 'learn-real-warning', t('learn.game.realWarning')));
  return box;
}

function renderSimpleInteraction(card, scenario, lang, flags) {
  if (state.phase !== 'feedback') {
    const box = el('div', 'learn-simple-actions');
    box.appendChild(el('h3', 'learn-phase-title', t('learn.game.simplePrompt')));

    const btnPair = el('div', 'learn-simple-btn-pair');

    const btnDontTrust = el('button', 'learn-btn-simple-safe', t('learn.game.dontTrustBtn'));
    btnDontTrust.type = 'button';
    btnDontTrust.addEventListener('click', () => handleSimpleChoiceClick('dont-trust'));

    const btnTrust = el('button', 'learn-btn-simple-trust', t('learn.game.trustBtn'));
    btnTrust.type = 'button';
    btnTrust.addEventListener('click', () => handleSimpleChoiceClick('trust'));

    btnPair.appendChild(btnDontTrust);
    btnPair.appendChild(btnTrust);
    box.appendChild(btnPair);
    card.appendChild(box);
    return;
  }

  // Simple mode gentle feedback (auto-highlighted flags already shown on phone card)
  const isGood = state.simpleChoice === 'dont-trust';
  const fb = el('div', `learn-feedback-card learn-simple-feedback ${isGood ? 'is-correct' : 'is-gentle'}`);

  fb.appendChild(
    el('h3', 'learn-feedback-title', isGood ? t('learn.game.simpleGoodTitle') : t('learn.game.simpleGentleTitle'))
  );

  // Plain-words explanation from the correct option + rule
  const correctOpt = scenario.options.find((o) => o.correct);
  if (correctOpt) {
    const fbText = correctOpt.feedbackKey
      ? t(correctOpt.feedbackKey)
      : (correctOpt.feedbackText || (correctOpt.feedback && (correctOpt.feedback[lang] || correctOpt.feedback.en)) || '');
    if (fbText) fb.appendChild(el('p', 'learn-feedback-body', fbText));
  }

  if (flags.length > 0) {
    const flagsBox = el('div', 'learn-missed-flags');
    flagsBox.appendChild(el('span', 'learn-missed-label', t('learn.game.missedFlagsTitle')));
    const chips = el('div', 'learn-flag-chips');
    for (const f of flags) {
      chips.appendChild(el('span', 'learn-flag-chip', f));
    }
    flagsBox.appendChild(chips);
    fb.appendChild(flagsBox);
  }

  const ruleText = scenario.ruleKey
    ? t(scenario.ruleKey)
    : ((scenario.rule && (scenario.rule[lang] || scenario.rule.en)) || '');
  const ruleBox = el('div', 'learn-rule-box');
  ruleBox.appendChild(el('span', 'learn-rule-title', t('learn.game.ruleTitle')));
  ruleBox.appendChild(el('p', 'learn-rule-text', ruleText));
  fb.appendChild(ruleBox);

  const isLast = state.queueIdx + 1 >= state.queue.length;
  const nextBtn = el('button', 'learn-btn-primary', isLast ? t('learn.game.finishBtn') : t('learn.game.nextBtn'));
  nextBtn.type = 'button';
  nextBtn.addEventListener('click', advanceScenario);
  fb.appendChild(nextBtn);

  card.appendChild(fb);
}

// ── Result Screen ─────────────────────────────────────────────────────────

function getTierKey(safetyScore) {
  if (safetyScore >= 90) return 'shield';
  if (safetyScore >= 70) return 'alert';
  if (safetyScore >= 40) return 'learning';
  return 'practice';
}

function renderResultScreen(container) {
  container.appendChild(buildControlsBar());

  const total = Math.max(1, state.totalUnique);
  const correct = countInitialCorrect();
  const safetyScore = Math.round((100 * correct) / total);
  const tierKey = getTierKey(safetyScore);
  const tierLabel = t(`learn.result.tiers.${tierKey}`);

  const card = el('div', 'learn-card-shell learn-result-card');
  card.appendChild(el('h2', 'learn-result-title', t('learn.result.title')));

  if (state.mode === 'simple') {
    const simpleBox = el('div', 'learn-result-hero');
    simpleBox.appendChild(
      el('p', 'learn-result-simple-score', t('learn.result.simpleSpotted', { correct, total }))
    );
    card.appendChild(simpleBox);
  } else {
    const scoreBox = el('div', 'learn-result-hero');
    scoreBox.appendChild(el('span', 'learn-result-score-lbl', t('learn.result.scoreLabel')));
    scoreBox.appendChild(el('div', 'learn-result-score-num', `${safetyScore}`));
    scoreBox.appendChild(el('span', `learn-result-tier tier-${tierKey}`, tierLabel));
    if (state.bestRunSavedNew) {
      scoreBox.appendChild(el('span', 'learn-new-best', t('learn.result.newBest')));
    }
    card.appendChild(scoreBox);
  }

  // Weak spots by scamType
  const weakBox = el('div', 'learn-weak-spots');
  weakBox.appendChild(el('h3', 'learn-weak-title', t('learn.result.weakSpotsTitle')));
  if (state.missedIds.length === 0) {
    weakBox.appendChild(el('p', 'learn-no-weak', t('learn.result.noWeakSpots')));
  } else {
    const ul = el('ul', 'learn-weak-list');
    const seenTypes = new Set();
    for (const id of state.missedIds) {
      const sc = state.byId.get(id);
      if (sc && !seenTypes.has(sc.scamType)) {
        seenTypes.add(sc.scamType);
        ul.appendChild(el('li', 'learn-weak-item', t(`learn.scamTypes.${sc.scamType}`)));
      }
    }
    weakBox.appendChild(ul);
  }
  card.appendChild(weakBox);

  // Action buttons
  const btnRow = el('div', 'learn-result-actions');

  const btnPlayAgain = el('button', 'learn-btn-primary', t('learn.result.playAgain'));
  btnPlayAgain.type = 'button';
  btnPlayAgain.addEventListener('click', () => {
    startRun(state.scenarios.map((s) => s.id), false);
  });
  btnRow.appendChild(btnPlayAgain);

  if (state.missedIds.length > 0) {
    const btnWeak = el(
      'button',
      'learn-btn-secondary',
      t('learn.result.practiseWeak', { count: state.missedIds.length })
    );
    btnWeak.type = 'button';
    btnWeak.addEventListener('click', () => {
      startRun([...state.missedIds], false);
    });
    btnRow.appendChild(btnWeak);
  }

  const btnShare = el('button', 'learn-btn-secondary', t('learn.result.share'));
  btnShare.type = 'button';
  btnShare.addEventListener('click', () => handleShareResult(safetyScore, tierLabel, correct, total));
  btnRow.appendChild(btnShare);

  card.appendChild(btnRow);

  const toast = el('div', 'learn-share-toast hidden');
  toast.id = 'learn-share-toast';
  toast.setAttribute('role', 'status');
  card.appendChild(toast);

  container.appendChild(card);
}

async function handleShareResult(safetyScore, tierLabel, correct, total) {
  const shareText = state.mode === 'simple'
    ? t('learn.result.shareTextSimple', { correct, total })
    : t('learn.result.shareTextChallenge', { score: safetyScore, tier: tierLabel });

  if (navigator.share) {
    try {
      await navigator.share({ title: t('learn.start.title'), text: shareText });
      return;
    } catch {
      // User dismissed or share unavailable — fall through to clipboard
    }
  }

  try {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(shareText);
    } else {
      const ta = document.createElement('textarea');
      ta.value = shareText;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
    }
    const toastEl = document.getElementById('learn-share-toast');
    if (toastEl) {
      toastEl.textContent = t('learn.result.copiedToast');
      toastEl.classList.remove('hidden');
      if (toastTimeout) clearTimeout(toastTimeout);
      toastTimeout = setTimeout(() => toastEl.classList.add('hidden'), 2600);
    }
  } catch {
    // ignore clipboard failures
  }
}

// ── Main render dispatcher ────────────────────────────────────────────────

function render() {
  if (!learnRoot) return;
  learnRoot.replaceChildren();

  if (state.screen === 'play') {
    renderPlayScreen(learnRoot);
  } else if (state.screen === 'result') {
    renderResultScreen(learnRoot);
  } else {
    renderStartScreen(learnRoot);
  }
}

// ── Global API & Initialization ───────────────────────────────────────────

const SCAM_ALIASES = {
  kyc: 'kyc-sms',
  'kyc-fraud': 'kyc-sms',
  courier: 'kyc-sms',
  smishing: 'kyc-sms',
  phishing: 'kyc-sms',
  arrest: 'digital-arrest',
  'digital-arrest': 'digital-arrest',
  apk: 'cloned-app',
  'malicious-app': 'cloned-app',
  'malicious-apk': 'cloned-app'
};

function resolveScenarioId(rawId) {
  if (!state.loaded || state.scenarios.length === 0) return rawId;
  const key = String(rawId || '').trim().toLowerCase();
  if (state.byId.has(rawId)) return rawId;
  if (SCAM_ALIASES[key] && state.byId.has(SCAM_ALIASES[key])) return SCAM_ALIASES[key];
  return state.scenarios[0].id;
}

function buildLearnUrl(mode, scamId, lang) {
  const url = new URL(window.location.href);
  url.searchParams.set('mode', mode);
  url.searchParams.set('scam', scamId);
  url.searchParams.set('lang', lang);
  url.hash = '#learn';
  return url.toString();
}

async function openScenarioWithOptions(id, opts = {}) {
  await initPromise;
  if (!state.loaded || state.scenarios.length === 0) return;

  const targetId = resolveScenarioId(id);
  const scenario = state.byId.get(targetId);
  const targetMode = opts.mode === 'simple' ? 'simple' : 'challenge';

  const requestedLang = opts.lang || getLang() || 'en';
  const supportedLang = (scenario && scenario.message && scenario.message[requestedLang])
    ? requestedLang
    : 'en';

  if (getLang() !== supportedLang) {
    await setLang(supportedLang);
  }
  if (state.mode !== targetMode) {
    state.mode = targetMode;
    writeMode(targetMode);
    applyModeBodyClass();
  }

  if (opts.pushHistory && window.history && typeof window.history.pushState === 'function') {
    const checkUrl = new URL(window.location.href);
    checkUrl.searchParams.delete('mode');
    checkUrl.searchParams.delete('scam');
    checkUrl.searchParams.delete('lang');
    checkUrl.hash = '#check';
    if (window.location.hash !== '#check' || window.location.search.includes('scam=')) {
      window.history.replaceState({ ussView: 'check' }, '', checkUrl.toString());
    }
    window.history.pushState(
      { ussView: 'learn', mode: targetMode, scam: targetId, lang: supportedLang },
      '',
      buildLearnUrl(targetMode, targetId, supportedLang)
    );
  }

  const learnSection = document.getElementById('learn');
  if (learnSection) {
    learnSection.scrollIntoView({ behavior: prefersReducedMotion() ? 'auto' : 'smooth' });
  }
  startRun([targetId], true);
}

async function applyUrlParams(scrollToLearn = true) {
  const params = new URLSearchParams(window.location.search);
  const rawScam = params.get('scam');
  const rawMode = params.get('mode');
  if (!rawScam && !rawMode) return false;

  await openScenarioWithOptions(rawScam || '', {
    mode: rawMode === 'simple' ? 'simple' : 'challenge',
    lang: params.get('lang') || undefined,
    pushHistory: false
  });
  if (!scrollToLearn) return true;
  const learnSection = document.getElementById('learn');
  if (learnSection) {
    learnSection.scrollIntoView({ behavior: 'auto' });
  }
  return true;
}

const initPromise = (async () => {
  applyModeBodyClass();
  await Promise.all([initI18n(), loadScenarios()]);
  onLangChange(() => render());
  render();
})();

initPromise.then(() => {
  applyUrlParams(true);
});

window.addEventListener('popstate', async () => {
  await initPromise;
  const params = new URLSearchParams(window.location.search);
  if (params.has('scam') || params.has('mode')) {
    await applyUrlParams(true);
    return;
  }
  stopTimer();
  state.screen = 'start';
  render();
  const resultCard = document.getElementById('result-card');
  const checkTarget = (resultCard && !resultCard.classList.contains('hidden'))
    ? resultCard
    : document.getElementById('check');
  if (checkTarget) {
    checkTarget.scrollIntoView({ behavior: prefersReducedMotion() ? 'auto' : 'smooth', block: 'start' });
  }
});

window.USS = window.USS || {};
window.USS.startScenario = async (id, opts = {}) => {
  await openScenarioWithOptions(id, {
    mode: opts.mode || 'challenge',
    lang: opts.lang,
    pushHistory: opts.pushHistory !== false
  });
};
window.USS.startCustomScenario = async (customScenario) => {
  await initPromise;
  if (!customScenario || !customScenario.id) return;
  // Hold only in memory for this run; never persisted to localStorage
  state.byId.set(customScenario.id, customScenario);
  const learnSection = document.getElementById('learn');
  if (learnSection) {
    learnSection.scrollIntoView({ behavior: prefersReducedMotion() ? 'auto' : 'smooth' });
  }
  startRun([customScenario.id], true);
};
window.USS.getMode = () => state.mode;
window.USS.setMode = (m) => setMode(m);
window.USS.resetDemoState = () => {
  stopTimer();
  state.bestScore = null;
  state.bestRunSavedNew = false;
  state.screen = 'start';
  state.queue = [];
  state.missedIds = [];
  state.score = 0;
  state.streak = 0;
  render();
  if (typeof window.USS.resetVerifyState === 'function') {
    window.USS.resetVerifyState();
  }
};

