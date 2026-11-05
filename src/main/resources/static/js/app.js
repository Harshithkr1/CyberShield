/**
 * app.js – application entry point (ES module).
 *
 * Wires up UI events, orchestrates the analyze flow, and manages theme
 * switching.  All fetch logic lives in api.js; all DOM writes live in ui.js.
 */

import { analyzeText } from './api.js';
import { showEmpty, showLoading, showError, showResult } from './ui.js';

// ── DOM references ────────────────────────────────────────────────────────

const inputText    = document.getElementById('input-text');
const charCount    = document.getElementById('char-count');
const btnAnalyze   = document.getElementById('btn-analyze');
const btnClear     = document.getElementById('btn-clear');
const useMlToggle  = document.getElementById('use-ml');
const themeToggle  = document.getElementById('theme-toggle');

const tabs = document.querySelectorAll('[role="tab"]');
const panels = document.querySelectorAll('[role="tabpanel"]');

// ── Theme ─────────────────────────────────────────────────────────────────

(function initTheme() {
  // Persist theme preference across sessions
  const saved = localStorage.getItem('cs-theme');
  if (saved) document.documentElement.dataset.theme = saved;
})();

if (themeToggle) {
  themeToggle.addEventListener('click', () => {
    const next = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
    document.documentElement.dataset.theme = next;
    try {
      localStorage.setItem('cs-theme', next);
    } catch {}
    themeToggle.setAttribute(
      'aria-label',
      next === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'
    );
  });
}

// ── ML Layer Toggle (persisted in localStorage) ───────────────────────────

(function initMlToggle() {
  if (!useMlToggle) return;
  try {
    const saved = localStorage.getItem('cs-use-ml');
    if (saved !== null) {
      useMlToggle.checked = saved === 'true';
    } else {
      useMlToggle.checked = true;
    }
  } catch {
    useMlToggle.checked = true;
  }
})();

if (useMlToggle) {
  useMlToggle.addEventListener('change', () => {
    try {
      localStorage.setItem('cs-use-ml', String(useMlToggle.checked));
    } catch {
      // ignore localStorage restrictions
    }
  });
}

// ── Tab navigation ────────────────────────────────────────────────────────

tabs.forEach((tab) => {
  tab.addEventListener('click', () => {
    const target = tab.dataset.tab;

    // Update tabs
    tabs.forEach((t) => {
      const active = t.dataset.tab === target;
      t.classList.toggle('active', active);
      t.setAttribute('aria-selected', String(active));
    });

    // Update panels
    panels.forEach((p) => {
      const show = p.id === `panel-${target}`;
      p.classList.toggle('active', show);
      p.classList.toggle('hidden', !show);
    });
  });

  // Keyboard: left/right arrow to switch tabs
  tab.addEventListener('keydown', (e) => {
    const list = [...tabs];
    const idx  = list.indexOf(tab);
    if (e.key === 'ArrowRight') list[(idx + 1) % list.length].click();
    if (e.key === 'ArrowLeft')  list[(idx - 1 + list.length) % list.length].click();
  });
});

// ── Mobile Menu (under 760px) ──────────────────────────────────────────────

const navToggle = document.getElementById('nav-toggle');
const navMenu   = document.getElementById('nav-menu');

if (navToggle && navMenu) {
  function toggleMobileMenu(open) {
    const isOpen = open !== undefined ? open : !navMenu.classList.contains('is-open');
    navMenu.classList.toggle('is-open', isOpen);
    navToggle.setAttribute('aria-expanded', String(isOpen));
    navToggle.setAttribute('aria-label', isOpen ? 'Close navigation menu' : 'Open navigation menu');
    navMenu.setAttribute('aria-hidden', String(!isOpen));
  }

  navToggle.addEventListener('click', () => {
    toggleMobileMenu();
  });

  // Close when clicking any link inside mobile menu
  navMenu.querySelectorAll('a').forEach((link) => {
    link.addEventListener('click', () => {
      toggleMobileMenu(false);
    });
  });

  // Close on Escape key
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && navMenu.classList.contains('is-open')) {
      toggleMobileMenu(false);
      navToggle.focus();
    }
  });

  // Close on click outside
  document.addEventListener('click', (e) => {
    if (navMenu.classList.contains('is-open')) {
      if (!navMenu.contains(e.target) && !navToggle.contains(e.target)) {
        toggleMobileMenu(false);
      }
    }
  });
}

// ── In-page link navigation (#about, #features, #check, #learn, #report) ──

document.querySelectorAll('a[href^="#"]').forEach((anchor) => {
  anchor.addEventListener('click', (e) => {
    const targetId = anchor.getAttribute('href');
    if (!targetId || targetId === '#') return;

    if (targetId === '#check') {
      e.preventDefault();
      const targetEl = document.getElementById('check') || document.querySelector('.main-content');
      if (targetEl) {
        targetEl.scrollIntoView({ behavior: 'smooth' });
      }
      const input = document.getElementById('input-text');
      if (input) setTimeout(() => input.focus(), 350);
      return;
    }

    if (targetId === '#learn') {
      e.preventDefault();
      const targetEl = document.getElementById('learn');
      if (targetEl) {
        targetEl.scrollIntoView({ behavior: 'smooth' });
      }
      return;
    }

    if (targetId === '#report') {
      e.preventDefault();
      const reportSec = document.getElementById('report');
      if (reportSec) {
        reportSec.scrollIntoView({ behavior: 'smooth' });
      }
      return;
    }

    // Default smooth scroll for sections like #about, #features, #top
    const elem = document.querySelector(targetId);
    if (elem) {
      e.preventDefault();
      elem.scrollIntoView({ behavior: 'smooth' });
    }
  });
});

// ── Sample Buttons ────────────────────────────────────────────────────────

const SAMPLES = {
  kyc: "Dear SBI customer, your bank account KYC has expired. Your debit card and net banking will be blocked within 24 hours. Complete your kyc immediately at http://sbi-kyc-verify-portal.xyz to avoid disruption.",
  arrest: "This is Officer R. K. Verma from Central Bureau of Investigation cyber cell. An arrest warrant is issued against your name for money laundering and a drug parcel seized at Mumbai airport. You are under digital arrest. Stay on video call, do not tell anyone, and transfer funds to safe account for RBI verification.",
  courier: "Your FedEx courier parcel #FDX-99821 is on hold at customs clearance. Pay customs duty fee of Rs 49 to release package and reschedule your delivery: http://fedx-customs-clearance.top/track",
  apk: "Urgent notice from Power Grid: Electricity connection will be disconnected tonight due to unpaid dues. Install our electricity bill app to clear bill: http://quick-power-bill.org/payment.apk. Enable unknown sources and grant accessibility permission.",
  safe: "Hi Ananya, please find the meeting agenda and presentation slides for tomorrow's project review at 3 PM in the conference room. Let me know if you'd like to add any discussion points. Thanks!"
};

const sampleButtons = document.querySelectorAll('.btn-sample');
sampleButtons.forEach((btn) => {
  btn.addEventListener('click', () => {
    const key = btn.dataset.sample;
    if (SAMPLES[key]) {
      inputText.value = SAMPLES[key];
      updateCharCount();
      handleAnalyze();
    }
  });
});

// ── Character counter ─────────────────────────────────────────────────────

const MAX_CHARS = 5000;

inputText.addEventListener('input', updateCharCount);

function updateCharCount() {
  const len = inputText.value.length;
  charCount.textContent = `${len} / ${MAX_CHARS}`;
  charCount.classList.toggle('warn',   len > MAX_CHARS * 0.8);
  charCount.classList.toggle('danger', len >= MAX_CHARS);
}

// ── Clear ─────────────────────────────────────────────────────────────────

btnClear.addEventListener('click', () => {
  inputText.value = '';
  updateCharCount();
  showEmpty();
  if (window.cyberVortex) {
    window.cyberVortex.setMood('calm');
  }
  inputText.focus();
});

// ── Analyse ───────────────────────────────────────────────────────────────

btnAnalyze.addEventListener('click', handleAnalyze);

// Ctrl+Enter / Cmd+Enter shortcut
inputText.addEventListener('keydown', (e) => {
  if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') handleAnalyze();
});

async function handleAnalyze() {
  const text = inputText.value.trim();

  // Client-side guard (server validates too, but give instant feedback)
  if (!text) {
    showError('Please paste some text or a link before analysing.');
    return;
  }
  if (text.length > MAX_CHARS) {
    showError(`Text is too long (${text.length} chars). Maximum is ${MAX_CHARS} characters.`);
    return;
  }

  const useMl = useMlToggle.checked;

  const resultsArea = document.getElementById('results-area');
  if (resultsArea) resultsArea.setAttribute('aria-busy', 'true');

  // Show loading state and lock the button
  showLoading();
  setAnalyzeButtonState(true);

  // Trigger dynamic vortex scanning animation
  if (window.cyberVortex) {
    window.cyberVortex.setMood('scanning');
    window.cyberVortex.pulse();
  }

  try {
    const result = await analyzeText(text, useMl);
    showResult(result, text);

    // When the result arrives call setMood(level.toLowerCase()) and pulse(), then scroll to the results
    const level = String(result.level || 'low').toLowerCase();
    if (window.cyberVortex) {
      window.cyberVortex.setMood(level);
      window.cyberVortex.pulse();
    }

    const resultCard = document.getElementById('result-card');
    if (resultCard) {
      resultCard.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  } catch (err) {
    showError(err.message ?? 'An unexpected error occurred. Please try again.');
    if (window.cyberVortex) {
      window.cyberVortex.setMood('calm');
    }
  } finally {
    setAnalyzeButtonState(false);
    if (resultsArea) resultsArea.setAttribute('aria-busy', 'false');
  }
}

function setAnalyzeButtonState(isLoading) {
  btnAnalyze.disabled = isLoading;
  btnAnalyze.classList.toggle('loading', isLoading);

  // Swap icon for loading dots
  const iconEl = btnAnalyze.querySelector('.btn-icon');
  if (iconEl) iconEl.style.display = isLoading ? 'none' : '';

  btnAnalyze.querySelector('span') &&
    (btnAnalyze.querySelector('span').textContent = isLoading ? 'Analysing…' : 'Analyse');
}

// ── Scroll Reveal (IntersectionObserver, staggered children) ───────────────

function initScrollReveal() {
  const groups = document.querySelectorAll('.reveal-group');
  if (!groups.length) return;

  const prefersReduced = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  if (prefersReduced || typeof IntersectionObserver === 'undefined') {
    groups.forEach((g) => g.classList.add('is-visible'));
    return;
  }

  const observer = new IntersectionObserver(
    (entries, obs) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          entry.target.classList.add('is-visible');
          obs.unobserve(entry.target);
        }
      });
    },
    {
      root: null,
      rootMargin: '0px 0px -40px 0px',
      threshold: 0.12
    }
  );

  groups.forEach((group) => observer.observe(group));
}

// ── Bento Cards: Pointer-Following Glow ───────────────────────────────────

function initBentoGlow() {
  const cards = document.querySelectorAll('.bento-card');
  if (!cards.length) return;

  cards.forEach((card) => {
    card.addEventListener('pointermove', (e) => {
      const rect = card.getBoundingClientRect();
      const x = e.clientX - rect.left;
      const y = e.clientY - rect.top;
      card.style.setProperty('--mouse-x', `${x}px`);
      card.style.setProperty('--mouse-y', `${y}px`);
    });

    card.addEventListener('pointerleave', () => {
      card.style.setProperty('--mouse-x', '-999px');
      card.style.setProperty('--mouse-y', '-999px');
    });
  });
}

// ── Initial state ─────────────────────────────────────────────────────────

showEmpty();
initScrollReveal();
initBentoGlow();
