/**
 * i18n.js – lightweight translation loader for Cyber Shield / UPI Scam Simulator.
 *
 * Exposes t(key, vars), setLang(lang), getLang(), onLangChange(cb), and initI18n().
 * Falls back to English when a key is missing in kn/hi with a console warning.
 * Persists selected language in localStorage under "uss.lang" inside try/catch.
 */

const SUPPORTED_LANGS = ['en', 'kn', 'hi'];
const LANG_STORAGE_KEY = 'uss.lang';

const dictionaries = {};
const listeners = new Set();
let currentLang = 'en';
let initPromise = null;

function readStoredLang() {
  try {
    const saved = localStorage.getItem(LANG_STORAGE_KEY);
    if (saved && SUPPORTED_LANGS.includes(saved)) return saved;
  } catch {
    // ignore storage errors in restricted environments
  }
  return 'en';
}

function writeStoredLang(lang) {
  try {
    localStorage.setItem(LANG_STORAGE_KEY, lang);
  } catch {
    // ignore storage errors
  }
}

async function loadDictionary(lang) {
  if (dictionaries[lang]) return dictionaries[lang];
  const res = await fetch(`i18n/${lang}.json`);
  if (!res.ok) {
    throw new Error(`Failed to load i18n/${lang}.json (${res.status})`);
  }
  const data = await res.json();
  dictionaries[lang] = data;
  return data;
}

function lookupPath(obj, key) {
  if (!obj || typeof key !== 'string') return undefined;
  const parts = key.split('.');
  let cur = obj;
  for (const part of parts) {
    if (cur && Object.prototype.hasOwnProperty.call(cur, part)) {
      cur = cur[part];
    } else {
      return undefined;
    }
  }
  return typeof cur === 'string' ? cur : undefined;
}

function interpolate(str, vars) {
  if (!vars) return str;
  return str.replace(/\{(\w+)\}/g, (match, name) =>
    Object.prototype.hasOwnProperty.call(vars, name) ? String(vars[name]) : match
  );
}

export function t(key, vars) {
  let val = lookupPath(dictionaries[currentLang], key);
  if (val === undefined && currentLang !== 'en') {
    console.warn(`[i18n] Missing key "${key}" for language "${currentLang}", falling back to "en".`);
    val = lookupPath(dictionaries.en, key);
  }
  if (val === undefined) {
    if (dictionaries.en) {
      console.warn(`[i18n] Missing key "${key}" in "en".`);
    }
    return key;
  }
  return interpolate(val, vars);
}

export function getLang() {
  return currentLang;
}

export function onLangChange(cb) {
  if (typeof cb !== 'function') return () => {};
  listeners.add(cb);
  return () => listeners.delete(cb);
}

export function applyDomTranslations(root = document) {
  root.querySelectorAll('[data-i18n]').forEach((el) => {
    el.textContent = t(el.dataset.i18n);
  });
  root.querySelectorAll('[data-i18n-placeholder]').forEach((el) => {
    el.setAttribute('placeholder', t(el.dataset.i18nPlaceholder));
  });
  root.querySelectorAll('[data-i18n-aria]').forEach((el) => {
    el.setAttribute('aria-label', t(el.dataset.i18nAria));
  });
}

export async function setLang(lang) {
  const next = SUPPORTED_LANGS.includes(lang) ? lang : 'en';
  await loadDictionary('en');
  if (next !== 'en') {
    await loadDictionary(next);
  }
  currentLang = next;
  writeStoredLang(next);
  document.documentElement.lang = next;
  applyDomTranslations();
  listeners.forEach((cb) => {
    try {
      cb(next);
    } catch (err) {
      console.error('[i18n] listener error:', err);
    }
  });
  return next;
}

export function initI18n() {
  if (initPromise) return initPromise;
  initPromise = (async () => {
    const target = readStoredLang();
    await setLang(target);
    return currentLang;
  })();
  return initPromise;
}

window.USS = window.USS || {};
window.USS.i18n = { t, setLang, getLang, onLangChange, initI18n, applyDomTranslations };

