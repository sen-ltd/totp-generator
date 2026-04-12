/**
 * Main application: DOM, events, rendering, timer loop.
 */

import { totp, getTimeRemaining, parseOtpauthUrl } from './totp.js';
import { base32Decode } from './base32.js';
import { t, setLang, getLang, translations } from './i18n.js';

// ─────────────────────────────────────────────────────────
// Storage helpers
// ─────────────────────────────────────────────────────────

const STORAGE_KEY = 'totp_accounts';
const LANG_KEY = 'totp_lang';

function loadAccounts() {
  try {
    return JSON.parse(localStorage.getItem(STORAGE_KEY) || '[]');
  } catch {
    return [];
  }
}

function saveAccounts(accounts) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(accounts));
}

function genId() {
  return Date.now().toString(36) + Math.random().toString(36).slice(2, 7);
}

// ─────────────────────────────────────────────────────────
// State
// ─────────────────────────────────────────────────────────

let accounts = loadAccounts();
let codes = {}; // id -> current code string
let modal = null; // 'add' | 'export' | 'import' | null

// ─────────────────────────────────────────────────────────
// Crypto helpers for export/import encryption
// ─────────────────────────────────────────────────────────

async function deriveKey(password, salt) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function encryptData(plaintext, password) {
  const enc = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(password, salt);
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    enc.encode(plaintext)
  );
  // Package: salt (16) + iv (12) + ciphertext
  const result = new Uint8Array(16 + 12 + ct.byteLength);
  result.set(salt, 0);
  result.set(iv, 16);
  result.set(new Uint8Array(ct), 28);
  return btoa(String.fromCharCode(...result));
}

async function decryptData(b64, password) {
  const bytes = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
  const salt = bytes.slice(0, 16);
  const iv = bytes.slice(16, 28);
  const ct = bytes.slice(28);
  const key = await deriveKey(password, salt);
  const dec = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
  return new TextDecoder().decode(dec);
}

// ─────────────────────────────────────────────────────────
// Rendering
// ─────────────────────────────────────────────────────────

function renderWarning() {
  const el = document.getElementById('security-warning');
  if (el) el.textContent = t('securityWarning');
}

function renderHeader() {
  const h1 = document.querySelector('h1');
  if (h1) h1.textContent = t('title');
  const sub = document.querySelector('.subtitle');
  if (sub) sub.textContent = t('subtitle');
  const addBtn = document.getElementById('btn-add-account');
  if (addBtn) addBtn.textContent = t('addAccount');
  const exportBtn = document.getElementById('btn-export');
  if (exportBtn) exportBtn.textContent = t('exportAll');
  const importBtn = document.getElementById('btn-import-file');
  if (importBtn) importBtn.textContent = t('importFile');
}

function progressRingDasharray(remaining, step) {
  const pct = remaining / step;
  const circ = 2 * Math.PI * 20; // r=20
  return `${(pct * circ).toFixed(2)} ${circ.toFixed(2)}`;
}

function colorForRemaining(remaining, step) {
  const pct = remaining / step;
  if (pct > 0.5) return 'var(--ring-ok)';
  if (pct > 0.25) return 'var(--ring-warn)';
  return 'var(--ring-danger)';
}

function renderAccounts() {
  const container = document.getElementById('accounts-container');
  if (!container) return;

  if (accounts.length === 0) {
    container.innerHTML = `<p class="empty-state">${t('noAccounts')}</p>`;
    return;
  }

  const now = Date.now() / 1000;
  const remaining = getTimeRemaining(now);
  const step = 30;

  container.innerHTML = accounts.map(acc => {
    const code = codes[acc.id] || '------';
    const displayCode = code.length === 6
      ? code.slice(0, 3) + ' ' + code.slice(3)
      : code;
    const da = progressRingDasharray(remaining, step);
    const ringColor = colorForRemaining(remaining, step);
    const secs = Math.ceil(remaining);

    return `
      <div class="account-card" data-id="${acc.id}">
        <div class="card-left">
          <div class="account-label">${escHtml(acc.issuer || acc.label)}</div>
          ${acc.issuer ? `<div class="account-sublabel">${escHtml(acc.label)}</div>` : ''}
          <div class="code-row">
            <span class="otp-code">${displayCode}</span>
            <button class="btn-copy" data-id="${acc.id}" title="${t('copy')}">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <rect x="9" y="9" width="13" height="13" rx="2"/>
                <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
              </svg>
            </button>
          </div>
        </div>
        <div class="card-right">
          <svg class="progress-ring" width="52" height="52" viewBox="0 0 52 52">
            <circle class="ring-bg" cx="26" cy="26" r="20" fill="none" stroke-width="4"/>
            <circle class="ring-fg" cx="26" cy="26" r="20" fill="none" stroke-width="4"
              stroke="${ringColor}"
              stroke-dasharray="${da}"
              stroke-dashoffset="0"
              transform="rotate(-90 26 26)"/>
            <text x="26" y="31" text-anchor="middle" class="ring-text">${secs}</text>
          </svg>
          <button class="btn-delete" data-id="${acc.id}" title="${t('delete')}">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <polyline points="3 6 5 6 21 6"/>
              <path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/>
              <path d="M10 11v6M14 11v6"/>
              <path d="M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/>
            </svg>
          </button>
        </div>
      </div>
    `;
  }).join('');

  // Bind copy buttons
  container.querySelectorAll('.btn-copy').forEach(btn => {
    btn.addEventListener('click', () => copyCode(btn.dataset.id));
  });

  // Bind delete buttons
  container.querySelectorAll('.btn-delete').forEach(btn => {
    btn.addEventListener('click', () => deleteAccount(btn.dataset.id));
  });
}

function escHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// ─────────────────────────────────────────────────────────
// Code update loop
// ─────────────────────────────────────────────────────────

async function updateCodes() {
  const now = Math.floor(Date.now() / 1000);
  await Promise.all(accounts.map(async acc => {
    try {
      codes[acc.id] = await totp(acc.secret, now, acc.period || 30, acc.digits || 6);
    } catch {
      codes[acc.id] = '------';
    }
  }));
}

function updateRingsOnly() {
  const now = Date.now() / 1000;
  const remaining = getTimeRemaining(now);
  const step = 30;
  const secs = Math.ceil(remaining);
  const da = progressRingDasharray(remaining, step);

  document.querySelectorAll('.account-card').forEach(card => {
    const fg = card.querySelector('.ring-fg');
    const txt = card.querySelector('.ring-text');
    if (fg) {
      fg.setAttribute('stroke-dasharray', da);
      fg.setAttribute('stroke', colorForRemaining(remaining, step));
    }
    if (txt) txt.textContent = secs;
  });
}

let lastStep = -1;

async function tick() {
  const now = Math.floor(Date.now() / 1000);
  const currentStep = Math.floor(now / 30);

  if (currentStep !== lastStep) {
    lastStep = currentStep;
    await updateCodes();
    renderAccounts();
  } else {
    updateRingsOnly();
  }
}

// ─────────────────────────────────────────────────────────
// Account actions
// ─────────────────────────────────────────────────────────

async function copyCode(id) {
  const code = codes[id];
  if (!code || code === '------') return;
  await navigator.clipboard.writeText(code).catch(() => {});

  // Visual feedback
  const btn = document.querySelector(`.btn-copy[data-id="${id}"]`);
  if (btn) {
    const orig = btn.innerHTML;
    btn.textContent = t('copied');
    btn.classList.add('copied');
    setTimeout(() => {
      btn.innerHTML = orig;
      btn.classList.remove('copied');
    }, 1500);
  }
}

function deleteAccount(id) {
  if (!confirm(t('confirmDelete'))) return;
  accounts = accounts.filter(a => a.id !== id);
  delete codes[id];
  saveAccounts(accounts);
  renderAccounts();
}

async function addAccount(data) {
  // Validate secret
  try {
    base32Decode(data.secret);
  } catch {
    alert(t('invalidSecret'));
    return false;
  }

  const acc = {
    id: genId(),
    label: data.label || data.secret.slice(0, 8),
    issuer: data.issuer || '',
    secret: data.secret.toUpperCase().replace(/\s/g, ''),
    digits: data.digits || 6,
    period: data.period || 30,
    algorithm: data.algorithm || 'SHA1',
  };

  accounts.push(acc);
  saveAccounts(accounts);
  await updateCodes();
  renderAccounts();
  return true;
}

// ─────────────────────────────────────────────────────────
// Modal: Add Account
// ─────────────────────────────────────────────────────────

function showAddModal() {
  modal = 'add';
  const overlay = document.getElementById('modal-overlay');
  const content = document.getElementById('modal-content');

  content.innerHTML = `
    <h2>${t('addAccount')}</h2>
    <div class="form-section">
      <label>${t('addManually')}</label>
      <input id="f-label" type="text" placeholder="${t('labelPlaceholder')}" autocomplete="off"/>
      <input id="f-issuer" type="text" placeholder="${t('issuerPlaceholder')}" autocomplete="off"/>
      <input id="f-secret" type="text" placeholder="${t('secretPlaceholder')}" autocomplete="off" spellcheck="false"/>
      <div class="row-2col">
        <label>${t('period')} <input id="f-period" type="number" value="30" min="1" max="300"/></label>
        <label>${t('digits')} <input id="f-digits" type="number" value="6" min="6" max="8"/></label>
      </div>
    </div>
    <div class="form-section">
      <label>${t('orPasteUrl')}</label>
      <input id="f-url" type="text" placeholder="${t('otpauthPlaceholder')}" autocomplete="off" spellcheck="false"/>
      <button id="btn-import-url" class="btn-secondary">${t('importFromUrl')}</button>
    </div>
    <div class="modal-actions">
      <button id="btn-modal-cancel" class="btn-secondary">${t('cancel')}</button>
      <button id="btn-modal-add" class="btn-primary">${t('add')}</button>
    </div>
  `;

  overlay.classList.remove('hidden');

  document.getElementById('btn-modal-cancel').addEventListener('click', closeModal);
  document.getElementById('btn-modal-add').addEventListener('click', handleAddSubmit);
  document.getElementById('btn-import-url').addEventListener('click', handleImportUrl);
}

async function handleAddSubmit() {
  const label = document.getElementById('f-label').value.trim();
  const issuer = document.getElementById('f-issuer').value.trim();
  const secret = document.getElementById('f-secret').value.trim();
  const period = parseInt(document.getElementById('f-period').value, 10) || 30;
  const digits = parseInt(document.getElementById('f-digits').value, 10) || 6;

  if (!secret) {
    alert(t('invalidSecret'));
    return;
  }

  const ok = await addAccount({ label, issuer, secret, period, digits });
  if (ok) closeModal();
}

function handleImportUrl() {
  const url = document.getElementById('f-url').value.trim();
  const parsed = parseOtpauthUrl(url);
  if (!parsed) {
    alert(t('invalidUrl'));
    return;
  }
  document.getElementById('f-label').value = parsed.label || '';
  document.getElementById('f-issuer').value = parsed.issuer || '';
  document.getElementById('f-secret').value = parsed.secret || '';
  document.getElementById('f-period').value = parsed.period || 30;
  document.getElementById('f-digits').value = parsed.digits || 6;
}

// ─────────────────────────────────────────────────────────
// Modal: Export
// ─────────────────────────────────────────────────────────

function showExportModal() {
  modal = 'export';
  const overlay = document.getElementById('modal-overlay');
  const content = document.getElementById('modal-content');

  content.innerHTML = `
    <h2>${t('exportTitle')}</h2>
    <div class="form-section">
      <label>${t('exportPassword')}</label>
      <input id="f-export-pw" type="password" placeholder="(optional)" autocomplete="new-password"/>
    </div>
    <div class="modal-actions">
      <button id="btn-modal-cancel" class="btn-secondary">${t('cancel')}</button>
      <button id="btn-modal-export" class="btn-primary">${t('exportBtn')}</button>
    </div>
  `;

  overlay.classList.remove('hidden');

  document.getElementById('btn-modal-cancel').addEventListener('click', closeModal);
  document.getElementById('btn-modal-export').addEventListener('click', handleExport);
}

async function handleExport() {
  const pw = document.getElementById('f-export-pw').value;
  const data = JSON.stringify({ version: 1, accounts }, null, 2);
  let blob;

  if (pw) {
    try {
      const encrypted = await encryptData(data, pw);
      blob = new Blob([JSON.stringify({ version: 1, encrypted })], { type: 'application/json' });
    } catch (e) {
      alert('Encryption failed: ' + e.message);
      return;
    }
  } else {
    blob = new Blob([data], { type: 'application/json' });
  }

  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'totp-accounts.json';
  a.click();
  URL.revokeObjectURL(url);
  closeModal();
}

// ─────────────────────────────────────────────────────────
// Modal: Import
// ─────────────────────────────────────────────────────────

function showImportModal() {
  modal = 'import';
  const overlay = document.getElementById('modal-overlay');
  const content = document.getElementById('modal-content');

  content.innerHTML = `
    <h2>${t('importTitle')}</h2>
    <div class="form-section">
      <input id="f-import-file" type="file" accept=".json"/>
      <label>${t('importPassword')}</label>
      <input id="f-import-pw" type="password" placeholder="(if encrypted)" autocomplete="current-password"/>
    </div>
    <div class="modal-actions">
      <button id="btn-modal-cancel" class="btn-secondary">${t('cancel')}</button>
      <button id="btn-modal-import" class="btn-primary">${t('importBtn')}</button>
    </div>
  `;

  overlay.classList.remove('hidden');

  document.getElementById('btn-modal-cancel').addEventListener('click', closeModal);
  document.getElementById('btn-modal-import').addEventListener('click', handleImportFile);
}

async function handleImportFile() {
  const fileInput = document.getElementById('f-import-file');
  const pw = document.getElementById('f-import-pw').value;

  if (!fileInput.files[0]) return;

  const text = await fileInput.files[0].text();
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    alert('Invalid JSON file.');
    return;
  }

  let imported;
  if (parsed.encrypted) {
    if (!pw) {
      alert('Password required for encrypted file.');
      return;
    }
    try {
      const decrypted = await decryptData(parsed.encrypted, pw);
      imported = JSON.parse(decrypted);
    } catch {
      alert('Decryption failed. Wrong password?');
      return;
    }
  } else {
    imported = parsed;
  }

  const importedAccounts = imported.accounts || [];
  let added = 0;
  for (const acc of importedAccounts) {
    if (acc.secret && !accounts.find(a => a.secret === acc.secret)) {
      accounts.push({ ...acc, id: genId() });
      added++;
    }
  }

  saveAccounts(accounts);
  await updateCodes();
  renderAccounts();
  closeModal();
  alert(`Imported ${added} account(s).`);
}

// ─────────────────────────────────────────────────────────
// Modal close
// ─────────────────────────────────────────────────────────

function closeModal() {
  modal = null;
  const overlay = document.getElementById('modal-overlay');
  if (overlay) overlay.classList.add('hidden');
}

// ─────────────────────────────────────────────────────────
// Language toggle
// ─────────────────────────────────────────────────────────

function setupLangToggle() {
  const btn = document.getElementById('btn-lang');
  if (!btn) return;
  btn.textContent = getLang() === 'en' ? 'JA' : 'EN';
  btn.addEventListener('click', () => {
    const next = getLang() === 'en' ? 'ja' : 'en';
    setLang(next);
    localStorage.setItem(LANG_KEY, next);
    btn.textContent = next === 'en' ? 'JA' : 'EN';
    renderWarning();
    renderHeader();
    renderAccounts();
  });
}

// ─────────────────────────────────────────────────────────
// Init
// ─────────────────────────────────────────────────────────

async function init() {
  // Restore language preference
  const savedLang = localStorage.getItem(LANG_KEY);
  if (savedLang && translations[savedLang]) setLang(savedLang);

  renderWarning();
  renderHeader();
  setupLangToggle();

  // Button events
  document.getElementById('btn-add-account')?.addEventListener('click', showAddModal);
  document.getElementById('btn-export')?.addEventListener('click', showExportModal);
  document.getElementById('btn-import-file')?.addEventListener('click', showImportModal);

  // Close modal on overlay click
  document.getElementById('modal-overlay')?.addEventListener('click', e => {
    if (e.target.id === 'modal-overlay') closeModal();
  });

  // Initial codes
  await updateCodes();
  renderAccounts();

  // Tick every second
  setInterval(tick, 1000);
}

document.addEventListener('DOMContentLoaded', init);
