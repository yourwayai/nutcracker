/* ═══════════════════════════════════════════════
   Nutcracker — Renderer App Logic (HTTP API mode)
   ═══════════════════════════════════════════════ */
'use strict';

const API_BASE = '';  // same origin

// ─── API layer ────────────────────────────────────────────────────────────────
const api = {
  async post(path, body = {}) {
    const res = await fetch(API_BASE + path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    return res.json();
  },
  async get(path) {
    const res = await fetch(API_BASE + path);
    return res.json();
  },
};

const vault = {
  exists:         ()                    => api.post('/api/vault/exists'),
  create:         (pw)                  => api.post('/api/vault/create',          { password: pw }),
  unlock:         (pw)                  => api.post('/api/vault/unlock',          { password: pw }),
  save:           (pw, data)            => api.post('/api/vault/save',            { password: pw, data }),
  changePassword: (oldPw, newPw)        => api.post('/api/vault/change_password', { old_password: oldPw, new_password: newPw }),
  export:         (pw, path)            => api.post('/api/vault/export',          { password: pw, path }),
};

// ─── State ────────────────────────────────────────────────────────────────────
let masterPassword = null;
let vaultData = { entries: [] };
let activeCategory = '__all__';
let editingId = null;
let viewingId = null;

// ─── Helpers ──────────────────────────────────────────────────────────────────
function uuid() {
  return crypto.randomUUID();
}

function maskKey(val) {
  if (!val) return '—';
  if (val.length <= 8) return '••••••••';
  return val.slice(0, 4) + '•'.repeat(Math.min(val.length - 8, 20)) + val.slice(-4);
}

function platformInitial(name) {
  return (name || '?').trim()[0].toUpperCase();
}

function formatDate(iso) {
  if (!iso) return '—';
  return new Date(iso).toLocaleString();
}

function showToast(msg, type = '') {
  const el = document.getElementById('toast');
  el.textContent = msg;
  el.className = 'toast' + (type ? ' ' + type : '');
  el.classList.add('show');
  setTimeout(() => el.classList.remove('show'), 2800);
}

// ─── Screen switching ─────────────────────────────────────────────────────────
function showScreen(id) {
  document.querySelectorAll('.screen').forEach(s => s.classList.remove('active'));
  document.getElementById(id).classList.add('active');
  document.getElementById(id).style.display = '';
}

// ─── Modal helpers ─────────────────────────────────────────────────────────────
function openModal(id) {
  const el = document.getElementById(id);
  el.style.display = 'flex';
}
function closeModal(id) {
  document.getElementById(id).style.display = 'none';
}

document.querySelectorAll('[data-modal]').forEach(btn => {
  btn.addEventListener('click', () => closeModal(btn.dataset.modal));
});

document.querySelectorAll('.modal-overlay').forEach(overlay => {
  overlay.addEventListener('click', e => {
    if (e.target === overlay) closeModal(overlay.id);
  });
});

// ─── Eye toggle ───────────────────────────────────────────────────────────────
document.querySelectorAll('.eye-btn[data-target]').forEach(btn => {
  btn.addEventListener('click', () => {
    const input = document.getElementById(btn.dataset.target);
    input.type = input.type === 'password' ? 'text' : 'password';
  });
});

document.getElementById('toggle-pw').addEventListener('click', () => {
  const input = document.getElementById('master-pw');
  input.type = input.type === 'password' ? 'text' : 'password';
});

// ─── Auth flow ─────────────────────────────────────────────────────────────────
async function initAuth() {
  const res = await vault.exists();
  const exists = res.exists;
  if (exists) {
    document.getElementById('auth-title').textContent = 'Unlock Vault';
    document.getElementById('auth-subtitle').textContent = 'Enter your master password to access your API keys.';
    document.getElementById('auth-btn-text').textContent = 'Unlock';
    document.getElementById('confirm-pw-group').style.display = 'none';
  } else {
    document.getElementById('auth-title').textContent = 'Create Vault';
    document.getElementById('auth-subtitle').textContent = "Set a master password to protect your API keys. Don't forget it — there's no recovery.";
    document.getElementById('auth-btn-text').textContent = 'Create Vault';
    document.getElementById('confirm-pw-group').style.display = '';
  }
}

document.getElementById('auth-submit').addEventListener('click', handleAuth);
document.getElementById('master-pw').addEventListener('keydown', e => { if (e.key === 'Enter') handleAuth(); });
document.getElementById('confirm-pw').addEventListener('keydown', e => { if (e.key === 'Enter') handleAuth(); });

async function handleAuth() {
  const pw = document.getElementById('master-pw').value.trim();
  const errEl = document.getElementById('auth-error');
  errEl.textContent = '';
  if (!pw) { errEl.textContent = 'Please enter your master password.'; return; }

  const existsRes = await vault.exists();
  const exists = existsRes.exists;

  const btn = document.getElementById('auth-submit');
  const spinner = document.getElementById('auth-spinner');
  const btnText = document.getElementById('auth-btn-text');
  btn.disabled = true; spinner.style.display = 'inline-block'; btnText.style.display = 'none';

  if (!exists) {
    const confirm = document.getElementById('confirm-pw').value.trim();
    if (pw.length < 8) {
      errEl.textContent = 'Password must be at least 8 characters.';
      btn.disabled = false; spinner.style.display = 'none'; btnText.style.display = '';
      return;
    }
    if (pw !== confirm) {
      errEl.textContent = 'Passwords do not match.';
      btn.disabled = false; spinner.style.display = 'none'; btnText.style.display = '';
      return;
    }
    const res = await vault.create(pw);
    if (!res.ok) {
      errEl.textContent = res.error;
      btn.disabled = false; spinner.style.display = 'none'; btnText.style.display = '';
      return;
    }
    masterPassword = pw;
    vaultData = { entries: [] };
  } else {
    const res = await vault.unlock(pw);
    if (!res.ok) {
      errEl.textContent = res.error;
      btn.disabled = false; spinner.style.display = 'none'; btnText.style.display = '';
      return;
    }
    masterPassword = pw;
    vaultData = res.data;
  }

  btn.disabled = false; spinner.style.display = 'none'; btnText.style.display = '';
  document.getElementById('master-pw').value = '';
  document.getElementById('confirm-pw').value = '';
  enterApp();
}

// ─── App Initialization ────────────────────────────────────────────────────────
function enterApp() {
  showScreen('screen-app');
  renderCategories();
  renderKeys();
  loadVaultPath();
}

function lockVault() {
  masterPassword = null;
  vaultData = { entries: [] };
  activeCategory = '__all__';
  showScreen('screen-auth');
  initAuth();
}

document.getElementById('btn-lock').addEventListener('click', lockVault);

async function saveVault() {
  const res = await vault.save(masterPassword, vaultData);
  if (!res.ok) { showToast('Save failed: ' + res.error, 'error'); return false; }
  return true;
}

// ─── Categories ───────────────────────────────────────────────────────────────
function getCategories() {
  const cats = new Map();
  vaultData.entries.forEach(e => {
    const cat = (e.category || 'Uncategorized').trim();
    cats.set(cat, (cats.get(cat) || 0) + 1);
  });
  return cats;
}

function renderCategories() {
  const list = document.getElementById('category-list');
  list.innerHTML = '';

  const all = document.createElement('li');
  all.className = activeCategory === '__all__' ? 'active' : '';
  all.innerHTML = `<span>All Keys</span><span class="cat-count">${vaultData.entries.length}</span>`;
  all.addEventListener('click', () => { activeCategory = '__all__'; renderCategories(); renderKeys(); });
  list.appendChild(all);

  const cats = getCategories();
  cats.forEach((count, name) => {
    const li = document.createElement('li');
    li.className = activeCategory === name ? 'active' : '';
    li.innerHTML = `<span>${escHtml(name)}</span><span class="cat-count">${count}</span>`;
    li.addEventListener('click', () => { activeCategory = name; renderCategories(); renderKeys(); });
    list.appendChild(li);
  });

  const dl = document.getElementById('category-suggestions');
  dl.innerHTML = '';
  cats.forEach((_, name) => {
    const opt = document.createElement('option');
    opt.value = name;
    dl.appendChild(opt);
  });
}

// ─── Key rendering ─────────────────────────────────────────────────────────────
function getFilteredEntries() {
  const query = document.getElementById('search-input').value.toLowerCase().trim();
  return vaultData.entries.filter(e => {
    const inCat = activeCategory === '__all__' || (e.category || 'Uncategorized') === activeCategory;
    if (!query) return inCat;
    return inCat && (
      e.platform.toLowerCase().includes(query) ||
      (e.label || '').toLowerCase().includes(query) ||
      (e.category || '').toLowerCase().includes(query)
    );
  });
}

function renderKeys() {
  const grid = document.getElementById('key-grid');
  const emptyState = document.getElementById('empty-state');
  const entries = getFilteredEntries();

  document.getElementById('view-title').textContent = activeCategory === '__all__' ? 'All Keys' : activeCategory;
  document.getElementById('key-count').textContent = `${entries.length} key${entries.length !== 1 ? 's' : ''}`;

  grid.innerHTML = '';
  if (entries.length === 0) { emptyState.style.display = 'flex'; return; }
  emptyState.style.display = 'none';

  entries.forEach(entry => {
    const card = document.createElement('div');
    card.className = 'key-card';
    card.innerHTML = `
      <div class="key-card-platform">
        <div class="platform-icon">${escHtml(platformInitial(entry.platform))}</div>
        <span>${escHtml(entry.platform)}</span>
      </div>
      <div class="key-card-label">${escHtml(entry.label || '—')}</div>
      <div class="key-card-value">${escHtml(maskKey(entry.value))}</div>
      ${entry.category ? `<span class="key-card-category">${escHtml(entry.category)}</span>` : ''}
      <div class="key-card-actions">
        <button class="btn btn-ghost btn-sm" data-action="copy" data-id="${entry.id}">Copy Key</button>
        <button class="btn btn-ghost btn-sm" data-action="view" data-id="${entry.id}">View</button>
      </div>
    `;
    grid.appendChild(card);
  });

  grid.querySelectorAll('[data-action="copy"]').forEach(btn => {
    btn.addEventListener('click', e => { e.stopPropagation(); copyKey(btn.dataset.id); });
  });
  grid.querySelectorAll('[data-action="view"]').forEach(btn => {
    btn.addEventListener('click', e => { e.stopPropagation(); viewKey(btn.dataset.id); });
  });
  grid.querySelectorAll('.key-card').forEach(card => {
    card.addEventListener('click', (e) => {
      if (!e.target.closest('[data-action]')) {
        const btn = card.querySelector('[data-action="view"]');
        if (btn) viewKey(btn.dataset.id);
      }
    });
  });
}

function escHtml(str) {
  return String(str ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function copyKey(id) {
  const entry = vaultData.entries.find(e => e.id === id);
  if (!entry) return;
  navigator.clipboard.writeText(entry.value).then(() => {
    showToast('API key copied to clipboard', 'success');
  });
}

// ─── Search ───────────────────────────────────────────────────────────────────
document.getElementById('search-input').addEventListener('input', renderKeys);

// ─── View Key ─────────────────────────────────────────────────────────────────
let keyRevealed = false;

function viewKey(id) {
  const entry = vaultData.entries.find(e => e.id === id);
  if (!entry) return;
  viewingId = id;
  keyRevealed = false;

  document.getElementById('view-platform').textContent = entry.platform;
  document.getElementById('view-platform-val').textContent = entry.platform;
  document.getElementById('view-category-val').textContent = entry.category || '—';
  document.getElementById('view-label-val').textContent = entry.label || '—';
  document.getElementById('view-key-val').textContent = maskKey(entry.value);
  document.getElementById('view-toggle-key').textContent = 'Show';
  document.getElementById('view-notes-val').textContent = entry.notes || '—';
  document.getElementById('view-date-val').textContent = formatDate(entry.createdAt);
  openModal('modal-view');
}

document.getElementById('view-toggle-key').addEventListener('click', () => {
  const entry = vaultData.entries.find(e => e.id === viewingId);
  if (!entry) return;
  keyRevealed = !keyRevealed;
  document.getElementById('view-key-val').textContent = keyRevealed ? entry.value : maskKey(entry.value);
  document.getElementById('view-toggle-key').textContent = keyRevealed ? 'Hide' : 'Show';
});

document.getElementById('view-copy-key').addEventListener('click', () => {
  if (viewingId) copyKey(viewingId);
});

document.getElementById('btn-edit-key').addEventListener('click', () => {
  closeModal('modal-view');
  editKey(viewingId);
});

document.getElementById('btn-delete-key').addEventListener('click', () => {
  const entry = vaultData.entries.find(e => e.id === viewingId);
  if (!entry) return;
  document.getElementById('confirm-key-name').textContent = entry.platform + (entry.label ? ` (${entry.label})` : '');
  closeModal('modal-view');
  openModal('modal-confirm');
});

// ─── Add / Edit ────────────────────────────────────────────────────────────────
document.getElementById('btn-add').addEventListener('click', () => {
  editingId = null;
  document.getElementById('modal-key-title').textContent = 'Add API Key';
  document.getElementById('key-platform').value = '';
  document.getElementById('key-category').value = activeCategory !== '__all__' ? activeCategory : '';
  document.getElementById('key-label').value = '';
  document.getElementById('key-value').value = '';
  document.getElementById('key-notes').value = '';
  document.getElementById('modal-key-error').textContent = '';
  openModal('modal-key');
  document.getElementById('key-platform').focus();
});

function editKey(id) {
  const entry = vaultData.entries.find(e => e.id === id);
  if (!entry) return;
  editingId = id;
  document.getElementById('modal-key-title').textContent = 'Edit API Key';
  document.getElementById('key-platform').value = entry.platform;
  document.getElementById('key-category').value = entry.category || '';
  document.getElementById('key-label').value = entry.label || '';
  document.getElementById('key-value').value = entry.value;
  document.getElementById('key-notes').value = entry.notes || '';
  document.getElementById('modal-key-error').textContent = '';
  openModal('modal-key');
}

document.getElementById('btn-save-key').addEventListener('click', async () => {
  const platform = document.getElementById('key-platform').value.trim();
  const category = document.getElementById('key-category').value.trim();
  const label    = document.getElementById('key-label').value.trim();
  const value    = document.getElementById('key-value').value.trim();
  const notes    = document.getElementById('key-notes').value.trim();
  const errEl    = document.getElementById('modal-key-error');

  if (!platform) { errEl.textContent = 'Platform name is required.'; return; }
  if (!value)    { errEl.textContent = 'API key value is required.'; return; }
  errEl.textContent = '';

  if (editingId) {
    const idx = vaultData.entries.findIndex(e => e.id === editingId);
    if (idx !== -1) vaultData.entries[idx] = { ...vaultData.entries[idx], platform, category, label, value, notes };
  } else {
    vaultData.entries.push({ id: uuid(), platform, category, label, value, notes, createdAt: new Date().toISOString() });
  }

  const ok = await saveVault();
  if (ok) {
    closeModal('modal-key');
    renderCategories();
    renderKeys();
    showToast(editingId ? 'Key updated.' : 'Key added.', 'success');
  }
});

// ─── Delete ───────────────────────────────────────────────────────────────────
document.getElementById('btn-confirm-delete').addEventListener('click', async () => {
  vaultData.entries = vaultData.entries.filter(e => e.id !== viewingId);
  const ok = await saveVault();
  if (ok) {
    closeModal('modal-confirm');
    renderCategories();
    renderKeys();
    showToast('Key deleted.', 'success');
  }
});

// ─── Settings ─────────────────────────────────────────────────────────────────
document.getElementById('btn-settings').addEventListener('click', () => {
  document.getElementById('old-pw').value = '';
  document.getElementById('new-pw').value = '';
  document.getElementById('new-pw-confirm').value = '';
  document.getElementById('settings-error').textContent = '';
  openModal('modal-settings');
});

document.getElementById('btn-change-pw').addEventListener('click', async () => {
  const oldPw   = document.getElementById('old-pw').value;
  const newPw   = document.getElementById('new-pw').value;
  const confirmPw = document.getElementById('new-pw-confirm').value;
  const errEl   = document.getElementById('settings-error');

  if (!oldPw || !newPw) { errEl.textContent = 'All fields are required.'; return; }
  if (newPw.length < 8) { errEl.textContent = 'New password must be at least 8 characters.'; return; }
  if (newPw !== confirmPw) { errEl.textContent = 'New passwords do not match.'; return; }
  errEl.textContent = '';

  const res = await vault.changePassword(oldPw, newPw);
  if (!res.ok) { errEl.textContent = res.error; return; }

  masterPassword = newPw;
  closeModal('modal-settings');
  showToast('Master password changed successfully.', 'success');
});

document.getElementById('btn-export').addEventListener('click', async () => {
  const dest = prompt('Export path (leave blank for ~/nutcracker-export.json):');
  if (dest === null) return; // cancelled
  const exportPath = dest.trim() || undefined;
  const res = await vault.export(masterPassword, exportPath);
  if (res.ok) {
    showToast('Exported successfully to ' + (exportPath || '~/nutcracker-export.json'), 'success');
  } else if (res.error !== 'Cancelled') {
    showToast('Export failed: ' + res.error, 'error');
  }
});

async function loadVaultPath() {
  const res = await api.get('/api/status');
  document.getElementById('vault-path-display').textContent = res.vault_path || '—';
}

// ─── Boot ─────────────────────────────────────────────────────────────────────
initAuth();
