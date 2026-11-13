const { app, BrowserWindow, ipcMain, dialog, nativeTheme } = require('electron');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const os = require('os');

// --- Constants ---
const VAULT_DIR = process.env.NUTCRACKER_VAULT_DIR || path.join(os.homedir(), '.nutcracker');
const VAULT_FILE = process.env.NUTCRACKER_VAULT_FILE || path.join(VAULT_DIR, 'vault.enc');
const SALT_BYTES = 32;
const IV_BYTES = 12;   // GCM nonce
const KEY_BYTES = 32;  // AES-256
const PBKDF2_ITERS = 310_000; // OWASP 2023 recommendation for PBKDF2-SHA256

let mainWindow;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1100,
    height: 750,
    minWidth: 800,
    minHeight: 560,
    titleBarStyle: 'hiddenInset',
    backgroundColor: '#0f1117',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
    },
    icon: path.join(__dirname, '..', 'assets', 'icon.png'),
  });

  mainWindow.loadFile(path.join(__dirname, 'renderer', 'index.html'));
}

app.whenReady().then(() => {
  createWindow();
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});

// ── Crypto helpers ─────────────────────────────────────────────────────────

function deriveKey(password, salt) {
  return crypto.pbkdf2Sync(password, salt, PBKDF2_ITERS, KEY_BYTES, 'sha256');
}

function encrypt(plaintext, key) {
  const iv = crypto.randomBytes(IV_BYTES);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  // Layout: iv(12) | tag(16) | ciphertext
  return Buffer.concat([iv, tag, encrypted]);
}

function decrypt(buf, key) {
  const iv = buf.subarray(0, IV_BYTES);
  const tag = buf.subarray(IV_BYTES, IV_BYTES + 16);
  const ciphertext = buf.subarray(IV_BYTES + 16);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
}

// ── Vault file helpers ─────────────────────────────────────────────────────

function vaultExists() {
  return fs.existsSync(VAULT_FILE);
}

function readVaultFile() {
  return fs.readFileSync(VAULT_FILE);
}

function writeVaultFile(buf) {
  fs.mkdirSync(path.dirname(VAULT_FILE), { recursive: true, mode: 0o700 });
  fs.writeFileSync(VAULT_FILE, buf, { mode: 0o600 });
}

// ── IPC handlers ───────────────────────────────────────────────────────────

// Check if vault already exists (determines setup vs unlock flow)
ipcMain.handle('vault:exists', () => vaultExists());

// Create a brand new vault with a master password
ipcMain.handle('vault:create', (_e, password) => {
  try {
    const salt = crypto.randomBytes(SALT_BYTES);
    const key = deriveKey(password, salt);
    const payload = JSON.stringify({ entries: [] });
    const encrypted = encrypt(payload, key);
    // File layout: salt(32) | encrypted_blob
    writeVaultFile(Buffer.concat([salt, encrypted]));
    return { ok: true };
  } catch (err) {
    return { ok: false, error: err.message };
  }
});

// Unlock vault — returns decrypted data on success
ipcMain.handle('vault:unlock', (_e, password) => {
  try {
    const raw = readVaultFile();
    const salt = raw.subarray(0, SALT_BYTES);
    const blob = raw.subarray(SALT_BYTES);
    const key = deriveKey(password, salt);
    const plaintext = decrypt(blob, key);
    const data = JSON.parse(plaintext);
    return { ok: true, data };
  } catch {
    return { ok: false, error: 'Wrong password or corrupted vault.' };
  }
});

// Save updated entries back to vault
ipcMain.handle('vault:save', (_e, password, data) => {
  try {
    const raw = readVaultFile();
    const salt = raw.subarray(0, SALT_BYTES);
    const key = deriveKey(password, salt);
    const payload = JSON.stringify(data);
    const encrypted = encrypt(payload, key);
    writeVaultFile(Buffer.concat([salt, encrypted]));
    return { ok: true };
  } catch (err) {
    return { ok: false, error: err.message };
  }
});

// Change master password (re-encrypt with new key)
ipcMain.handle('vault:changePassword', (_e, oldPassword, newPassword) => {
  try {
    const raw = readVaultFile();
    const oldSalt = raw.subarray(0, SALT_BYTES);
    const blob = raw.subarray(SALT_BYTES);
    const oldKey = deriveKey(oldPassword, oldSalt);
    const plaintext = decrypt(blob, oldKey);

    const newSalt = crypto.randomBytes(SALT_BYTES);
    const newKey = deriveKey(newPassword, newSalt);
    const encrypted = encrypt(plaintext, newKey);
    writeVaultFile(Buffer.concat([newSalt, encrypted]));
    return { ok: true };
  } catch {
    return { ok: false, error: 'Wrong current password.' };
  }
});

// Export vault as plaintext JSON (user confirms dialog first)
ipcMain.handle('vault:export', async (_e, password) => {
  try {
    const raw = readVaultFile();
    const salt = raw.subarray(0, SALT_BYTES);
    const blob = raw.subarray(SALT_BYTES);
    const key = deriveKey(password, salt);
    const plaintext = decrypt(blob, key);

    const { filePath } = await dialog.showSaveDialog(mainWindow, {
      title: 'Export API Keys',
      defaultPath: 'nutcracker-export.json',
      filters: [{ name: 'JSON', extensions: ['json'] }],
    });
    if (!filePath) return { ok: false, error: 'Cancelled' };
    fs.writeFileSync(filePath, plaintext, 'utf8');
    return { ok: true };
  } catch (err) {
    return { ok: false, error: err.message };
  }
});

ipcMain.handle('app:getVaultPath', () => VAULT_FILE);
