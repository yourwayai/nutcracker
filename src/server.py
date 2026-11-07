#!/usr/bin/env python3
"""
Nutcracker — API Key Manager
Local HTTP server backend with AES-256-GCM encryption.
"""

import json
import os
import sys
import hashlib
import hmac
import base64
import secrets
import struct
import http.server
import urllib.parse
import urllib.request
import threading
import subprocess
import time
from pathlib import Path

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    CRYPTO_OK = True
except ImportError:
    CRYPTO_OK = False

# ── Constants ──────────────────────────────────────────────────────────────────
VAULT_DIR  = Path(os.environ.get('NUTCRACKER_VAULT_DIR', str(Path.home() / '.nutcracker')))
VAULT_FILE = Path(os.environ.get('NUTCRACKER_VAULT_FILE', str(VAULT_DIR / 'vault.enc')))
SALT_BYTES = 32
PBKDF2_ITERS = 310_000
PORT = int(os.environ.get('NUTCRACKER_PORT', '17432'))  # default local port

# ── Crypto ─────────────────────────────────────────────────────────────────────
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERS,
    )
    return kdf.derive(password.encode('utf-8'))

def encrypt(plaintext: str, key: bytes) -> bytes:
    nonce = secrets.token_bytes(12)
    ct = AESGCM(key).encrypt(nonce, plaintext.encode('utf-8'), None)
    return nonce + ct  # nonce(12) + ciphertext+tag(len+16)

def decrypt(blob: bytes, key: bytes) -> str:
    nonce, ct = blob[:12], blob[12:]
    return AESGCM(key).decrypt(nonce, ct, None).decode('utf-8')

# ── Vault helpers ──────────────────────────────────────────────────────────────
def vault_exists() -> bool:
    return VAULT_FILE.exists()

def _write_vault_bytes(blob: bytes):
    VAULT_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp_file = VAULT_DIR / f'vault.enc.tmp.{secrets.token_hex(4)}'
    tmp_file.write_bytes(blob)
    tmp_file.chmod(0o600)
    tmp_file.replace(VAULT_FILE)

def create_vault(password: str) -> dict:
    salt = secrets.token_bytes(SALT_BYTES)
    key  = derive_key(password, salt)
    payload = json.dumps({'entries': []})
    encrypted = encrypt(payload, key)
    _write_vault_bytes(salt + encrypted)
    return {'ok': True}

def unlock_vault(password: str) -> dict:
    try:
        raw  = VAULT_FILE.read_bytes()
        salt = raw[:SALT_BYTES]
        blob = raw[SALT_BYTES:]
        key  = derive_key(password, salt)
        text = decrypt(blob, key)
        data = json.loads(text)
        return {'ok': True, 'data': data}
    except Exception:
        return {'ok': False, 'error': 'Wrong master password or corrupted vault.'}

def save_vault(password: str, data: dict) -> dict:
    try:
        raw  = VAULT_FILE.read_bytes()
        salt = raw[:SALT_BYTES]
        key  = derive_key(password, salt)
        text = json.dumps(data)
        encrypted = encrypt(text, key)
        _write_vault_bytes(salt + encrypted)
        return {'ok': True}
    except Exception as e:
        return {'ok': False, 'error': str(e)}

def change_password(old_pw: str, new_pw: str) -> dict:
    try:
        raw     = VAULT_FILE.read_bytes()
        old_salt = raw[:SALT_BYTES]
        blob    = raw[SALT_BYTES:]
        old_key = derive_key(old_pw, old_salt)
        text    = decrypt(blob, old_key)
        new_salt = secrets.token_bytes(SALT_BYTES)
        new_key  = derive_key(new_pw, new_salt)
        _write_vault_bytes(new_salt + encrypt(text, new_key))
        return {'ok': True}
    except Exception:
        return {'ok': False, 'error': 'Wrong current password.'}

def export_vault(password: str, export_path: str) -> dict:
    try:
        raw  = VAULT_FILE.read_bytes()
        salt = raw[:SALT_BYTES]
        blob = raw[SALT_BYTES:]
        key  = derive_key(password, salt)
        text = decrypt(blob, key)
        target = Path(export_path).expanduser().resolve()
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding='utf-8')
        return {'ok': True}
    except Exception as e:
        return {'ok': False, 'error': str(e)}

# ── HTTP Handler ───────────────────────────────────────────────────────────────
STATIC_DIR = Path(__file__).parent / 'renderer'

class NutcrackerHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # silence access log

    def send_json(self, data, code=200):
        body = json.dumps(data).encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Access-Control-Allow-Origin', f'http://localhost:{PORT}')
        self.end_headers()
        self.wfile.write(body)

    def send_static(self, path: Path):
        if not path.exists():
            self.send_error(404)
            return
        content = path.read_bytes()
        mime = {
            '.html': 'text/html; charset=utf-8',
            '.css':  'text/css; charset=utf-8',
            '.js':   'application/javascript; charset=utf-8',
            '.png':  'image/png',
            '.ico':  'image/x-icon',
        }.get(path.suffix, 'application/octet-stream')
        self.send_response(200)
        self.send_header('Content-Type', mime)
        self.send_header('Content-Length', str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path   = parsed.path.lstrip('/')

        if path == '' or path == 'index.html':
            self.send_static(STATIC_DIR / 'index.html')
        elif path.endswith('.css'):
            self.send_static(STATIC_DIR / path)
        elif path.endswith('.js'):
            self.send_static(STATIC_DIR / path)
        elif path == 'api/status':
            self.send_json({
                'vault_exists': vault_exists(),
                'vault_path': str(VAULT_FILE),
                'crypto_ok': CRYPTO_OK,
            })
        else:
            self.send_error(404)

    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        body   = self.rfile.read(length)
        try:
            req = json.loads(body) if body else {}
        except Exception:
            self.send_json({'ok': False, 'error': 'Invalid JSON'}, 400)
            return

        path = self.path

        if path == '/api/vault/exists':
            self.send_json({'ok': True, 'exists': vault_exists()})

        elif path == '/api/vault/create':
            pw = req.get('password', '')
            if not pw:
                self.send_json({'ok': False, 'error': 'Password required'})
            else:
                self.send_json(create_vault(pw))

        elif path == '/api/vault/unlock':
            pw = req.get('password', '')
            self.send_json(unlock_vault(pw))

        elif path == '/api/vault/save':
            pw   = req.get('password', '')
            data = req.get('data', {})
            self.send_json(save_vault(pw, data))

        elif path == '/api/vault/change_password':
            self.send_json(change_password(
                req.get('old_password', ''),
                req.get('new_password', ''),
            ))

        elif path == '/api/vault/export':
            pw   = req.get('password', '')
            dest = req.get('path', str(Path.home() / 'nutcracker-export.json'))
            self.send_json(export_vault(pw, dest))

        elif path == '/api/app/quit':
            self.send_json({'ok': True})
            threading.Thread(target=lambda: (time.sleep(0.3), os._exit(0))).start()

        else:
            self.send_json({'ok': False, 'error': 'Unknown endpoint'}, 404)


# ── Main ───────────────────────────────────────────────────────────────────────
def open_browser():
    url = f'http://localhost:{PORT}'
    time.sleep(0.4)
    # Try Chrome/Brave app mode first for a desktop-app look, fallback to default browser
    candidates = [
        ['open', '-n', '-a', 'Google Chrome', '--args', f'--app={url}', '--window-size=1100,750'],
        ['open', '-n', '-a', 'Brave Browser', '--args', f'--app={url}'],
        ['open', url],
    ]
    for cmd in candidates:
        try:
            res = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if res.returncode == 0:
                break
        except Exception:
            continue

def main():
    if not CRYPTO_OK:
        print('ERROR: cryptography package not installed.')
        print('Run: python3 -m pip install cryptography --user')
        sys.exit(1)

    # If already running, focus existing window and exit cleanly
    try:
        req = urllib.request.Request(f'http://localhost:{PORT}/api/status')
        with urllib.request.urlopen(req, timeout=0.8) as resp:
            if resp.status == 200:
                print(f'🔐 Nutcracker is already running on port {PORT}.')
                print('   Opening browser window...')
                open_browser()
                return
    except Exception:
        pass

    server = http.server.ThreadingHTTPServer(('127.0.0.1', PORT), NutcrackerHandler)

    print(f'🔐 Nutcracker running at http://localhost:{PORT}')
    print('   Press Ctrl+C to quit.')

    if not os.environ.get('NUTCRACKER_NO_BROWSER'):
        threading.Thread(target=open_browser, daemon=True).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print('\nShutting down...')
        server.shutdown()

if __name__ == '__main__':
    main()
