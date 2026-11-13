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

# ── Dynamic Configuration Helpers ──────────────────────────────────────────────
def get_vault_dir() -> Path:
    return Path(os.environ.get('NUTCRACKER_VAULT_DIR', str(Path.home() / '.nutcracker')))

def get_vault_file() -> Path:
    env_file = os.environ.get('NUTCRACKER_VAULT_FILE', '').strip()
    if env_file:
        return Path(env_file)
    return get_vault_dir() / 'vault.enc'

def get_configured_port() -> int:
    return int(os.environ.get('NUTCRACKER_PORT', '17432'))

# Backward compatibility attributes (module-level defaults)
VAULT_DIR  = get_vault_dir()
VAULT_FILE = get_vault_file()
SALT_BYTES = 32
PBKDF2_ITERS = 310_000
PORT = get_configured_port()

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
    return get_vault_file().exists()

def _write_vault_bytes(blob: bytes):
    v_dir = get_vault_dir()
    v_file = get_vault_file()
    v_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp_file = v_dir / f'vault.enc.tmp.{secrets.token_hex(4)}'
    tmp_file.write_bytes(blob)
    tmp_file.chmod(0o600)
    tmp_file.replace(v_file)

def create_vault(password: str) -> dict:
    salt = secrets.token_bytes(SALT_BYTES)
    key  = derive_key(password, salt)
    payload = json.dumps({'entries': []})
    encrypted = encrypt(payload, key)
    _write_vault_bytes(salt + encrypted)
    return {'ok': True}

def unlock_vault(password: str) -> dict:
    try:
        raw  = get_vault_file().read_bytes()
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
        raw  = get_vault_file().read_bytes()
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
        raw     = get_vault_file().read_bytes()
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
        raw  = get_vault_file().read_bytes()
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
        port = self.server.server_address[1] if hasattr(self, 'server') and hasattr(self.server, 'server_address') else get_configured_port()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Access-Control-Allow-Origin', f'http://localhost:{port}')
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
            actual_port = self.server.server_address[1] if hasattr(self, 'server') and hasattr(self.server, 'server_address') else get_configured_port()
            self.send_json({
                'vault_exists': vault_exists(),
                'vault_path': str(get_vault_file()),
                'crypto_ok': CRYPTO_OK,
                'port': actual_port,
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
def open_browser(port: int = None):
    if port is None:
        port = get_configured_port()
    url = f'http://localhost:{port}'
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

def create_server(host: str = '127.0.0.1', port: int = None) -> http.server.ThreadingHTTPServer:
    if port is None:
        port = get_configured_port()
    return http.server.ThreadingHTTPServer((host, port), NutcrackerHandler)

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Nutcracker API Key Manager Backend")
    parser.add_argument("--port", "-p", type=int, default=None, help="Port to listen on (or set NUTCRACKER_PORT)")
    parser.add_argument("--vault-file", type=str, default=None, help="Path to vault.enc (or set NUTCRACKER_VAULT_FILE)")
    parser.add_argument("--vault-dir", type=str, default=None, help="Path to vault dir (or set NUTCRACKER_VAULT_DIR)")
    parser.add_argument("--no-browser", action="store_true", help="Do not launch browser on startup")
    args, _ = parser.parse_known_args()

    if args.port is not None:
        os.environ['NUTCRACKER_PORT'] = str(args.port)
    if args.vault_file is not None:
        os.environ['NUTCRACKER_VAULT_FILE'] = str(args.vault_file)
    if args.vault_dir is not None:
        os.environ['NUTCRACKER_VAULT_DIR'] = str(args.vault_dir)
    if args.no_browser:
        os.environ['NUTCRACKER_NO_BROWSER'] = "1"

    if not CRYPTO_OK:
        print('ERROR: cryptography package not installed.')
        print('Run: python3 -m pip install cryptography --user')
        sys.exit(1)

    port = get_configured_port()

    # If already running on non-zero port, focus existing window and exit cleanly
    if port != 0:
        try:
            req = urllib.request.Request(f'http://localhost:{port}/api/status')
            with urllib.request.urlopen(req, timeout=0.8) as resp:
                if resp.status == 200:
                    print(f'🔐 Nutcracker is already running on port {port}.')
                    print('   Opening browser window...')
                    open_browser(port)
                    return
        except Exception:
            pass

    server = create_server('127.0.0.1', port)
    bound_port = server.server_address[1]

    print(f'🔐 Nutcracker running at http://localhost:{bound_port}')
    print('   Press Ctrl+C to quit.')

    if not os.environ.get('NUTCRACKER_NO_BROWSER'):
        threading.Thread(target=open_browser, args=(bound_port,), daemon=True).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print('\nShutting down...')
        server.shutdown()

if __name__ == '__main__':
    main()
