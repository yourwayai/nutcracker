# Nutcracker 🔐

A lightweight, secure desktop API key manager for macOS.

## Features

- **Robust Encryption**: AES-256-GCM authenticated encryption with PBKDF2-SHA256 key derivation (310,000 iterations).
- **Zero Cloud Dependence**: Everything is stored locally in `~/.nutcracker/vault.enc` with strict file permissions (`0600`).
- **Clean Modern UI**: Dark-themed responsive interface with platform categories, fast search, masked values, and one-click clipboard copying.
- **Vault Management**: Change master password anytime, re-encrypting all entries, or export your vault to JSON.
- **Zero Node/Electron Dependency**: Runs with standard macOS Python 3 + `cryptography`, launching directly in a native desktop app window.

## Quick Start

### 1. Launch

You can launch Nutcracker in any of the following ways:

```bash
# Option A: Run the launcher script
./run.sh

# Option B: Run via Python directly
python3 src/server.py

# Option C: In Finder, double-click Nutcracker.command
```

Nutcracker will automatically launch in Chrome/Brave app mode (or your default browser) at `http://localhost:17432`.

### 2. First Run

- On initial startup, set your **Master Password** (minimum 8 characters).
- Once unlocked, add and categorize your API keys (e.g., OpenAI, Anthropic, AWS, GitHub).
- Use **Lock Vault** or close the window when done.
