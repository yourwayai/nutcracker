# Nutcracker 🔐

A lightweight, secure native desktop API key manager built with **Tauri v2 + Rust**.

## Architecture & Features

- **Tauri v2 Native Desktop App**:
  - Native macOS WKWebView window (no Chromium overhead).
  - Native binary with tiny memory footprint (~30MB) and instant startup.
  - Rust backend handling cryptographic operations directly with memory safety.
- **Robust Encryption**:
  - **AES-256-GCM** authenticated encryption.
  - **PBKDF2-SHA256** key derivation (310,000 iterations).
  - Local vault stored at `~/.nutcracker/vault.enc` with strict POSIX permissions (`0600`) and atomic replace.
- **Clean Modern Dark UI**:
  - Platform categorization (OpenAI, Anthropic, AWS, GitHub, etc.).
  - Instant search & filtering.
  - Masked values with one-click clipboard copying.
  - Master password modification & JSON export.
- **Dual Runtime Support**:
  - Runs natively via **Tauri (Rust)** desktop window.
  - Seamless fallback to local Python server if needed.

## Quick Start

### 1. Launch

You can launch Nutcracker via:

```bash
# Option A: Run the launcher script (automatically runs native Tauri release binary)
./run.sh

# Option B: Run via Cargo directly
cargo run --release --manifest-path src-tauri/Cargo.toml

# Option C: In Finder, double-click Nutcracker.command
```

### 2. First Run

- On initial startup, set your **Master Password** (minimum 8 characters).
- Add and categorize your API keys.
- Click **Lock Vault** or close the app when done.
