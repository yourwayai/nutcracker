#!/usr/bin/env bash
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
[ -f "$HOME/.cargo/env" ] && source "$HOME/.cargo/env"

if [ -f "$DIR/src-tauri/target/release/nutcracker" ]; then
    exec "$DIR/src-tauri/target/release/nutcracker"
elif [ -f "$DIR/src-tauri/target/debug/nutcracker" ]; then
    exec "$DIR/src-tauri/target/debug/nutcracker"
elif command -v cargo >/dev/null 2>&1; then
    exec cargo run --release --manifest-path "$DIR/src-tauri/Cargo.toml"
else
    exec /usr/bin/python3 "$DIR/src/server.py"
fi
