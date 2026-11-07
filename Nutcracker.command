#!/usr/bin/env bash
DIR="$(cd "$(dirname "$0")" && pwd)"
[ -f "$HOME/.cargo/env" ] && source "$HOME/.cargo/env"

if [ -f "$DIR/src-tauri/target/release/nutcracker" ]; then
    exec "$DIR/src-tauri/target/release/nutcracker"
elif [ -f "$DIR/src-tauri/target/debug/nutcracker" ]; then
    exec "$DIR/src-tauri/target/debug/nutcracker"
else
    exec /usr/bin/python3 "$DIR/src/server.py"
fi
