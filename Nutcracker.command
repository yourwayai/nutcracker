#!/usr/bin/env bash
DIR="$(cd "$(dirname "$0")" && pwd)"
exec /usr/bin/python3 "$DIR/src/server.py"
