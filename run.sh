#!/bin/sh
# ApprovalGuard one-command run (stdlib only, no install step).
# Usage: ./run.sh [port]   (default port 8000)
set -e
cd "$(dirname "$0")"
PORT="${1:-${PORT:-8000}}"
export PORT
echo "Starting ApprovalGuard on http://0.0.0.0:$PORT ..."
exec python3 app.py
