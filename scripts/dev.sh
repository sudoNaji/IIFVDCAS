#!/bin/bash
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
echo "Starting IIFVDCAS development servers..."
pgrep -x redis-server &>/dev/null || redis-server --daemonize yes --loglevel warning
echo "[+] Backend  → http://localhost:8000  (API docs: http://localhost:8000/docs)"
echo "[+] Frontend → http://localhost:5173"
cd "$ROOT/backend"
PYTHONPATH="$ROOT/backend" uvicorn main:app --reload --host 0.0.0.0 --port 8000 &
BPID=$!
cd "$ROOT/frontend"
npm run dev &
FPID=$!
trap "kill $BPID $FPID 2>/dev/null; exit 0" INT TERM
wait $BPID $FPID
