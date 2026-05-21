#!/bin/bash
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BACKEND="$ROOT/backend"
FRONTEND="$ROOT/frontend"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  IIFVDCAS — Dev Server"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# ── Redis (optional, skip gracefully if missing) ──
if command -v redis-server &>/dev/null; then
    pgrep -x redis-server &>/dev/null || redis-server --daemonize yes --loglevel warning
    echo "[✅] Redis started"
else
    echo "[⚠️ ] redis-server not found — skipping (install: sudo apt install redis-server)"
fi

# ── Frontend deps check ──
if [ ! -d "$FRONTEND/node_modules" ]; then
    echo "[⚙️ ] node_modules missing — running npm install..."
    cd "$FRONTEND" && npm install
fi

# ── Backend ──
echo "[+] Backend  → http://localhost:8000"
echo "    API docs → http://localhost:8000/docs"
cd "$BACKEND"
PYTHONPATH="$BACKEND" uvicorn main:app --reload --host 0.0.0.0 --port 8000 &
BPID=$!
sleep 2

# ── Frontend ──
echo "[+] Frontend → http://localhost:5173"
cd "$FRONTEND"
npx vite &
FPID=$!

echo ""
echo "Both servers running. Press Ctrl+C to stop."
trap "echo 'Stopping...'; kill $BPID $FPID 2>/dev/null; exit 0" INT TERM
wait $BPID $FPID
