#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STATE="$HOME/.local/state/quantum-shield"
PIDFILE="$STATE/qsctl.pid"
LOGFILE="$STATE/server.log"
URL="http://127.0.0.1:18090"

mkdir -p "$STATE"
cd "$ROOT"
export LD_LIBRARY_PATH="/usr/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

if [[ ! -f .env ]]; then
  echo "SETUP REQUIRED: .env is missing."
  echo "Configure PayPal Sandbox credentials before starting."
  exit 1
fi

set -a
source .env
set +a

if [[ -z "${QS_API_TOKEN:-}" || -z "${QS_MERCHANT_ID:-}" ]]; then
  echo "SETUP REQUIRED: QS_API_TOKEN or QS_MERCHANT_ID is missing from .env."
  exit 1
fi

if curl -fsS "$URL/health" >/dev/null 2>&1; then
  echo "Quantum Shield is already running."
  echo "Dashboard: $URL"
  exit 0
fi

if [[ ! -x target/release/qsctl ]]; then
  echo "Building Quantum Shield for the first time..."
  cargo build --locked --release --bin qsctl
fi

echo "Starting Quantum Shield on your computer..."
nohup target/release/qsctl payment-serve --listen 127.0.0.1:18090 \
  >"$LOGFILE" 2>&1 </dev/null &
echo $! > "$PIDFILE"

for _ in $(seq 1 30); do
  if curl -fsS "$URL/health" >/dev/null 2>&1; then
    echo
    echo "QUANTUM SHIELD IS READY."
    echo "Dashboard: $URL"
    echo "Health:    $URL/health"
    echo "Log:       $LOGFILE"
    exit 0
  fi
  sleep 1
done

echo "Startup failed. Recent server log:"
tail -40 "$LOGFILE" || true
exit 1
