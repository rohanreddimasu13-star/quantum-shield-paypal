#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
URL="http://127.0.0.1:18090"
BIN="$ROOT/target/release/qsctl"
STATE="${XDG_STATE_HOME:-$HOME/.local/state}/quantum-shield"
TOKEN_FILE="$STATE/dashboard-token"
LOG="$STATE/server.log"
PID_FILE="$STATE/server.pid"
mkdir -p "$STATE"
chmod 700 "$STATE"

fail() { printf 'Quantum Shield PayPal: %s\n' "$1" >&2; exit 1; }
printf '\nWelcome to Quantum Shield PayPal. This launcher uses Sandbox and local storage.\n'
printf 'Step 1 of 5: checking your computer and required tools…\n'
case "$(uname -s 2>/dev/null || true)" in
  Linux) export LD_LIBRARY_PATH="/usr/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" ;;
  *) fail "This launcher currently supports Linux. This operating system has not been validated; use a supported Linux computer or Linux VM." ;;
esac
for cmd in cargo curl; do command -v "$cmd" >/dev/null 2>&1 || fail "Required command '$cmd' was not found. Install Rust/Cargo and curl, then retry."; done
printf 'Linux, Cargo, and curl are ready.\n'

if [[ ! -x "$BIN" || "$ROOT/Cargo.toml" -nt "$BIN" || "$ROOT/Cargo.lock" -nt "$BIN" ]] || \
   find "$ROOT/src" "$ROOT/web" -type f -newer "$BIN" -print -quit 2>/dev/null | grep -q .; then
  printf 'Building Quantum Shield PayPal release binary…\n'
  (cd "$ROOT" && cargo build --locked --release --bin qsctl) || fail "Release build failed. Review the Cargo error above."
else
  printf 'Using the existing Quantum Shield program.\n'
fi

printf 'Step 2 of 5: securing your local sign-in…\n'
if [[ ! -s "$TOKEN_FILE" ]]; then
  command -v openssl >/dev/null 2>&1 || fail "OpenSSL is required to create the local dashboard session token."
  umask 077
  openssl rand -hex 32 > "$TOKEN_FILE" || fail "Could not create the dashboard session token."
fi
chmod 600 "$TOKEN_FILE"
QS_API_TOKEN="$(<"$TOKEN_FILE")"
[[ ${#QS_API_TOKEN} -ge 32 ]] || fail "The local dashboard token is invalid; remove $TOKEN_FILE and retry."
printf 'Private dashboard sign-in is ready.\n'

HEALTH="$(curl --silent --show-error --fail --max-time 2 "$URL/health" 2>/dev/null || true)"
if [[ "$HEALTH" == *'"service":"quantum-shield-paypal"'* ]]; then
  printf 'Quantum Shield PayPal is already running at %s\n' "$URL"
else
  printf 'Step 3 of 5: starting the local service and preparing storage…\n'
  [[ -z "$HEALTH" ]] || fail "Port 18090 is answering, but it is not Quantum Shield PayPal. Stop that service or choose another port."
  if command -v ss >/dev/null 2>&1 && ss -ltnH 'sport = :18090' 2>/dev/null | grep -q .; then
    fail "Port 18090 is in use by a service that did not answer the Quantum Shield health check."
  fi
  umask 077
  touch "$LOG" && chmod 600 "$LOG"
  export QS_API_TOKEN
  export QS_MERCHANT_ID="${QS_MERCHANT_ID:-merchant_local}"
  export PAYPAL_ENVIRONMENT=sandbox
  export QS_KEY_DIR="$STATE/payment-pq-keys"
  "$BIN" payment-serve --listen 127.0.0.1:18090 >>"$LOG" 2>&1 &
  SERVER_PID=$!
  printf '%s\n' "$SERVER_PID" > "$PID_FILE"
  chmod 600 "$PID_FILE"
  started=0
  for _ in $(seq 1 45); do
    if curl --silent --fail --max-time 2 "$URL/health" >/dev/null 2>&1; then started=1; break; fi
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then break; fi
    sleep 1
  done
  if [[ "$started" != 1 ]]; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
    rm -f "$PID_FILE"
    if grep -qiE 'Operation not permitted|PermissionDenied' "$LOG"; then
      fail "Your computer's security policy denied the local connection. Quantum Shield was stopped. Run it in a normal desktop session that permits 127.0.0.1, or ask your administrator to allow local loopback. Private diagnostics: $LOG."
    elif grep -qiE 'Address already in use|address in use' "$LOG"; then
      fail "Another program is using port 18090. Close that program, then run this launcher again. Private diagnostics: $LOG."
    else
      fail "Quantum Shield could not start and was stopped. Check the private diagnostics at $LOG, then ask for help with that file kept private."
    fi
  fi
  printf 'Quantum Shield PayPal started (PID %s).\n' "$SERVER_PID"
  cleanup() {
    if kill -0 "$SERVER_PID" 2>/dev/null; then
      kill -TERM "$SERVER_PID" 2>/dev/null || true
      wait "$SERVER_PID" 2>/dev/null || true
    fi
    rm -f "$PID_FILE"
  }
  trap cleanup INT TERM EXIT
fi

printf 'Dashboard: %s\n' "$URL"
printf 'Step 4 of 5: checking service health and local storage…\n'
HEALTH="$(curl --silent --show-error --fail --max-time 3 "$URL/health" 2>/dev/null || true)"
if [[ "$HEALTH" == *'"service":"quantum-shield-paypal"'* && "$HEALTH" == *'"status":"ok"'* ]]; then
  printf 'Self-check: service, storage, and active key are ready.\n'
else
  printf 'Self-check: the service answered with a warning. Open Settings → Diagnostics for details.\n'
fi
printf 'Step 5 of 5: checking PayPal Sandbox setup and opening your dashboard…\n'
if [[ "$HEALTH" == *'"paypal_sandbox_configured":true'* ]]; then
  printf 'PayPal Sandbox: OAuth connection verified.\n'
else
  printf 'PayPal Sandbox: not configured or not verified. You can continue offline; payments will not be sent.\n'
  printf 'To set it up, open PayPal Setup in the dashboard. Never paste credentials into this terminal.\n'
fi
if [[ "${QS_BROWSER:-}" == "firefox" ]]; then
  if command -v firefox >/dev/null 2>&1; then
    firefox --new-window "$URL/" >/dev/null 2>&1 &
  else
    printf 'Firefox was requested but is not installed. Open %s manually.\n' "$URL"
  fi
elif [[ -n "${QS_BROWSER:-}" ]]; then
  printf 'QS_BROWSER supports "firefox" only. Open %s manually.\n' "$URL"
elif command -v xdg-open >/dev/null 2>&1; then
  xdg-open "$URL/" >/dev/null 2>&1 || printf 'Could not open a browser automatically; open %s manually.\n' "$URL"
else
  printf 'No desktop browser opener was found. Open %s manually.\n' "$URL"
fi
if [[ -n ${SERVER_PID:-} ]]; then
  printf 'Press Ctrl+C to stop the service cleanly.\n'
  wait "$SERVER_PID"
else
  printf 'This instance was already running; use scripts/quantum-shield-stop.sh to stop it.\n'
fi
