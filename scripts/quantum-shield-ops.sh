#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
DATA_ROOT="${XDG_DATA_HOME:-$HOME/.local/share}/quantum-shield"
STATE_ROOT="${XDG_STATE_HOME:-$HOME/.local/state}/quantum-shield"
KEY_ROOT="${QS_KEY_DIR:-$STATE_ROOT/payment-pq-keys}"
PAYPAL_CONFIG="${QS_PAYPAL_CONFIG:-$KEY_ROOT/paypal-sandbox.enc}"
DB="$DATA_ROOT/payments/payments.sqlite3"
TOKEN_FILE="$STATE_ROOT/dashboard-token"
URL="http://127.0.0.1:18090"
TEMP_DIRS=()

fail() { printf 'Quantum Shield: %s\n' "$1" >&2; exit 1; }
cleanup_temp_dirs() {
  local temporary
  for temporary in "${TEMP_DIRS[@]}"; do
    [[ -n "$temporary" && -d "$temporary" ]] && rm -rf -- "$temporary"
  done
}
trap cleanup_temp_dirs EXIT
usage() {
  cat <<'HELP'
Quantum Shield local controls

Usage: scripts/quantum-shield-ops.sh COMMAND [PATH]

  start       Build if needed, start Sandbox service, open dashboard
  stop        Stop the managed service safely
  restart     Stop, then start the service
  update      Rebuild the binary from the current checkout (no download)
  diagnostics Check local service health without printing secrets
  backup      Save database, local session, and cryptographic key files
  restore     Restore one of this tool's backups after a confirmation
  uninstall   Remove local app data after a confirmation; keeps source files

Backups contain payment data, the dashboard token, and private key material.
Keep them private and store a second copy in a secure location.
HELP
}

service_is_running() {
  local pid_file pid name
  for pid_file in "$STATE_ROOT/server.pid" "$STATE_ROOT/qsctl.pid"; do
    [[ -f "$pid_file" ]] || continue
    IFS= read -r pid < "$pid_file" || true
    [[ "${pid:-}" =~ ^[0-9]+$ ]] || fail "A service PID file is malformed. Check it before continuing."
    kill -0 "$pid" 2>/dev/null || continue
    name="$(ps -p "$pid" -o comm= 2>/dev/null | tr -d '[:space:]' || true)"
    [[ "$name" == qsctl ]] && return 0
  done
  return 1
}

make_backup() {
  local destination="${1:-$HOME/quantum-shield-backup-$(date -u +%Y%m%dT%H%M%SZ).tar.gz}"
  local staging
  service_is_running && fail "Stop Quantum Shield before backing up so the database is consistent."
  [[ -f "$DB" && ! -L "$DB" ]] || fail "The local database was not found. Start the app once before making a backup."
  [[ -f "$TOKEN_FILE" && ! -L "$TOKEN_FILE" ]] || fail "The private dashboard session file is missing. Start the app once before making a backup."
  [[ -d "$KEY_ROOT" && ! -L "$KEY_ROOT" ]] || fail "The private key folder is missing or unsafe. Start the app once before making a backup."
  [[ "$PAYPAL_CONFIG" == "$KEY_ROOT/paypal-sandbox.enc" ]] || fail "This backup command cannot include a custom PayPal config path. Back up that encrypted file separately with the service stopped."
  [[ ! -e "$destination" ]] || fail "That backup file already exists. Choose a new name; existing files are never overwritten."
  if find "$KEY_ROOT" -type l -print -quit | grep -q .; then
    fail "The key folder contains a symbolic link. Resolve it with an administrator before backing up."
  fi
  mkdir -p -- "$(dirname -- "$destination")"
  staging="$(mktemp -d "${TMPDIR:-/tmp}/qs-backup.XXXXXXXX")"
  TEMP_DIRS+=("$staging")
  mkdir -m 700 -p "$staging/data/payments" "$staging/state"
  cp -p -- "$DB" "$staging/data/payments/payments.sqlite3"
  cp -p -- "$TOKEN_FILE" "$staging/state/dashboard-token"
  cp -a -- "$KEY_ROOT" "$staging/state/payment-pq-keys"
  printf 'format=quantum-shield-backup-v1\ncreated_utc=%s\n' "$(date -u +%FT%TZ)" > "$staging/manifest.txt"
  find "$staging" -type d -exec chmod 700 {} +
  find "$staging" -type f -exec chmod 600 {} +
  umask 077
  tar -czf "$destination" -C "$staging" manifest.txt data state
  chmod 600 "$destination"
  printf 'Private backup created: %s\n' "$destination"
  printf 'It contains payment records, the dashboard session token, and private keys.\n'
}

safe_extract_backup() {
  local archive="$1" destination="$2"
  python3 - "$archive" "$destination" <<'PY'
import pathlib, shutil, sys, tarfile

archive, destination = sys.argv[1:]
root = pathlib.Path(destination).resolve()
allowed = (
    "manifest.txt",
    "data/payments/payments.sqlite3",
    "state/dashboard-token",
)
max_total = 10 * 1024 * 1024 * 1024
total = 0
count = 0

try:
    with tarfile.open(archive, "r:gz") as bundle:
        for item in bundle.getmembers():
            name = pathlib.PurePosixPath(item.name)
            if name.is_absolute() or ".." in name.parts or not name.parts:
                raise ValueError("archive contains an unsafe path")
            text = name.as_posix().rstrip("/")
            is_key = text.startswith("state/payment-pq-keys/")
            is_dir = text in {"data", "data/payments", "state", "state/payment-pq-keys"}
            if text not in allowed and not is_key and not is_dir:
                raise ValueError("archive contains an unexpected file")
            if not (item.isdir() or item.isreg()):
                raise ValueError("archive contains a link or special file")
            count += 1
            total += item.size
            if count > 20000 or total > max_total:
                raise ValueError("archive exceeds safe entry or size limits")
            target = (root / pathlib.Path(*name.parts)).resolve()
            if root not in target.parents and target != root:
                raise ValueError("archive path escapes the temporary folder")
            if item.isdir():
                target.mkdir(mode=0o700, parents=True, exist_ok=True)
                continue
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            source = bundle.extractfile(item)
            if source is None:
                raise ValueError("archive member could not be read")
            with source, target.open("xb") as output:
                shutil.copyfileobj(source, output, length=1024 * 1024)
            target.chmod(0o600)
    required = [root / "manifest.txt", root / "data/payments/payments.sqlite3", root / "state/dashboard-token", root / "state/payment-pq-keys"]
    if not all(path.exists() for path in required):
        raise ValueError("backup is incomplete")
except Exception as error:
    print(f"Backup could not be safely restored: {error}", file=sys.stderr)
    raise SystemExit(1)
PY
}

command_name="${1:-}"
case "$command_name" in
  -h|--help|help) usage ;;
  start) exec "$ROOT/Run-Quantum-Shield.sh" ;;
  stop) exec "$ROOT/scripts/quantum-shield-stop.sh" ;;
  restart)
    "$ROOT/scripts/quantum-shield-stop.sh"
    for _ in $(seq 1 30); do
      if ! curl --silent --fail --max-time 1 "$URL/health" >/dev/null 2>&1; then break; fi
      sleep 0.2
    done
    if curl --silent --fail --max-time 1 "$URL/health" >/dev/null 2>&1; then
      fail "The service still answers after stop. No second instance was started."
    fi
    exec "$ROOT/Run-Quantum-Shield.sh"
    ;;
  update)
    service_is_running && fail "Stop Quantum Shield before rebuilding its running binary."
    export LD_LIBRARY_PATH="/usr/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
    cd "$ROOT"
    cargo build --locked --release --bin qsctl
    printf 'Updated the local binary from this checkout. No source was downloaded.\n'
    ;;
  diagnostics)
    health="$(curl --silent --show-error --fail --max-time 3 "$URL/health" 2>/dev/null)" || fail "Quantum Shield did not answer at $URL. Start it first."
    [[ "$health" == *'"service":"quantum-shield-paypal"'* ]] || fail "Port 18090 answered, but it is not Quantum Shield."
    if [[ "$health" == *'"status":"ok"'* ]]; then printf 'Service and local storage: ready.\n'; else printf 'Service answered in degraded state. Open Settings → Diagnostics.\n'; fi
    if [[ "$health" == *'"paypal_sandbox_configured":true'* ]]; then printf 'PayPal Sandbox: OAuth verified.\n'; else printf 'PayPal Sandbox: not connected. Offline inspection is available; payment actions need Sandbox setup.\n'; fi
    ;;
  backup) make_backup "${2:-}" ;;
  restore)
    archive="${2:-}"
    [[ -n "$archive" && -f "$archive" && ! -L "$archive" ]] || fail "Choose an existing backup file created by this tool."
    [[ "$PAYPAL_CONFIG" == "$KEY_ROOT/paypal-sandbox.enc" ]] || fail "This restore command cannot restore a custom PayPal config path. Restore that encrypted file separately."
    service_is_running && fail "Stop Quantum Shield before restoring a database."
    command -v python3 >/dev/null 2>&1 || fail "Python 3 is required to safely inspect the backup archive."
    staging="$(mktemp -d "${TMPDIR:-/tmp}/qs-restore.XXXXXXXX")"
    TEMP_DIRS+=("$staging")
    safe_extract_backup "$archive" "$staging/unpacked" || exit 1
    printf 'This replaces payment data, the dashboard token, and the cryptographic keys with the selected backup.\n'
    printf 'A backup of the current local data will be made first when possible.\n'
    read -r -p 'Type RESTORE to continue: ' answer
    [[ "$answer" == RESTORE ]] || { printf 'Restore cancelled; no files changed.\n'; exit 0; }
    if [[ -f "$DB" && -f "$TOKEN_FILE" && -d "$KEY_ROOT" ]]; then
      make_backup "$HOME/quantum-shield-pre-restore-$(date -u +%Y%m%dT%H%M%SZ).tar.gz"
    fi
    mkdir -m 700 -p "$(dirname -- "$DB")" "$(dirname -- "$TOKEN_FILE")" "$(dirname -- "$KEY_ROOT")"
    install -m 600 "$staging/unpacked/data/payments/payments.sqlite3" "$DB.restore"
    mv -f -- "$DB.restore" "$DB"
    install -m 600 "$staging/unpacked/state/dashboard-token" "$TOKEN_FILE.restore"
    mv -f -- "$TOKEN_FILE.restore" "$TOKEN_FILE"
    old_keys=""
    if [[ -d "$KEY_ROOT" ]]; then
      old_keys="$KEY_ROOT.pre-restore-$(date -u +%Y%m%dT%H%M%SZ)"
      mv -- "$KEY_ROOT" "$old_keys"
    fi
    if ! cp -a -- "$staging/unpacked/state/payment-pq-keys" "$KEY_ROOT"; then
      rm -rf -- "$KEY_ROOT"
      [[ -z "$old_keys" ]] || mv -- "$old_keys" "$KEY_ROOT"
      fail "Key restoration failed; the previous key folder was restored."
    fi
    chmod 700 "$KEY_ROOT"
    find "$KEY_ROOT" -type d -exec chmod 700 {} +
    find "$KEY_ROOT" -type f -exec chmod 600 {} +
    printf 'Restore completed. Start Quantum Shield and check Settings → Diagnostics.\n'
    ;;
  uninstall)
    printf 'This deletes local payment records, keys, encrypted PayPal setup, and dashboard authentication.\n'
    printf 'Project source files and separate backups will remain.\n'
    read -r -p 'Type DELETE to remove Quantum Shield local data: ' answer
    [[ "$answer" == DELETE ]] || { printf 'Uninstall cancelled; no files changed.\n'; exit 0; }
    "$ROOT/scripts/quantum-shield-stop.sh"
    [[ "$DATA_ROOT" == */quantum-shield && "$STATE_ROOT" == */quantum-shield ]] || fail "The storage paths are unusual; remove them manually after review."
    rm -rf -- "$DATA_ROOT" "$STATE_ROOT"
    printf 'Local data removed. Project source and separate backups were kept.\n'
    ;;
  *) usage >&2; exit 2 ;;
esac
