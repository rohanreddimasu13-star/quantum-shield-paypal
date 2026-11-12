#!/usr/bin/env bash
set -Eeuo pipefail

STATE="${XDG_STATE_HOME:-$HOME/.local/state}/quantum-shield"
found=0
stopped=0

for pid_file in "$STATE/server.pid" "$STATE/qsctl.pid"; do
  [[ -f "$pid_file" ]] || continue
  found=1
  IFS= read -r pid < "$pid_file" || true
  if [[ ! "${pid:-}" =~ ^[0-9]+$ ]]; then
    printf 'Cannot safely read the service PID file: %s\n' "$pid_file" >&2
    exit 1
  fi
  if ! kill -0 "$pid" 2>/dev/null; then
    rm -f -- "$pid_file"
    continue
  fi
  process_name="$(ps -p "$pid" -o comm= 2>/dev/null | tr -d '[:space:]' || true)"
  if [[ "$process_name" != "qsctl" ]]; then
    printf 'PID file %s points to a different program; nothing was stopped. Check it manually.\n' "$pid_file" >&2
    exit 1
  fi
  if [[ "$stopped" == "$pid" ]]; then
    rm -f -- "$pid_file"
    continue
  fi

  kill -TERM "$pid"
  for _ in $(seq 1 50); do
    kill -0 "$pid" 2>/dev/null || break
    sleep 0.2
  done
  if kill -0 "$pid" 2>/dev/null; then
    printf 'Quantum Shield did not stop within 10 seconds. It is still running; no force kill was sent.\n' >&2
    exit 1
  fi
  rm -f -- "$pid_file"
  stopped="$pid"
  printf 'Quantum Shield stopped cleanly.\n'
done

if [[ "$found" == 0 ]]; then
  printf 'No Quantum Shield PID file found.\n'
elif [[ "$stopped" == 0 ]]; then
  printf 'No running Quantum Shield service was found.\n'
fi
