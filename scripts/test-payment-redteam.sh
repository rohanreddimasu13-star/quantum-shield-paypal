#!/usr/bin/env bash
# Offline payment red-team regression: deterministic run, plan replay, safety guard.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

BIN=./target/debug/qsctl
cargo build --locked --bin qsctl

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

"$BIN" payment-redteam --seed 42 --json > "$tmp/report.json"
python3 - "$tmp/report.json" <<'PY'
import json
import sys

report = json.load(open(sys.argv[1], encoding="utf-8"))
assert report["verdict"] == "PASS", report["verdict"]
assert report["bypasses"] == 0, report["bypasses"]
assert report["critical_bypasses"] == 0, report["critical_bypasses"]
assert report["wrong_control"] == 0, report["wrong_control"]
assert report["invariant_violations"] == 0, report["invariant_violations"]
assert report["invalid"] == 0, report["invalid"]
assert report["verified_rejected"] == report["evaluated"]
assert report["not_evaluated"] == 1, report["not_evaluated"]
assert report["defense_score"] < 100.0
print(
    "deterministic red team:",
    report["verified_rejected"],
    "blocked,",
    report["not_evaluated"],
    "not evaluated,",
    f"coverage {report['coverage_percent']:.2f}%",
)
PY

"$BIN" payment-redteam --seed 42 --plan-out "$tmp/plan.json" > /dev/null
"$BIN" payment-redteam --plan-in "$tmp/plan.json" --json > "$tmp/replay.json"
python3 - "$tmp/report.json" "$tmp/replay.json" <<'PY'
import json
import sys

original = json.load(open(sys.argv[1], encoding="utf-8"))
replay = json.load(open(sys.argv[2], encoding="utf-8"))
assert original["verdict"] == replay["verdict"] == "PASS"
assert [item["kind"] for item in original["results"]] == [
    item["kind"] for item in replay["results"]
]
print("saved plan replay reproduced the same attack order and verdict")
PY

if PAYPAL_ENVIRONMENT=live "$BIN" payment-redteam > "$tmp/live.out" 2>&1; then
  echo "expected PAYPAL_ENVIRONMENT=live to be refused" >&2
  exit 1
fi

echo "payment red-team regression passed"
