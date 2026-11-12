# Release candidate status

Status: **RELEASE BLOCKED**. This is an engineering review state, not a claim of production readiness.

## Public release preparation update — 2026-11-12

- The PayPal integration is for Sandbox evaluation, not an approved live-money
  payment service. The recorded Sandbox checkout attempt returned
  `UNSUPPORTED_PAYEE_CURRENCY`. No completed PayPal payment or live-money
  transaction was demonstrated.
- Order creation/retrieval code and the operator-confirmed capture flow do not
  establish a successful end-to-end payment. Automated tests and static checks
  are not proof of successful PayPal operation.
- The managed test environment denied local listener binding. Its own live
  service/browser verification was not completed. Docker/Compose and
  Windows/macOS runtime behavior have not been verified by this checkout.
- Real PayPal webhook delivery still requires a publicly reachable HTTPS
  endpoint. No post-quantum protection is claimed for PayPal, TLS, or external
  infrastructure. The AI red-team planner is a separate test operator with no
  payment authority.
- Historical verification entries below describe their dated runs. Their test
  counts and environment-specific statements are not substitutes for the
  current checks recorded after this update.

### Checks run for this release preparation

- Passed: `cargo fmt --all -- --check`.
- Passed: `cargo test --locked --all-targets --all-features` — 284 passed,
  0 failed, 5 ignored (the ignored tests are real-Sandbox network tests).
- Passed: `cargo clippy --locked --all-targets --all-features -- -D warnings`.
- Passed: `cargo build --locked --all-targets --all-features` and release builds
  of `qsctl` and `qs-desktop`.
- Passed: `cargo audit --no-fetch` against the local advisory database (513
  locked dependencies and 1,386 cached advisories); the database was not
  refreshed.
- Passed: `scripts/test-security-modules.sh`,
  `scripts/test-payment-redteam.sh` (22 synthetic cases blocked, 1 not
  evaluated), `bash -n` across 28 shell scripts, and local Markdown-link checks.
- Passed: `docker compose --env-file /dev/null -f deploy/compose.yaml config
  --quiet` with a placeholder `QS_API_TOKEN`. This only validates Compose
  configuration; no container was built or started.
- Blocked: `scripts/test-sandbox-run.sh` exited 2 because the environment denied
  Bubblewrap's network-namespace setup (`NETLINK_ROUTE` returned
  `Operation not permitted`). This is not a passing sandbox result.
- Not run: local HTTP listener/browser checks, real PayPal Sandbox tests,
  external webhook delivery, Docker/Compose runtime, Windows/macOS runtime, and
  cross-platform CI. The managed environment's local listener restriction and
  the explicit Sandbox-only verification boundary remain in force.

## Historical verification log

The dated entries below are retained for traceability. They predate the current
release-preparation checks above and are superseded wherever counts, environment
status, or Sandbox-attempt descriptions differ. In particular, earlier notes
that say no Sandbox attempt occurred refer to those specific runs; the later
checkout attempt returned `UNSUPPORTED_PAYEE_CURRENCY` and did not complete a
payment.

## Verification performed in the earlier baseline

- `cargo test --all-targets --all-features` with the required Void Linux `LD_LIBRARY_PATH` setting: 244 passed, 9 failed, 5 ignored on the final run. The nine failures are PayPal mock-server tests that cannot bind loopback sockets in this environment (`PermissionDenied`). The tests remain enabled.
- Focused payment red-team tests after correcting the reordered-evidence rejection classification: 24 passed, 0 failed.
- `cargo clippy --all-targets --all-features -- -D warnings`: not run; the installed toolchain has no `cargo-clippy` component.
- Real PayPal Sandbox and Live calls, browser interaction, external webhook delivery, and deployment were not performed. No credentials or real-money transactions were used.

## Git-history key scan

The local scanner reported one critical private-key finding in locally reachable history. Inspection of the reachable commit identified short escaped PEM marker strings in `src/body_gate.rs` and `src/security.rs` regression tests, including a synthetic scanner fixture. No complete private-key payload was present in those changed lines, and no real or active key can be identified from that evidence. The finding appears to be a scanner false positive. This conclusion covers only locally reachable refs; remote, unreachable, and other copies were not inspected. No key rotation is indicated by this local evidence.

## Open release blockers

1. The project now carries MIT OR Apache-2.0 license files and Cargo metadata. The existing copyright notice names Rohan Reddimasu (Quantum Shield), but relicensing authority for every contribution has not been independently verified. Resolve rights for all contributions before distribution.
2. Third-party distribution scope still needs a complete audit. Bundled OWASP CRS files retain their separate Apache-2.0 license and attribution notices.
3. Nine PayPal mock-server tests need a run in an environment that permits loopback binding.
4. Clippy must be installed in the required Rust environment and run with warnings denied.
5. PayPal Sandbox credential, OAuth, order, explicit capture, webhook verification and reconciliation workflows need an authorized Sandbox run. Live operation has not been verified and must remain disabled until deliberate production configuration and independent operational review.
6. Dashboard browser interactions, restart/recovery behavior, external webhook delivery, deployment controls, backups, monitoring, and incident procedures need operational verification.

## Deterministic security boundary

Payment authorization, provider verification, cryptographic checks, and enforcement remain deterministic. AI-related red-team planning code is isolated from the payment authorization and enforcement paths; its presence is not an authorization signal.

## Additional local checks

- `cargo fmt --all -- --check`: exit 0.
- `cargo audit --no-fetch`: exit 0; 513 locked dependencies checked against 1,386 advisories in the locally cached database. Database freshness was not checked because network access was not authorized.
- Dashboard inline JavaScript syntax (`node --check`): exit 0 for one inline script. This is not browser-interaction verification.
- Shell syntax (`bash -n`): exit 0 across `scripts/*.sh`, `Run-Quantum-Shield.sh`, and `quantum-shield-first-run.sh`.
- Repository self-scan: exit 0; 933 files scanned, no truncation, 45 findings. Findings include `.env` and its backup in the working tree; two credential-like assignment detections in `src/payment_api.rs` (the static AEAD context label and an empty-credential parser test); broad matches in scanner regression code, backups, and bundled OWASP CRS test/rule content; and a workflow permissions warning. The cross-platform workflow now declares read-only `contents` permission. No matched credential value is included in this report. The working tree still contains local environment files and must not be distributed wholesale.

## Packaging and repository state

A filtered review ZIP is generated at the repository root. It contains 737 source, documentation, launcher, deployment, example, workflow, and bundled OWASP CRS entries. ZIP CRC validation passes; `.env`, environment backups, local backups, Git metadata, build output, reports/artifacts, runtime databases/logs, and key/certificate extensions are excluded. That archive predates the current license files and metadata, so it is stale and must not be distributed as the current project package.

The working tree was already substantially modified before this task. Those changes were preserved. Backups from the earlier engineering work remain under `backups/production-readiness-*`; backups for this license update were stored outside the repository.

## Operations-center follow-up (2026-11-12)

The earlier results above are the baseline audit. This follow-up supersedes baseline test, Clippy, and dashboard status where noted.

- The nine previously failing tests were individually rerun and passed: `capture_refund_and_retrieval_use_official_paths`, `create_order_uses_documented_endpoint_and_idempotency`, `invalid_amount_and_currency_fail_before_network`, `invalid_credentials_are_rejected_by_oauth`, `oauth_token_is_cached_between_requests`, `oversized_paypal_response_is_rejected`, `paypal_api_errors_include_issue_and_debug_id`, `rejected_token_is_invalidated_and_refreshed_once`, and `webhook_verification_requires_paypal_success`. Their common root cause was the test helper requiring a loopback TCP listener, denied by the container. It now uses the real TCP HTTP mock where binding succeeds and otherwise injects a deterministic executor after `reqwest` builds the request. The fallback records method, path, auth header, idempotency header, and serialized body, then supplies bounded HTTP response fixtures.
- Full suite result after the mock fallback and configuration-delete fix: 280 passed, 0 failed, 5 ignored; exit 0. The later payment-summary/refund-balance adjustment has a focused passing regression test; rerun the full suite after all changes before treating these aggregate counts as final.
- System Clippy is available outside the active rustup toolchain. `RUSTC=/usr/bin/rustc /usr/bin/cargo-clippy --all-targets --all-features -- -D warnings` passed after the production helper fix and scoped dispute-storage lint allowance. Rerun after the final payment-summary changes.
- `cargo build --all-targets --all-features`, formatting, cached `cargo audit --no-fetch`, payment red-team plan replay, and protection encryption/key-revocation E2E checks passed. Repository self-scan: 947 files, no truncation, 49 findings. The count includes known patterns in local backups, scanner tests, OWASP CRS fixtures, and working-tree `.env` files; the static credential-assignment detections in `src/payment_api.rs` refer to the AEAD context label and empty-value parser fixture, not PayPal credentials. Git history still reports the previously investigated escaped test markers.
- Dashboard improvements now include live captured/refunded totals in the payment ledger, state and severity filters, Sandbox configuration/database/key/webhook status from APIs, explicit capture/clear/refund confirmations, server-reported refundable balance limits, and response-confirmed refund totals. `docs/OPERATIONS.md` maps dashboard/API/CLI/script responsibilities. The Sandbox-only UI remains deliberate; Live mode is not exposed.
- Dashboard inline JavaScript syntax, unique IDs, selector-to-ID checks, and shell syntax pass. **No browser interaction was verified.** Chromium repeatedly exited in this container: first Crashpad `setsockopt` returned `Operation not permitted`, then disabling Crashpad reached a fatal browser sandbox-host `Operation not permitted`. Browser-driven form, dialog, navigation, and payment-flow verification remains required in a compatible environment.
- The prior `quantum-shield-release-review-20261112.zip` predates these dashboard/backend changes and is stale. It remains a review artifact only and was not regenerated or distributed.

## Final verification after payment balance and retry updates

- `cargo test --all-targets --all-features`: desktop target 27 passed; main target 254 passed, 0 failed, 5 ignored; total **281 passed, 0 failed, 5 ignored**, command exit 0. The 9 formerly failing PayPal tests each passed individually earlier in this run; the added idempotent 503 retry test also passed individually. The cumulative refund-summary regression passed.
- `cargo fmt --all -- --check`: exit 0.
- `RUSTC=/usr/bin/rustc /usr/bin/cargo-clippy --all-targets --all-features -- -D warnings`: exit 0. This uses the installed system Rust 1.99.0/Clippy with matching system compiler because active rustup stable lacks its Clippy component.
- `cargo build --all-targets --all-features`: exit 0.
- `cargo audit --no-fetch`: exit 0; cached database scan of 513 locked crates and 1,386 advisories. The database was not refreshed.
- Payment red-team regression: pass; deterministic run/replay, 22 blocked, 1 not evaluated. Protection E2E: pass, including key generation, file and payload encryption round trips, wrong-context rejection, bundle verification, and revoked-key refusal.
- Latest repository self-scan: 959 files, no truncation, 53 findings. Most findings are scanner false positives in retained backups, scanner tests, and OWASP CRS fixtures. It still flags `.env` and its backup in the local tree, two credential-like source patterns (static AAD context and an empty-value test), and the known generic escaped private-key marker in Git test history. No secret values were included in the report. Continue excluding local environment files and backups from any package.
- Dashboard static checks: one inline script passes `node --check`; 83 IDs, no duplicates; no missing statically referenced selectors; `bash -n` passed for 21 launcher/script files; `git diff --check` passes. Chromium interaction testing remains **unverified** due the container's denied Crashpad/sandbox operations described above.
- No real Sandbox/Live credential checks, external webhook delivery, real money movement, production deployment, or operational recovery testing was performed. The UI remains Sandbox-only. Rights clearance and the stale review ZIP remain release blockers.

## Operations-center continuation verification — 2026-11-12

- The nine previously failing PayPal tests each pass individually (exit 0) using the deterministic in-process mock transport. The original socket-based HTTP test path remains available where loopback binding is allowed; this environment denies loopback bind with `PermissionDenied`, so real socket transport was not verified here.
- Final `cargo test --all-targets --all-features`: exit 0; 282 passed, 0 failed, 5 ignored across the desktop and main test targets. The five ignored tests were not represented as verified.
- `cargo fmt --all -- --check`, system `cargo-clippy --all-targets --all-features -- -D warnings`, and `cargo build --all-targets --all-features` passed. `LD_LIBRARY_PATH=/usr/lib...` was set for Rust quality gates.
- `cargo audit --no-fetch` passed for 513 locked crates against the locally cached 1,386-advisory database. The advisory database was not refreshed.
- Payment red-team regression passed (22 blocked, 1 not evaluated); protection encryption, context binding, archive checks, and key-revocation E2E passed; security-module fixtures passed; shell syntax passed for the project scripts and launchers.
- The latest repository self-scan completed without truncation: 966 files and 57 findings. Findings include local `.env` files, retained source backups, scanner test patterns and OWASP CRS fixtures, and known static source matches. Values were not copied into this document. These local files must remain excluded from any release package. The recent-history scanner still reports one generic private-key-marker finding; previous review found escaped marker strings in regression code, not a complete key payload. Remote and unreachable Git objects were not inspected.
- Firefox 157 rendered the dashboard and exercised seven navigation items, payment/event search and filters, form validation, and capture/config-clear confirmation dialogs in a temporary harness with intercepted fixture responses: 15 interactions passed. A synthetic focus-visible assertion did not establish real keyboard modality; trusted Tab input was not available. The harness did not contact PayPal or a running service, and asynchronous browser workflows were not independently verified in this environment. The Firefox screenshot command produced the page but required timeout termination during browser shutdown.
- The project now declares `MIT OR Apache-2.0` in Cargo metadata and provides both license texts. The existing copyright holder notice was preserved; authority over all contributions is not independently confirmed.
- The health endpoint now probes a merchant-scoped SQLite read and reports database availability separately from the SQLite engine. A regression test covers available and degraded health classification.

**Readiness remains RELEASE BLOCKED.** Live PayPal, external Sandbox credentials/webhook callbacks, deployment controls, trusted keyboard behavior, asynchronous browser workflows, and final review of the local scanner findings remain unverified or outstanding.

### Additional integration-gate and package results

- `scripts/test-ai-agent-blocking.sh`: exit 1 during fixture startup; its loopback upstream could not bind in this environment (`PermissionDenied`), and the local `ss` preflight also reported restricted netlink access. The deterministic AI-policy unit tests in the Rust suite passed.
- `scripts/test-failsafe-validation-local.sh`: exit 1 during loopback upstream startup (`PermissionDenied`). `scripts/test-security-regression-local.sh`: exit 2 because its local upstream could not bind. These tests were not counted as passing.
- `scripts/test-wizard-validation.sh`: static launcher and menu validation passed. All launcher scripts passed `bash -n`; runtime startup/shutdown was not attempted because it requires a local listener and the existing `scripts/quantum-shield-start.sh` sources the repository `.env`.
- A local, undistributed archive was prepared outside the source tree. `unzip -t` passed; 814 entries were checked; required Cargo, license, app, config, docs, and launcher files were present; local environment files, databases, keys/certificates, backups, sensitive local reports, Git data, and build output were absent. The release-status document is intentionally included. Archive scan was complete (759 files, no private-key-payload rule match; two known credential-pattern matches in `src/payment_api.rs` are the fixed AAD context and empty-input validation fixture).

The ZIP is a review artifact only; it has not been published or distributed. It predates the dual-license update and must be regenerated before any distribution.

## Local application launch and end-to-end attempt — 2026-11-12

- Before launch, no `qsctl` process or listener on port 18090 was found. The official `Run-Quantum-Shield.sh` launcher was run with the required `/usr/lib` library path and Firefox selected. Its release build completed, but the service could not bind `127.0.0.1:18090`: the managed host denied the local socket operation (`PermissionDenied` / `Operation not permitted`). The launcher stopped and reaped the process and removed its PID file. It exited 1. No duplicate service was started.
- Final process check found no `qsctl` or Firefox process. The host also denied the `ss` netlink query; an HTTP health request returned no response (`000`). No application service is left running, and the dashboard URL was not opened in Firefox because startup failed.
- Consequently, **none of the seven dashboard sections or requested live-backend operations were verified in this run**: Overview, Payments/details, Protection diagnostics, Security Events, Evidence and audit verification, PayPal Setup, or Settings. Search, filters, refresh, confirmations, form submission, keyboard navigation, error handling against the application, and browser console inspection were also not verified against a running backend. The existing offline screenshots and prior fixture-harness interactions are not evidence of live-backend behavior.
- No encrypted Sandbox PayPal configuration or external Sandbox credentials were supplied. OAuth, order creation, approval, explicit capture, refund, and external webhook workflows therefore remain untested. No PayPal transaction was attempted.
- That statement applies only to this local application-launch attempt. In a
  separate Sandbox checkout attempt, PayPal returned
  `UNSUPPORTED_PAYEE_CURRENCY`; no completed payment was demonstrated.
- The runtime blocker is this managed host's loopback socket restriction. The application did not remain running, and local refresh/restart stability could not be exercised. A supported desktop environment that permits loopback binding is required to continue the end-to-end test. This session has no browser automation tool, and no unfamiliar-person usability test was performed.
- This attempt adds no claim of production or Sandbox readiness. The repository remains **RELEASE BLOCKED** until a compatible-host run verifies the real backend and required operational workflows.
