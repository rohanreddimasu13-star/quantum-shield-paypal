# QUANTUM SHIELD PAYPAL — FINAL INTEGRATION REPORT

## Public release preparation update — 2026-11-12

This report preserves the dated integration work below; it is not evidence of a
completed payment. A later PayPal Sandbox checkout attempt returned
`UNSUPPORTED_PAYEE_CURRENCY`. No completed PayPal payment or live-money
transaction was demonstrated. The managed test environment denied local
listener binding, so live service/browser verification was not completed there.
Order creation/retrieval code, approval-before-capture behavior, automated Rust
tests, and static checks do not establish successful end-to-end PayPal
operation. Current checkout checks are recorded in
[`docs/RELEASE_CANDIDATE_STATUS.md`](docs/RELEASE_CANDIDATE_STATUS.md).

## Historical integration report — 2026-11-07

The status and test notes below describe the earlier integration report. They do
not replace the 2026-11-12 release-preparation status above. In particular, the
earlier statement that no Sandbox credentials or public HTTPS webhook endpoint
were available describes that earlier run; a later Sandbox checkout attempt
returned `UNSUPPORTED_PAYEE_CURRENCY` and did not complete a payment.

**Product:** Quantum Shield PayPal  
**Date:** 2026-11-07  
**Status at that time:** The REST integration and mocked tests were implemented.
No successful PayPal Sandbox transaction or live service/browser run was
verified.

---

## 1. Before and After

| Area | Before this change | After this change |
|---|---|---|
| PayPal client | Limited Sandbox helper with placeholder-oriented flows | Official PayPal REST client for OAuth, Orders v2, Payments v2, and webhook verification |
| OAuth | Token obtained per operation with no shared cache | Cached token shared by all clones, 60-second refresh margin, invalidation and one retry after `401` |
| Order creation | No full create/bind/retrieve flow in the HTTP API | `POST /api/paypal/orders`, deterministic idempotency key, durable binding, provider status stored |
| Capture | Capture flow relied on narrower fixtures and had no HTTP route for PayPal orders | Capture only after PayPal reports a matching `COMPLETED` order; recovery lookup after a lost response; duplicate capture acknowledgement |
| Refunds | No refund persistence or HTTP flow | Partial/full refunds with `PayPal-Request-Id`, authoritative refund lookup, cumulative over-refund prevention |
| Webhooks | Capture-only reconciliation; duplicate events could still fail after an authoritative capture | Signature verification through PayPal, capture and refund dispatch, event-ID/content deduplication, duplicate acknowledgement |
| Validation | Some amount/currency checks only | Strict amount, currency, provider ID, request ID, description, body-size, and unknown-field validation |
| Reliability | No explicit response bound or handler timeout | 1 MiB PayPal response cap, 10 s connect / 30 s request timeouts, bounded retries, 60 s handler timeout |
| Authentication | Bearer token optional for some processes | `QS_API_TOKEN` required to start `payment-serve`; mutating/account-sensitive routes require it |
| Abuse controls | No in-process limits | 120 requests/minute general and 20 PayPal mutations/minute per peer IP |
| Configuration | No explicit environment selector | `PAYPAL_ENVIRONMENT=sandbox` default; `live` requires an explicit opt-in; missing credentials fail clearly |
| Tests | No PayPal HTTP-mock suite and no real-Sandbox test hooks | 13 mocked-HTTP tests plus 5 ignored real-Sandbox tests and additional persistence/API tests |
| Reporting | Previous report claimed completed Sandbox integration without real verification | This report separates implemented, mocked, and unverified behavior |

---

## 2. Official PayPal REST Endpoints Connected

All paths and fields use PayPal's documented REST API. No invented endpoints or
request fields are used.

| Operation | Method and path |
|---|---|
| OAuth 2.0 client credentials | `POST /v1/oauth2/token` |
| Create order | `POST /v2/checkout/orders` |
| Retrieve order | `GET /v2/checkout/orders/{order_id}` |
| Capture order | `POST /v2/checkout/orders/{order_id}/capture` |
| Retrieve capture | `GET /v2/payments/captures/{capture_id}` |
| Refund capture | `POST /v2/payments/captures/{capture_id}/refund` |
| Retrieve refund | `GET /v2/payments/refunds/{refund_id}` |
| Verify webhook signature | `POST /v1/notifications/verify-webhook-signature` |

Base URLs:

- Sandbox (default): `https://api-m.sandbox.paypal.com`
- Live (explicit): `https://api-m.paypal.com`

TLS certificate verification is enabled. Redirects are disabled. Client ID and
secret are kept in memory, never logged, never returned by an API, and the secret
is wrapped in a zeroizing buffer.

---

## 3. Local HTTP Endpoints

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `GET` | `/health` | no | Liveness, version, algorithms, PayPal configuration state. Alias: `/api/health`. |
| `GET` | `/api/paypal/status` | no | Real PayPal OAuth connectivity check. |
| `POST` | `/api/paypal/orders` | bearer | Create and bind a PayPal order. |
| `GET` | `/api/paypal/orders/{order_id}` | bearer | Authoritative order lookup and local reconciliation. |
| `POST` | `/api/paypal/orders/{order_id}/capture` | bearer | Capture an approved order. |
| `POST` | `/api/paypal/captures/{capture_id}/refund` | bearer | Partial or full refund. |
| `GET` | `/api/paypal/refunds/{refund_id}` | bearer | Authoritative refund lookup. |
| `POST` | `/api/paypal/webhooks` | PayPal signature | Receive and verify webhooks. Legacy alias: `/paypal/webhook`. |

The existing `/api/payments/*`, dashboard, evidence, audit, key, and lab endpoints
remain available. The legacy endpoints are not presented as the new PayPal flow.

### Idempotency and validation

- Order creation requires an `idempotency_key` in the body. A matching
  `Idempotency-Key` or `PayPal-Request-Id` header is accepted; conflicting values
  are rejected.
- Order creation sends `PayPal-Request-Id: qs-order-{payment_id}`.
- Capture sends `PayPal-Request-Id: qs-capture-{order_id}`.
- Refunds accept an idempotency key; if absent, the deterministic fallback is
  `qs-refund-{capture_id}-{amount_minor}`.
- Amounts must be integer minor units in `1..=100_000_000`.
- Currency must be three uppercase ASCII letters.
- PayPal order, capture, and refund IDs must be 1–64 alphanumeric characters.
- JSON bodies are limited to 1 MiB, unknown fields are rejected, and PayPal
  responses are limited to 1 MiB.

---

## 4. Payment-Safety Behavior

- A browser approval redirect is never treated as proof of payment.
- A capture is recorded only when the capture response and an independent
  authoritative `GET /v2/checkout/orders/{id}` both report `COMPLETED`.
- The order's single purchase unit must match the local payment ID in
  `reference_id` and `custom_id`, and its amount and currency must match exactly.
- A refund is recorded only after an authoritative `GET /v2/payments/refunds/{id}`
  reports the requested amount and currency.
- Cumulative refunds cannot exceed the captured amount; local capture status moves
  to `PARTIALLY_REFUNDED` or `REFUNDED`.
- If a capture response is lost, the service recovers only from PayPal's
  authoritative order and still requires the expected `COMPLETED` state.
- If a webhook arrives after an authoritative capture already reconciled the
  payment, it is acknowledged as a duplicate instead of causing PayPal retries.
- Webhook event IDs are deduplicated. Reuse of an event ID with a different event
  type or payload hash is rejected.
- Missing PayPal configuration returns `503`; it never falls back to a mock payment.

---

## 5. Security Controls Wired into the Flow

- Request validation before any PayPal call.
- In-process rate limiting per peer IP.
- Bearer authentication with constant-time comparison.
- PayPal webhook signature verification before parsing state-changing resources.
- Event replay and duplicate protection in SQLite.
- Authoritative capture/refund amount and currency checks.
- Merchant authorization and evidence generation with ML-DSA-65.
- Hash-chained audit events and evidence export/verification.
- Key lifecycle commands remain available for creation, rotation, and revocation.
- Outbound PayPal retries are bounded and only applied to GET requests or requests
  with an idempotency key.

The local key-management and evidence components use `aws-lc-rs` 1.18.2:

- ML-KEM-768 (FIPS 203) for key establishment.
- ML-DSA-65 (FIPS 204) for authorization and evidence signatures.
- AES-256-GCM for authenticated encryption.
- HKDF-SHA-256 for key derivation.
- SHA-256 for hashing and hash chains.

PayPal's own HTTPS connection uses ordinary TLS; no PQC protection is claimed for
PayPal's infrastructure.

---

## 6. Persistence Changes

SQLite schema additions:

- `payment_captures`: authoritative capture ID, payment, order, status, amount,
  currency, cumulative refunded amount, timestamp.
- `payment_refunds`: refund ID, capture, payment, status, amount, currency,
  timestamp.
- `payments.paypal_order_status`: latest PayPal order status.

Migration behavior is additive (`CREATE TABLE IF NOT EXISTS`, `ALTER TABLE` only
when a column is missing). Existing payment rows and untracked project files were
preserved.

The idempotency check now compares caller-controlled business fields and the
requested lifetime, not server-derived `created_at`/`expires_at`; an honest retry
with new timestamps returns the original payment, while a changed amount, currency,
description, merchant, payment ID, or lifetime is rejected.

---

## 7. Tests and Validation

### Commands required for this task

```bash
cargo fmt --all -- --check
cargo check --locked
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
```

### Historical results reported for the 2026-11-07 run

| Command | Result |
|---|---|
| `cargo fmt --all -- --check` | Passed |
| `cargo check --locked` | Passed |
| `cargo test --locked` | **201 passed, 0 failed, 5 ignored** |
| `cargo clippy --locked --all-targets -- -D warnings` | Passed |

The five ignored tests are the real PayPal Sandbox network tests. They are ignored
by default so the normal suite never contacts PayPal or moves Sandbox money.

### Test layers

| Layer | Count | What it proves |
|---|---|---|
| Unit and persistence tests | Included in the 201 | Validation, state transitions, idempotency, capture/refund accounting, audit/evidence, unrelated existing security tests |
| Mocked PayPal HTTP tests | 13 | Official paths, OAuth cache, 401 refresh, idempotency headers, request bodies, bounded responses, API error mapping, webhook verification handling |
| Real PayPal Sandbox tests | 5 (ignored) | OAuth/status, order creation/retrieval, capture/refund with supplied Sandbox resources, forged webhook rejection, invalid-credential rejection |

Mock tests use bounded response fixtures and a deterministic request executor;
where the test environment permits it, they may use a local loopback HTTP server.
They are **not** evidence that PayPal accepted a request. They deliberately do
not write a real credential or claim a real transaction.

Real-Sandbox command:

```bash
PAYPAL_CLIENT_ID=... \
PAYPAL_CLIENT_SECRET=... \
PAYPAL_WEBHOOK_ID=... \
PAYPAL_ENVIRONMENT=sandbox \
cargo test --locked paypal_sandbox -- --ignored --nocapture
```

For the capture/refund test, also supply either:

```bash
PAYPAL_SANDBOX_APPROVED_ORDER_ID=<approved buyer order>
# or
PAYPAL_SANDBOX_CAPTURE_ID=<completed capture>
# optional, default 100 minor units
PAYPAL_SANDBOX_REFUND_AMOUNT_MINOR=100
```

Tests that require credentials or resources skip with a clear message when those
are absent; the invalid-credential rejection test needs only outbound network
access. All of them refuse to run against Live.

---

## 8. Historical Local Runtime Smoke-Test Report

The request results below were recorded in an earlier run. They were not
reproduced during public release preparation. In the current managed test
environment, local listener binding was denied, so live service and browser
verification was not completed.

The binary was started with a temporary database/key directory, a dummy
`QS_API_TOKEN`, and no PayPal credentials:

```bash
QS_API_TOKEN=... \
XDG_DATA_HOME="$TMPDIR/qs-test-data"\
QS_KEY_DIR="$TMPDIR/qs-test-keys"\
./target/debug/qsctl payment-serve --listen 127.0.0.1:18090
```

Observed:

| Request | Result |
|---|---|
| `GET /health` | `200` with service status, version, algorithms, and `paypal_sandbox_configured=false` |
| `GET /api/paypal/status` | `503 {"error":"PayPal is not configured"}` |
| `POST /api/paypal/orders` without bearer token | `401 bearer token required` |
| `POST /api/paypal/orders` with wrong bearer token | `401 bearer token required` |
| `POST /api/paypal/orders` with correct token but no PayPal config | `503 {"error":"PayPal is not configured"}` |
| `POST /api/paypal/webhooks` without PayPal headers | `400 missing PayPal transmission headers` |

The startup log explicitly stated that PayPal endpoints would refuse to call PayPal
rather than simulate payment. No payment was marked paid.

---

## 9. Real PayPal Sandbox Verification Status

The integration report dated 2026-11-07 recorded **no verified Sandbox
transaction**. A later Sandbox checkout attempt returned
`UNSUPPORTED_PAYEE_CURRENCY`; no completed PayPal payment was demonstrated.
This attempt does not establish successful order creation/retrieval,
buyer-approval-to-capture, capture, refund, or webhook behavior end to end.

For the original 2026-11-07 run, the following variables were absent:

- `PAYPAL_CLIENT_ID`
- `PAYPAL_CLIENT_SECRET`
- `PAYPAL_WEBHOOK_ID`
- `PAYPAL_ENVIRONMENT`

There was also no public HTTPS endpoint registered with PayPal for webhook
delivery, no approved Sandbox buyer order, and no completed Sandbox capture.

Consequently, that dated run did not verify:

- No real Sandbox OAuth token was obtained in validation.
- No real Sandbox order was created or retrieved.
- No real Sandbox capture or refund was executed.
- No real webhook was delivered or verified.

The integration code and ignored real-Sandbox test harness are present. They are
not evidence of a successful transaction; this report does not claim Sandbox or
Live payment success.

---

## 10. Blockers

| Blocker | Impact |
|---|---|
| No successful Sandbox end-to-end payment | The recorded checkout attempt returned `UNSUPPORTED_PAYEE_CURRENCY`; no completed payment was demonstrated |
| No verified Sandbox webhook delivery | Public HTTPS delivery and provider signature verification remain unverified |
| No public HTTPS webhook URL | PayPal cannot deliver a real event to the local service |
| No verified capture/refund result | Capture and refund are not demonstrated as a completed payment workflow |

These are external configuration blockers, not unresolved local compile or test
failures.

---

## 11. Production Requirements Before Real Money

1. Complete a Sandbox end-to-end run using the ignored tests and a real webhook
   delivery; record the results.
2. Put the service behind a TLS-terminating reverse proxy and expose only the
   intended paths.
3. Replace the single bearer token with per-operator authentication and
   authorization, and add edge rate limiting.
4. Move PQ keys and PayPal credentials to an HSM/KMS or equivalent secret store.
5. Replace single-node SQLite with a shared transactional store before running
   multiple instances.
6. Monitor webhook failures, retries, duplicate events, refund mismatches, and
   PayPal API errors.
7. Review data retention and PCI/GDPR obligations with the payment data owner.
8. Repeat the capture/refund and webhook checks against a PayPal Live app only
   after a separate production approval; never use Live credentials in tests.

These future requirements do not approve or enable live-money use. This project
is not an approved live payment service.

---

## 12. Startup and Examples

Exact local startup:

```bash
cd ~/Projects/quantum-shield-paypal
export QS_API_TOKEN="$(openssl rand -hex 32)"
export PAYPAL_CLIENT_ID="<sandbox client id>"
export PAYPAL_CLIENT_SECRET="<sandbox client secret>"
export PAYPAL_WEBHOOK_ID="<sandbox webhook id>"
export PAYPAL_ENVIRONMENT=sandbox
cargo run --locked --bin qsctl -- payment-serve --listen 127.0.0.1:18090
```

- Health: <http://127.0.0.1:18090/health>
- PayPal status: <http://127.0.0.1:18090/api/paypal/status>

Create an order:

```bash
curl -sS -X POST http://127.0.0.1:18090/api/paypal/orders \
  -H "Authorization: Bearer $QS_API_TOKEN" \
  -H "Content-Type: application/json" \
  -H "Idempotency-Key: idem_demo_001" \
  -d '{"id":"pay_demo_001","merchant_id":"merchant_demo","amount_minor":1299,"currency":"USD","description":"Sandbox demo","expires_in":600,"idempotency_key":"idem_demo_001"}'
```

Capture an approved order:

```bash
curl -sS -X POST \
  http://127.0.0.1:18090/api/paypal/orders/<PAYPAL_ORDER_ID>/capture \
  -H "Authorization: Bearer $QS_API_TOKEN"
```

Refund a capture:

```bash
curl -sS -X POST \
  http://127.0.0.1:18090/api/paypal/captures/<PAYPAL_CAPTURE_ID>/refund \
  -H "Authorization: Bearer $QS_API_TOKEN" \
  -H "Content-Type: application/json" \
  -H "Idempotency-Key: refund_demo_001" \
  -d '{"amount_minor":100,"currency":"USD","idempotency_key":"refund_demo_001"}'
```

Full setup, HTTPS webhook proxy examples, and additional commands are in
[`docs/PAYPAL_DEPLOYMENT.md`](docs/PAYPAL_DEPLOYMENT.md).

---

## 13. Files and Backups

Primary implementation files:

- `src/paypal.rs` — official client, validation, caching, retries, mocked HTTP
  tests, ignored real-Sandbox tests.
- `src/payment_api.rs` — HTTP routes, authentication, rate limiting, timeouts,
  capture/refund/webhook handling, API tests.
- `src/payments.rs` — SQLite captures/refunds, deduplication, refund accounting,
  idempotency fixes, persistence tests.
- `src/main.rs` — CLI wiring and webhook reconciliation.
- `src/payment_security.rs` — unchanged cryptography and evidence/audit functions,
  capture call sites updated.
- `.env.example` — Sandbox/token/environment template.
- `deploy/compose.yaml` — passes `PAYPAL_ENVIRONMENT`.
- `docs/PAYPAL_DEPLOYMENT.md` — operations guide and examples.
- `README.md` — integration summary.
- `FINAL_REPORT.md` — this report.

Pre-change backups are in
`backups/paypal-integration-20261107-101230/`. No files were deleted and no
credentials, `.env` files, or generated keys were committed. No commit, push, or
GitHub publication was performed.

---

## Summary

The source contains a PayPal REST client, local HTTP endpoints, validation,
idempotency, bounded retries and response sizes, capture/refund reconciliation,
webhook signature code, duplicate protection, rate limiting, audit/evidence
integration, and mocked and ignored real-Sandbox test layers. These are
implementation descriptions, not a successful payment result.

For this release-preparation checkout, `cargo test --locked --all-targets --all-features`
passed with 284 passed, 0 failed, and 5 ignored; formatting,
Clippy, and build checks passed. The ignored Sandbox tests were not run. The
managed environment denied local listener binding, so live service/browser
verification was not completed.

The Sandbox checkout attempt returned `UNSUPPORTED_PAYEE_CURRENCY`. No completed
PayPal payment or live-money transaction was demonstrated. Keep the project
Sandbox-only; do not make a production, compliance, certification, or guaranteed
attack-prevention claim.

---

## Offline adversarial payment red team (2026-11-10)

Added `qsctl payment-redteam`, a deterministic offline harness that executes
synthetic attacks against the existing payment defenses. An optional local Ollama
planner may choose attack kinds, but it never sees secrets and never decides a
result; deterministic Rust executes every attack and the judge derives the verdict.

- Catalog: 23 attacks across 20 defense controls.
- Deterministic run (seed 42): 22 verified rejections, 0 bypasses, 0 wrong-control
  rejections, 1 not evaluated (real PayPal webhook signature verification).
- Coverage: 95.65% (22/23); coverage-weighted defense score 94.57%; grade A.
- 24 new tests; the full payment test set is 56 passed.
- Fixed a latent defect: `SecurityStore::append_evidence` rewrote the chain hash
  after signing, so exported stored evidence failed independent verification. It
  now re-signs after finalising the chain position.

Real PayPal webhook signature verification is still **not evaluated offline** and
is not claimed as blocked. No real capture, refund or transfer was performed.

Updated files: `src/payment_redteam/*`, `src/main.rs`, `src/payment_security.rs`,
`src/payment_api.rs`, `README.md`, `SECURITY.md`, `docs/PAYPAL_DEPLOYMENT.md`,
`scripts/test-payment-redteam.sh`, `.github/workflows/ci.yml`.

Backups: `backups/ai-redteam-20261110T160217Z/`.
