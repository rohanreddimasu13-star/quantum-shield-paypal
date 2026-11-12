# Quantum Shield PayPal — Advanced Administrator Guide

Beginners should start with the project [README](../README.md). This guide covers
advanced API, Sandbox webhook, and deployment operations.

> **Verification boundary:** This is a PayPal Sandbox integration, not an approved
> live-money payment service. The recorded Sandbox checkout attempt returned
> `UNSUPPORTED_PAYEE_CURRENCY`; no completed payment was demonstrated. The
> workflow below is implementation guidance, not evidence of a successful
> end-to-end transaction. Docker/Compose and Windows/macOS runtime behavior are
> not verified by this checkout.

Quantum Shield PayPal is a merchant-side payment-security gateway. PayPal remains
the processor. This service validates and persists payment intents, creates and
binds PayPal Orders v2 orders, captures only after PayPal confirms the capture,
verifies webhook signatures through PayPal's official API, reconciles refunds
against authoritative PayPal data, and produces signed, hash-chained evidence.

It does **not** use AI in its defense path. An optional offline red-team planner
may use a local loopback model to propose synthetic attack plans; deterministic
Rust code executes them and decides every verdict. That planner never sees PayPal
credentials or keys and never performs a capture, refund or transfer. It does
**not** claim to protect PayPal's internal systems, card processing, or the PayPal
HTTPS transport with post-quantum cryptography.

## Algorithms actually used

| Purpose | Algorithm | Implementation |
|---|---|---|
| Key establishment | ML-KEM-768 (FIPS 203) | `aws-lc-rs` 1.18.2 (AWS-LC) |
| Authorization/evidence signatures | ML-DSA-65 (FIPS 204) | `aws-lc-rs` 1.18.2 (AWS-LC) |
| Authenticated encryption | AES-256-GCM | `aws-lc-rs` |
| Key derivation | HKDF-SHA-256 | `aws-lc-rs` |
| Hashing / hash chain | SHA-256 | `aws-lc-rs` |

The older experimental HQC profile (`src/hqc_profile.rs`) is not compiled into this
binary and is not presented as a supported standardized profile.

## Required configuration

| Variable | Required | Meaning |
|---|---|---|
| `QS_API_TOKEN` | yes | Bearer token for protected API calls. The local launcher creates a private token file. Docker operators provide it through a private `.env` file. |
| `PAYPAL_CLIENT_ID` / `PAYPAL_CLIENT_SECRET` | no for local startup | The dashboard setup sends Sandbox credentials directly to the authenticated backend, which verifies OAuth and encrypts the saved configuration. Do not put these values in `.env`, shell history, or command arguments. |
| `PAYPAL_WEBHOOK_ID` | needed for webhooks | Enter it with the Sandbox credentials in PayPal Setup; the backend encrypts the saved configuration. |
| `PAYPAL_ENVIRONMENT` | no | `sandbox` is the default. The local launcher and provided Compose file set Sandbox explicitly. Live deployment is not validated by this project. |
| `QS_KEY_DIR` | no | PQ key directory; defaults to `$HOME/.local/state/quantum-shield/payment-pq-keys`. |

The service starts without PayPal credentials so health and setup remain available.
Order, capture, and refund operations return `503 Service Unavailable` until Sandbox
OAuth is verified. The service never falls back to simulated payments.

## PayPal Sandbox setup

1. Sign in to the [PayPal Developer Dashboard](https://developer.paypal.com/),
   open **Apps & Credentials**, switch to **Sandbox**, and create or select a
   Sandbox REST app. See PayPal's
   [Sandbox testing guide](https://developer.paypal.com/sandbox-testing/overview/).
2. Under **Testing Tools → Sandbox Accounts**, select or create a Sandbox
   Business seller and Personal buyer. See PayPal's
   [Sandbox account guide](https://developer.paypal.com/sandbox-testing/accounts).
3. Start Quantum Shield and open **PayPal Setup** in the dashboard.
4. Enter the Sandbox Client ID, Secret, and webhook ID there. The setup form is
   served by the authenticated local application; the client secret is cleared
   from the browser after the request. The backend verifies Sandbox OAuth and
   encrypts the configuration before saving it.
5. Create a Sandbox webhook pointing to your public HTTPS endpoint plus
   `/api/paypal/webhooks`.
6. Subscribe to at least:
   - `PAYMENT.CAPTURE.COMPLETED`
   - `PAYMENT.CAPTURE.REFUNDED`
7. Use Sandbox buyer accounts only. No real-money transactions are permitted.

### HTTPS webhook exposure

PayPal must reach the webhook over public HTTPS. This binary serves plain HTTP, so
put a TLS-terminating reverse proxy in front of it (for example Caddy, nginx, or a
cloud load balancer) and expose:

- `POST /api/paypal/webhooks` to PayPal.
- `GET /health` to your monitoring system.
- `/api/paypal/*` to trusted backend clients only.
- `/` (dashboard) behind your normal access control.

The proxy **must**:

- Forward the `PAYPAL-AUTH-ALGO`, `PAYPAL-CERT-URL`, `PAYPAL-TRANSMISSION-ID`,
  `PAYPAL-TRANSMISSION-SIG`, and `PAYPAL-TRANSMISSION-TIME` headers unchanged.
- Forward the raw request body unchanged (no JSON rewriting or re-serialization).
- Allow request bodies up to 1 MiB.
- Pass requests through without requiring your `QS_API_TOKEN`; PayPal does not send it.

Example Caddy site block:

```caddyfile
payments.example.com {
    reverse_proxy 127.0.0.1:18090
}
```

Example nginx location:

```nginx
location /api/paypal/webhooks {
    proxy_pass http://127.0.0.1:18090;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    client_max_body_size 1m;
}
```

Verify the webhook from the PayPal dashboard using a Sandbox test event. A valid
event is acknowledged with `200`; a bad signature is rejected and logged.

## Run locally

```bash
cd ~/Projects/quantum-shield-paypal
./Run-Quantum-Shield.sh
```

The launcher creates the local session token, initializes storage, starts the
service on loopback, runs a health check, and opens the browser. For a direct
CLI run after the first launch, read the existing token from its private file
without putting it in command arguments or printing it:

```bash
export QS_API_TOKEN="$(<"${XDG_STATE_HOME:-$HOME/.local/state}/quantum-shield/dashboard-token")"
export PAYPAL_ENVIRONMENT=sandbox
cargo run --locked --bin qsctl -- payment-serve --listen 127.0.0.1:18090
```

Release build:

```bash
cargo build --release --locked --bin qsctl
./target/release/qsctl payment-serve --listen 127.0.0.1:18090
```

### Sandbox workflow procedure (not verified end to end)

The following is a test procedure, not a report of a successful payment. The
recorded Sandbox checkout attempt returned `UNSUPPORTED_PAYEE_CURRENCY`. No
completed PayPal payment was demonstrated. Order creation/retrieval and the
operator-confirmed capture path do not establish a successful end-to-end result.

Configure the Sandbox app through **PayPal Setup** first. Do not export the
Client Secret into a terminal. The following advanced API example reads the
local API token from its mode-600 file without printing it.

```bash
cd ~/Projects/quantum-shield-paypal
export PAYPAL_ENVIRONMENT=sandbox
export QS_API_TOKEN="$(<"${XDG_STATE_HOME:-$HOME/.local/state}/quantum-shield/dashboard-token")"
qs_curl() {
  curl --config <(printf 'header = "Authorization: Bearer %s"\n' "$QS_API_TOKEN") "$@"
}
```

`qs_curl` supplies the token through a temporary file descriptor, not a curl
command-line argument. Keep the shell open for the API examples below; do not
enable shell tracing while the token is in memory.

Create a disposable local payment intent for exactly `$1.99` (`199` minor units)
and move it to `Pending`:

```bash
NOW=$(date +%s)
PAYMENT_ID="pay_sandbox_$(date +%s)"
cat > /tmp/qs-paypal-199.json <<EOF
{
  "id": "$PAYMENT_ID",
  "merchant_id": "merchant_sandbox",
  "amount_minor": 199,
  "currency": "USD",
  "description": "Quantum Shield Sandbox 1.99 USD order",
  "created_at": $NOW,
  "expires_at": $((NOW + 600))
}
EOF

cargo run --locked --bin qsctl -- payment-check /tmp/qs-paypal-199.json \
  --idempotency-key "idem-$PAYMENT_ID"
```

Create the PayPal Sandbox order through the existing Sandbox-aware client. The
command uses the validated amount/currency and the deterministic
`PayPal-Request-Id: qs-order-{payment_id}` idempotency key:

```bash
cargo run --locked --bin qsctl -- paypal-create-order "$PAYMENT_ID"
```

The output includes the PayPal order ID, PayPal status, and the buyer approval URL.
No capture is performed by this command.

#### Buyer approval with a Sandbox Personal account

1. Open the PayPal Developer Dashboard: <https://developer.paypal.com/dashboard/accounts>.
2. Under **Sandbox > Accounts**, select a **Personal** account and use **View/Edit**
   to obtain its Sandbox email and password. Do not use a Live account.
3. Open the printed approval URL in a private/incognito browser window and sign in
   with that Sandbox Personal account.
4. Confirm the merchant and the `$1.99 USD` amount, then click **Continue** / **Pay**
   to approve the order. The final browser redirect is informational only; it is
   never treated as proof of payment.
5. Save the PayPal order ID printed by `paypal-create-order`; it is needed for the
   capture/refund test. Do not capture before approval is complete.

Only after reviewing the Sandbox order and explicitly choosing to run this
operator-initiated test, pass its approved order ID. The integration test captures
that order and refunds the configured test amount. It verifies
the capture with `GET /v2/payments/captures/{id}`, requests a refund, and verifies it
with `GET /v2/payments/refunds/{id}`:

```bash
export PAYPAL_SANDBOX_APPROVED_ORDER_ID="<PayPal order ID printed above>"
export PAYPAL_SANDBOX_REFUND_AMOUNT_MINOR=100   # optional; default is 100 = $1.00
cargo test --locked paypal_sandbox_capture_and_refund -- --ignored --nocapture
```

Use a freshly approved order for each run. An order can be captured only once, and
PayPal rejects double refunds beyond the captured amount. The test refuses to run
when `PAYPAL_ENVIRONMENT=live` and skips with a clear message if the order ID or
credentials are absent. To refund an existing completed capture instead, set
`PAYPAL_SANDBOX_CAPTURE_ID` rather than `PAYPAL_SANDBOX_APPROVED_ORDER_ID`.

URLs:

- Dashboard: <http://127.0.0.1:18090/>
- Health: <http://127.0.0.1:18090/health>
- PayPal connectivity: <http://127.0.0.1:18090/api/paypal/status>

`/api/paypal/status` obtains a real OAuth token from PayPal. It returns the
environment, API base, whether a token was acquired, and whether a webhook ID is
configured. It never returns the token or secret.

## HTTP endpoints

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `GET` | `/health` (alias `/api/health`) | no | Liveness and configuration summary. |
| `GET` | `/api/paypal/status` | no | Real PayPal OAuth connectivity check. |
| `POST` | `/api/paypal/orders` | bearer | Create and bind a PayPal order. |
| `GET` | `/api/paypal/orders/{order_id}` | bearer | Authoritative order lookup and reconciliation. |
| `POST` | `/api/paypal/orders/{order_id}/capture` | bearer | Capture an approved order. |
| `POST` | `/api/paypal/captures/{capture_id}/refund` | bearer | Partial or full refund. |
| `GET` | `/api/paypal/refunds/{refund_id}` | bearer | Authoritative refund lookup. |
| `POST` | `/api/paypal/webhooks` (legacy `/paypal/webhook`) | PayPal signature | Receive verified webhooks. |

All amounts are integer minor units (`1299` = `12.99`), currency is a three-letter
uppercase ISO code, and provider IDs are alphanumeric. Unknown JSON fields are
rejected. Mutating routes accept `Idempotency-Key` (or `PayPal-Request-Id`); if a
body `idempotency_key` is also present, the two must match.

### Create an order

```bash
qs_curl -sS -X POST http://127.0.0.1:18090/api/paypal/orders \
  -H "Content-Type: application/json" \
  -H "Idempotency-Key: idem_demo_001" \
  -d '{
    "id": "pay_demo_001",
    "merchant_id": "merchant_demo",
    "amount_minor": 1299,
    "currency": "USD",
    "description": "Sandbox demo order",
    "expires_in": 600,
    "idempotency_key": "idem_demo_001"
  }'
```

The response contains `paypal_order_id`, `paypal_order_status`, `state`, and an
`approval_url`. Open the approval URL with a Sandbox buyer account. Approval alone
does **not** mark the payment paid.

### Retrieve an order

```bash
qs_curl -sS http://127.0.0.1:18090/api/paypal/orders/<PAYPAL_ORDER_ID>
```

If PayPal reports `COMPLETED`, the service verifies the capture ID, amount,
currency, and payment reference and records the capture atomically.

### Capture an approved order

```bash
qs_curl -sS -X POST \
  http://127.0.0.1:18090/api/paypal/orders/<PAYPAL_ORDER_ID>/capture
```

A capture is recorded only when PayPal returns a `COMPLETED` order whose capture
matches the locally stored amount, currency, and reference. A browser redirect is
never accepted as proof of payment.

### Refund a capture

Partial refund:

```bash
qs_curl -sS -X POST \
  http://127.0.0.1:18090/api/paypal/captures/<PAYPAL_CAPTURE_ID>/refund \
  -H "Content-Type: application/json" \
  -H "Idempotency-Key: refund_demo_001" \
  -d '{"amount_minor": 100, "currency": "USD", "idempotency_key": "refund_demo_001"}'
```

Full refund (empty body):

```bash
qs_curl -sS -X POST \
  http://127.0.0.1:18090/api/paypal/captures/<PAYPAL_CAPTURE_ID>/refund \
  -H "Idempotency-Key: refund_demo_full_001"
```

Cumulative refunds cannot exceed the captured amount. Refunds are recorded only
after an authoritative `GET /v2/payments/refunds/{id}` response matches the
requested amount and currency. If you intentionally issue two separate refunds of
the same amount, supply a distinct `Idempotency-Key` for each; otherwise the
deterministic fallback key treats the second request as a retry of the first.

### Retrieve a refund

```bash
qs_curl -sS http://127.0.0.1:18090/api/paypal/refunds/<PAYPAL_REFUND_ID>
```

### Health and status

```bash
curl -sS http://127.0.0.1:18090/health
curl -sS http://127.0.0.1:18090/api/paypal/status
```

## Tests

The suite distinguishes three levels:

| Level | Command | Network |
|---|---|---|
| Unit and persistence tests | `cargo test --locked` | none |
| Mocked PayPal HTTP tests | `cargo test --locked paypal::tests` | loopback only |
| Real PayPal Sandbox tests | `cargo test --locked paypal_sandbox -- --ignored --nocapture` | PayPal Sandbox |

The normal suite reports the real-Sandbox tests as ignored. The mocked tests verify
official request paths, OAuth caching, 401 refresh, idempotency headers, bounded
response sizes, error mapping, and webhook verification handling. They do not prove
that PayPal accepted a request.

Real-Sandbox tests read credentials from the environment and skip with a clear
message when they are absent; the invalid-credential rejection test needs only
outbound network access. They refuse to run with `PAYPAL_ENVIRONMENT=live`.
Additional variables for the capture/refund test:

- `PAYPAL_SANDBOX_APPROVED_ORDER_ID` — an approved Sandbox order (buyer approved),
  which the test captures and refunds.
- `PAYPAL_SANDBOX_CAPTURE_ID` — alternatively, an existing completed Sandbox
  capture to refund.
- `PAYPAL_SANDBOX_REFUND_AMOUNT_MINOR` — refund amount in minor units (default `100`).

Use a fresh approved order or a capture with enough remaining balance; PayPal
rejects double refunds.

## Other CLI commands

```bash
qsctl payment-lab                         # deterministic security scenarios
qsctl payment-redteam                     # offline adversarial red team (deterministic plan)
qsctl payment-redteam --provider ollama --model qwen2.5-coder:3b
qsctl payment-redteam --plan-out plan.json
qsctl payment-redteam --plan-in plan.json --json   # replay without AI or network
qsctl payment-evidence                    # export and chain-verify evidence JSON
qsctl payment-verify-evidence evidence.json
qsctl payment-key-create key-2026-11      # create a new PQ key set for rotation
qsctl payment-key-revoke key-2026-10      # revoke a key ID
qsctl payment-check intent.json --idempotency-key idem_001
qsctl paypal-create-order pay_demo_001
qsctl paypal-verify-webhook event.json --auth-algo ... --cert-url ... \
  --transmission-id ... --transmission-sig ... --transmission-time ...
```

The red team runs only against synthetic local fixtures. It has no PayPal client
and performs no capture, refund, transfer or provider request. An optional local
model may only choose attack kinds from a fixed catalog; it never sees secrets and
never decides a verdict. Real PayPal webhook signature verification cannot be
evaluated offline and is reported as `not_evaluated`, not blocked. The command
exits nonzero on a bypass, a wrong-control rejection, an invariant violation, or a
harness failure; `--allow-bypass` is for exploratory runs only.

## Linux native deployment

```bash
cargo build --release --locked --bin qsctl
install -m 0755 target/release/qsctl /usr/local/bin/qsctl
useradd --system --home /var/lib/quantum-shield qshield
install -d -m 0700 -o qshield -g qshield /var/lib/quantum-shield
```

Environment:

```text
HOME=/var/lib/quantum-shield
QS_KEY_DIR=/var/lib/quantum-shield/.local/state/quantum-shield/payment-pq-keys
QS_API_TOKEN=<32-byte random hex>
PAYPAL_ENVIRONMENT=sandbox
```

Provision the token through a root-owned mode-600 systemd credential or
environment file. Start the service in Sandbox, then configure PayPal through
the authenticated dashboard so credentials are encrypted in the application
state. Do not store PayPal credentials in the unit file.

Run under systemd with a non-root user, `NoNewPrivileges=yes`,
`ProtectSystem=strict`, `PrivateTmp=yes`, and a writable
`/var/lib/quantum-shield` only.

## Container deployment (Docker/Podman)

```bash
if [ -e .env ]; then echo 'Keep the existing .env; do not overwrite it.'; exit 1; fi
umask 077
{
  printf 'QS_API_TOKEN='
  openssl rand -hex 32
  printf '\nQS_MERCHANT_ID=merchant_local\nPAYPAL_ENVIRONMENT=sandbox\n'
} > .env
chmod 600 .env
docker compose --env-file .env -f deploy/compose.yaml up --build -d
docker compose --env-file .env -f deploy/compose.yaml ps
curl -fsS http://127.0.0.1:18090/health
```

The `.env` contains only the dashboard session token and merchant identifier.
Configure Sandbox credentials in PayPal Setup after the dashboard starts. The
Compose service sets `PAYPAL_ENVIRONMENT=sandbox` and does not accept Live mode.

Podman:

```bash
podman build -t quantum-shield-paypal:local .
podman run --rm --env-file .env -p 127.0.0.1:18090:18090 \
  -e PAYPAL_ENVIRONMENT=sandbox \
  -v qs-data:/data quantum-shield-paypal:local
```

The Dockerfile configures UID 10001, dropped capabilities, a read-only root
filesystem, a small `/tmp`, and a health check. SQLite data and key files are
configured to live in the `/data` volume. Back up that volume and restore it
while the service is stopped. Never copy `.env` or key material into the image.

The container files are provided for evaluation, but this runtime was not
started in the current verification environment. Do not treat Docker/Podman
deployment as validated until the health check, persistent-volume recovery,
reverse proxy, HTTPS, and Sandbox webhook have been exercised on the target host.

## Verification status and production requirements

- The public release source does not include PayPal credentials. A recorded
  Sandbox checkout attempt returned `UNSUPPORTED_PAYEE_CURRENCY`; no completed
  PayPal payment was demonstrated. This does not verify order creation/retrieval,
  explicit approval-before-capture, capture, refund, or webhook handling as a
  successful end-to-end payment.
- The five real-Sandbox tests are ignored by default. They remain unverified as
  evidence of a successful Sandbox transaction and require an operator to
  intentionally supply Sandbox credentials and disposable approved resources.
- Mocked HTTP tests and unit/persistence tests do pass locally.
- The HTTP service is plain HTTP and requires an externally reachable HTTPS
  endpoint in front of it for PayPal webhook delivery. Keep the integration in
  Sandbox; this project does not approve or validate live-money use.
- API authentication is a single bearer token. Production needs per-operator
  authentication, authorization, secret rotation, and edge rate limiting in
  addition to the in-process limits (120 requests/minute general, 20 PayPal
  mutations/minute per peer IP).
- Keys are raw PQ key files with mode 0600 inside a 0700 directory. They are not
  encrypted at rest and are not held in an HSM/KMS; move them to a hardware-backed
  secret store before handling real traffic. Key lifecycle is supported through
  `qsctl payment-key-create <id>` and `qsctl payment-key-revoke <id>`; restart with
  `QS_KEY_ID=<id>` to rotate. Automated rotation scheduling is not included.
- Webhook verification depends on PayPal's certificate URL and signature service;
  allow outbound HTTPS from the service and keep clocks synchronized.
- SQLite is suitable for a single node. Production multi-instance deployments need
  a shared transactional store and idempotency/deduplication across instances.
- Evidence signing uses ML-DSA-65 with a locally held key. Independent verification
  proves integrity and authenticity relative to that public key; trust distribution
  of the public key is an operator responsibility.
- No claim is made that PayPal's own infrastructure or HTTPS connection is
  PQC-protected.
