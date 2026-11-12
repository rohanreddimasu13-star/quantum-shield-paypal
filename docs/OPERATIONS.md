# Operations map

The PayPal dashboard is a merchant-scoped operations interface. It exposes only authenticated application operations; it does not provide shell, filesystem, or SQL access.

| Operation | Dashboard | Authenticated API | Local CLI / script |
|---|---|---|---|
| Health and runtime status | Overview, Settings | `GET /api/health` | `payment-serve` startup output |
| Merchant payment list and intent creation | Payments | `GET/POST /api/payments` | `payment-check` validates a local intent file |
| PayPal connection check and Sandbox setup | PayPal Setup | `GET /api/paypal/status`, `GET/POST/DELETE /api/paypal/config` | environment-based PayPal client commands |
| PayPal order retrieval | Payments | `GET /api/paypal/orders/{id}` | `paypal-create-order` creates an order without capturing |
| Explicit capture | Payments, confirmation required | `POST /api/payments/{id}/capture` | No unattended capture command |
| Refund and refund retrieval | Payments, confirmation required | `POST /api/paypal/captures/{id}/refund`, `GET /api/paypal/refunds/{id}` | No unattended refund command |
| Webhook receipt and verification | Status/details in Setup and Events | `POST /api/paypal/webhooks` | `paypal-verify-webhook` verifies a supplied event file |
| Events and audit verification | Security Events, Evidence & Audit | `GET /api/events`, `GET /api/audit/verify` | `repo-scan`, `git-history-scan` for repository checks |
| Evidence listing, record verification, chain verification | Evidence & Audit | `GET /api/evidence`, `POST /api/evidence/verify`, `GET /api/evidence/verify-chain` | evidence CLI subcommands, when available in `qsctl --help` |
| Deterministic security lab | Protection, Settings diagnostics | `POST /api/lab/run` | `payment-lab` |
| Key generation, wrapping, rotation/revocation, file encryption | Read-only key status in Protection | `GET /api/keys` exposes public key metadata only | `key-*`, `encrypt-*`, and `decrypt-*` commands |
| Reverse-proxy deployment, TLS, ACME, mTLS, sandbox execution | Not exposed in dashboard | Not exposed by payment API | `deploy-compose`, TLS and sandbox scripts |
| Start, stop, restart, rebuild, diagnostics | Not exposed in dashboard | Not exposed by payment API | `scripts/quantum-shield-ops.sh` |
| Local backup and restore | Not exposed in dashboard | Not exposed by payment API | `quantum-shield-ops.sh backup/restore`; restore validates archive paths and asks for confirmation |
| Local uninstall | Not exposed in dashboard | Not exposed by payment API | `quantum-shield-ops.sh uninstall`; explains deleted data and requires typing `DELETE` |

Use `qsctl --help` and each command's `--help` before executing CLI operations. Deployment, key lifecycle changes, and filesystem operations remain CLI-only because they require host-level privileges and explicit paths. The dashboard cannot accept or execute arbitrary commands.

The main `Run-Quantum-Shield.sh` launcher is Linux-only in this checkout. It prepares local storage, keeps the dashboard token private, starts the service on loopback, performs a health check, and opens a browser. `QS_BROWSER=firefox` selects Firefox. Docker/Compose files are provided but their runtime was not verified here.

The PayPal setup interface remains Sandbox-only. Live selection is intentionally unavailable until separate live-mode safeguards, deployment authorization, and production verification are implemented and approved.
