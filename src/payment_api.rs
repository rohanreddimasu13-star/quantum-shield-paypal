//! Payment API, PayPal webhook endpoint and embedded security dashboard.
//!
//! The service never trusts a browser as proof of payment. Capture state is
//! changed only after PayPal's verification API and an authoritative order
//! lookup agree with the locally stored payment.

use anyhow::{bail, Context, Result};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{
    body::Incoming,
    header::{AUTHORIZATION, CONTENT_TYPE},
    service::service_fn,
    Method, Request, Response, StatusCode,
};
use hyper_util::rt::TokioIo;
use serde::Deserialize;
use serde::Serialize;
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    convert::Infallible,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex as StdMutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::net::TcpListener;

use crate::{
    parse_capture_webhook,
    payment_security::{
        build_evidence, create_authorization, run_security_lab, verify_authorization,
        verify_evidence, AuthorizationExpectation, CryptoKeys, EvidenceInput, SecurityStore,
        AEAD_ALG, KDF_ALG, ML_DSA_ALG, ML_KEM_ALG,
    },
    payments::{PaymentIntent, PaymentState, SqlitePaymentBook},
    paypal::{
        validate_amount, validate_capture_id, validate_currency, validate_order_id,
        validate_refund_id, validate_request_id, PayPalSandbox, WebhookHeaders,
    },
};

const MAX_BODY: usize = 1024 * 1024;
const DASHBOARD: &str = include_str!("../web/index.html");
const GENERAL_RATE_LIMIT: u32 = 120;
const MUTATION_RATE_LIMIT: u32 = 20;
const RATE_WINDOW: Duration = Duration::from_secs(60);
const MAX_RATE_BUCKETS: usize = 4096;
const HANDLER_TIMEOUT: Duration = Duration::from_secs(60);

struct RateWindow {
    started: Instant,
    count: u32,
}

/// Small in-process fixed-window limiter. It is a defence-in-depth control for
/// this single-node service; production deployments should also rate limit at
/// the TLS reverse proxy or edge.
pub struct RateLimiter {
    buckets: StdMutex<HashMap<String, RateWindow>>,
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self {
            buckets: StdMutex::new(HashMap::new()),
        }
    }
}

impl RateLimiter {
    fn check(&self, key: &str, max: u32, window: Duration) -> Result<(), u64> {
        let mut buckets = match self.buckets.lock() {
            Ok(guard) => guard,
            Err(_) => return Err(1),
        };
        let now = Instant::now();
        if buckets.len() > MAX_RATE_BUCKETS {
            buckets.retain(|_, entry| now.duration_since(entry.started) < window);
        }
        let entry = buckets.entry(key.to_owned()).or_insert(RateWindow {
            started: now,
            count: 0,
        });
        if now.duration_since(entry.started) >= window {
            entry.started = now;
            entry.count = 0;
        }
        if entry.count >= max {
            let retry = window
                .as_secs()
                .saturating_sub(now.duration_since(entry.started).as_secs())
                .max(1);
            return Err(retry);
        }
        entry.count += 1;
        Ok(())
    }
}

pub struct ApiState {
    pub book: SqlitePaymentBook,
    pub security: SecurityStore,
    pub keys: CryptoKeys,
    pub paypal: Option<PayPalSandbox>,
    pub paypal_error: Option<String>,
    pub webhook_id: Option<String>,
    pub rate_limiter: RateLimiter,
    pub started_at: u64,
    pub api_token: Option<String>,
    /// Server-configured tenant; never selected by an untrusted request.
    pub merchant_id: String,
    paypal_config_path: std::path::PathBuf,
    paypal_runtime: tokio::sync::RwLock<(Option<PayPalSandbox>, Option<String>, Option<String>)>,
}

#[derive(Deserialize)]
struct PaypalSetup {
    client_id: String,
    client_secret: String,
    #[serde(default)]
    webhook_id: String,
}
#[derive(Serialize, Deserialize)]
struct PaypalStored {
    client_id: String,
    client_secret: String,
    #[serde(default)]
    webhook_id: String,
}
const PAYPAL_CONFIG_AAD: &[u8] = b"quantum-shield-paypal-sandbox-config-v1";

fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

type ApiBody = Full<Bytes>;

fn json_response(status: StatusCode, value: &Value) -> Response<ApiBody> {
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "application/json; charset=utf-8")
        .header("Cache-Control", "no-store")
        .header("X-Content-Type-Options", "nosniff")
        .header("X-Frame-Options", "DENY")
        .header("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'")
        .body(Full::new(Bytes::from(
            serde_json::to_vec(value).unwrap_or_else(|_| b"{\"error\":\"serialization\"}".to_vec()),
        )))
        .expect("static response headers")
}

fn text_response(status: StatusCode, text: &str) -> Response<ApiBody> {
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "text/plain; charset=utf-8")
        .header("Cache-Control", "no-store")
        .body(Full::new(Bytes::from(text.to_owned())))
        .expect("static response headers")
}

fn html_response(local_token: Option<&str>) -> Response<ApiBody> {
    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "text/html; charset=utf-8")
        .header("Cache-Control", "no-store")
        .header("X-Content-Type-Options", "nosniff")
        .header("X-Frame-Options", "DENY")
        .header(
            "Content-Security-Policy",
            "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'",
        );

    if let Some(token) = local_token.filter(|t| {
        !t.is_empty()
            && t.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    }) {
        builder = builder.header(
            "Set-Cookie",
            format!("qs_local_session={token}; Path=/; Max-Age=3600; HttpOnly; SameSite=Strict"),
        );
    }

    builder
        .body(Full::new(Bytes::from(DASHBOARD)))
        .expect("static response headers")
}

#[allow(clippy::result_large_err)]
async fn read_body_limited(request: Request<Incoming>) -> Result<Vec<u8>, Response<ApiBody>> {
    let mut body = request.into_body();
    let mut out = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| text_response(StatusCode::BAD_REQUEST, "invalid body"))?;
        if let Ok(data) = frame.into_data() {
            if out.len() + data.len() > MAX_BODY {
                return Err(text_response(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "request body exceeds 1 MiB",
                ));
            }
            out.extend_from_slice(&data);
        }
    }
    Ok(out)
}

fn bearer_token_matches(expected: Option<&str>, supplied: Option<&str>) -> bool {
    let Some(expected) = expected else {
        return false;
    };
    supplied
        .map(|value| constant_time_eq(value.as_bytes(), expected.as_bytes()))
        .unwrap_or(false)
}

fn authorized(state: &ApiState, request: &Request<Incoming>, peer_ip: IpAddr) -> bool {
    let supplied = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));

    if bearer_token_matches(state.api_token.as_deref(), supplied) {
        return true;
    }

    // Browser-cookie authentication is strictly limited to loopback clients.
    if !peer_ip.is_loopback() {
        return false;
    }

    // State-changing cookie-authenticated requests must originate from
    // this exact local service origin.
    let method = request.method();
    if method != Method::GET && method != Method::HEAD && method != Method::OPTIONS {
        let host = request.headers().get("host").and_then(|v| v.to_str().ok());
        let origin = request
            .headers()
            .get("origin")
            .and_then(|v| v.to_str().ok());
        let Some(host) = host else { return false };
        let Some(origin) = origin else { return false };
        if origin != format!("http://{host}") && origin != format!("https://{host}") {
            return false;
        }
    }

    let cookie = request
        .headers()
        .get("cookie")
        .and_then(|v| v.to_str().ok());
    let supplied = cookie.and_then(|value| {
        value
            .split(';')
            .map(str::trim)
            .find_map(|part| part.strip_prefix("qs_local_session="))
    });

    bearer_token_matches(state.api_token.as_deref(), supplied)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

fn extract_header<'a>(request: &'a Request<Incoming>, name: &str) -> Result<&'a str> {
    request
        .headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .filter(|v| !v.is_empty())
        .ok_or_else(|| anyhow::anyhow!("missing PayPal header {name}"))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreatePaymentRequest {
    id: String,
    merchant_id: String,
    amount_minor: u64,
    currency: String,
    #[serde(default)]
    description: String,
    #[serde(default = "default_ttl")]
    expires_in: u64,
    idempotency_key: String,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct RefundRequest {
    #[serde(default)]
    amount_minor: Option<u64>,
    #[serde(default)]
    currency: Option<String>,
    #[serde(default)]
    idempotency_key: Option<String>,
}

fn default_ttl() -> u64 {
    600
}

fn validate_state_transition(intent: &PaymentIntent) -> Result<()> {
    intent.validate(now()?)?;
    Ok(())
}

async fn paypal_client(state: &ApiState) -> Result<PayPalSandbox> {
    let runtime = state.paypal_runtime.read().await;
    runtime
        .0
        .clone()
        .or_else(|| state.paypal.clone())
        .ok_or_else(|| anyhow::anyhow!("PayPal is not configured"))
}

async fn webhook_id(state: &ApiState) -> Result<String> {
    let runtime = state.paypal_runtime.read().await;
    runtime
        .2
        .clone()
        .or_else(|| state.webhook_id.clone())
        .ok_or_else(|| anyhow::anyhow!("PayPal webhook ID is not configured"))
}

fn idempotency_header(request: &Request<Incoming>) -> Option<&str> {
    request
        .headers()
        .get("idempotency-key")
        .or_else(|| request.headers().get("paypal-request-id"))
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty())
}

fn choose_idempotency_key(
    body_key: Option<&str>,
    header_key: Option<&str>,
) -> Result<Option<String>> {
    match (body_key, header_key) {
        (Some(body), Some(header)) if body != header => {
            bail!("conflicting idempotency keys in body and header")
        }
        (Some(body), _) => {
            validate_request_id(body)?;
            Ok(Some(body.to_owned()))
        }
        (_, Some(header)) => {
            validate_request_id(header)?;
            Ok(Some(header.to_owned()))
        }
        (None, None) => Ok(None),
    }
}

fn parse_refund_request(raw: &[u8]) -> Result<RefundRequest> {
    if raw.iter().all(u8::is_ascii_whitespace) {
        return Ok(RefundRequest::default());
    }
    serde_json::from_slice(raw).context("invalid refund request JSON")
}

fn extract_webhook_headers(request: &Request<Incoming>) -> Result<WebhookHeaders> {
    Ok(WebhookHeaders {
        auth_algo: extract_header(request, "paypal-auth-algo")?.to_owned(),
        cert_url: extract_header(request, "paypal-cert-url")?.to_owned(),
        transmission_id: extract_header(request, "paypal-transmission-id")?.to_owned(),
        transmission_sig: extract_header(request, "paypal-transmission-sig")?.to_owned(),
        transmission_time: extract_header(request, "paypal-transmission-time")?.to_owned(),
    })
}

fn external_error_status(error: &anyhow::Error) -> StatusCode {
    let text = error.to_string();
    if text.contains("PAYPAL_WEBHOOK_ID is not configured")
        || text.contains("PayPal is not configured")
    {
        StatusCode::SERVICE_UNAVAILABLE
    } else if text.starts_with("PayPal ")
        || text.contains("PayPal OAuth")
        || text.starts_with("invalid JSON in PayPal")
    {
        StatusCode::BAD_GATEWAY
    } else if text.contains("not found") {
        StatusCode::NOT_FOUND
    } else {
        StatusCode::BAD_REQUEST
    }
}

fn database_is_available(book: &SqlitePaymentBook, merchant_id: &str) -> bool {
    book.list_payments_for_merchant(merchant_id).is_ok()
}

fn health_status(database_available: bool, key_available: bool) -> &'static str {
    if database_available && key_available {
        "ok"
    } else {
        "degraded"
    }
}

fn handler_error(error: anyhow::Error) -> Response<ApiBody> {
    json_response(
        external_error_status(&error),
        &json!({"error": error.to_string()}),
    )
}

fn rate_limited(retry_after: u64) -> Response<ApiBody> {
    Response::builder()
        .status(StatusCode::TOO_MANY_REQUESTS)
        .header(CONTENT_TYPE, "application/json; charset=utf-8")
        .header("Retry-After", retry_after.to_string())
        .header("Cache-Control", "no-store")
        .body(Full::new(Bytes::from(
            serde_json::to_vec(&json!({"error":"rate limit exceeded"})).unwrap_or_default(),
        )))
        .expect("static response headers")
}

fn rate_limit(
    state: &ApiState,
    peer: IpAddr,
    path: &str,
    method: &Method,
) -> Option<Response<ApiBody>> {
    let general_key = format!("{peer}:general");
    if let Err(retry) = state
        .rate_limiter
        .check(&general_key, GENERAL_RATE_LIMIT, RATE_WINDOW)
    {
        return Some(rate_limited(retry));
    }
    let mutating_paypal = path.starts_with("/api/paypal/")
        && matches!(
            *method,
            Method::POST | Method::PUT | Method::PATCH | Method::DELETE
        );
    if mutating_paypal {
        let mutation_key = format!("{peer}:paypal-mutation");
        if let Err(retry) =
            state
                .rate_limiter
                .check(&mutation_key, MUTATION_RATE_LIMIT, RATE_WINDOW)
        {
            return Some(rate_limited(retry));
        }
    }
    None
}

fn evidence_json(state: &ApiState, payment_id: &str) -> Result<Option<Value>> {
    Ok(state
        .security
        .evidence_for(payment_id)?
        .map(|record| serde_json::to_value(record).unwrap_or(Value::Null)))
}

fn append_capture_evidence(
    state: &ApiState,
    intent: &PaymentIntent,
    order_id: &str,
    capture_id: &str,
    event_id: &str,
    payload_sha: &str,
    at: u64,
) -> Result<String> {
    let authorization = create_authorization(
        &state.keys,
        intent,
        order_id,
        Some(capture_id.to_owned()),
        300,
    )?;
    verify_authorization(
        &state.keys,
        &authorization,
        &state.security,
        AuthorizationExpectation {
            intent,
            paypal_order_id: order_id,
            capture_id: Some(capture_id),
            expected_key_id: &state.keys.key_id,
            now: at,
        },
    )?;
    let evidence = build_evidence(EvidenceInput {
        intent,
        paypal_order_id: order_id,
        capture_id,
        event_id,
        payload_sha256: payload_sha,
        reconciled_at: at,
        authorization: &authorization,
        authorization_verified: true,
        keys: &state.keys,
    })?;
    state.security.append_evidence(&evidence, &state.keys)?;
    Ok(evidence.chain_hash)
}

fn valid_webhook_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn parse_money_value(value: &str) -> Result<u64> {
    let (whole, fraction) = value
        .split_once('.')
        .ok_or_else(|| anyhow::anyhow!("PayPal amount is not in decimal format"))?;
    if whole.is_empty()
        || whole.len() > 12
        || !whole.bytes().all(|b| b.is_ascii_digit())
        || fraction.len() != 2
        || !fraction.bytes().all(|b| b.is_ascii_digit())
    {
        bail!("PayPal amount is not in a valid decimal format");
    }
    let whole: u64 = whole.parse().context("invalid PayPal amount")?;
    let fraction: u64 = fraction.parse().context("invalid PayPal amount")?;
    let minor = whole
        .checked_mul(100)
        .and_then(|v| v.checked_add(fraction))
        .ok_or_else(|| anyhow::anyhow!("PayPal amount overflow"))?;
    validate_amount(minor)?;
    Ok(minor)
}

fn validate_authoritative_refund_id(expected_id: &str, refund: &Value) -> Result<()> {
    let actual_id = refund
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("PayPal refund response has no refund ID"))?;

    if actual_id != expected_id {
        bail!("PayPal refund ID does not match requested refund ID");
    }

    Ok(())
}

fn capture_id_from_refund(refund: &Value) -> Result<String> {
    if let Some(id) = refund
        .pointer("/supplementary_data/related_ids/capture_id")
        .and_then(Value::as_str)
    {
        validate_capture_id(id)?;
        return Ok(id.to_owned());
    }

    let links = refund
        .get("links")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow::anyhow!("refund has no related capture link"))?;
    for link in links {
        let rel = link.get("rel").and_then(Value::as_str).unwrap_or_default();
        let href = link.get("href").and_then(Value::as_str).unwrap_or_default();
        if rel == "up" || href.contains("/captures/") {
            if let Some(id) = href.trim_end_matches('/').rsplit('/').next() {
                if validate_capture_id(id).is_ok() {
                    return Ok(id.to_owned());
                }
            }
        }
    }
    bail!("refund has no related capture link")
}

async fn handle_webhook(state: &ApiState, raw: &[u8], headers: WebhookHeaders) -> Result<Value> {
    let event_json: Value =
        serde_json::from_slice(raw).context("webhook event is not valid JSON")?;
    let event_id = event_json
        .get("id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow::anyhow!("webhook event has no string event ID"))?
        .to_owned();
    let event_type = event_json
        .get("event_type")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow::anyhow!("webhook event has no string event_type"))?
        .to_owned();
    if !valid_webhook_identifier(&event_id) {
        bail!("webhook event ID is invalid");
    }

    let paypal = paypal_client(state).await?;
    let configured_webhook_id = webhook_id(state).await?;
    paypal
        .verify_webhook_signature(&configured_webhook_id, &headers, &event_json)
        .await?;
    let payload_sha = crate::payment_security::sha256_hex(raw);
    let received_at = now()?;

    match event_type.as_str() {
        "PAYMENT.CAPTURE.COMPLETED" => {
            let (_, parsed) = parse_capture_webhook(raw)?;
            let (bound_intent, _) = state.book.payment_for_paypal_order(&parsed.order_id)?;
            if bound_intent.merchant_id != state.merchant_id {
                bail!("webhook order is outside the configured merchant");
            }
            let order = paypal.get_order(&parsed.order_id).await?;
            if order.get("id").and_then(Value::as_str) != Some(parsed.order_id.as_str())
                || order.get("status").and_then(Value::as_str) != Some("COMPLETED")
            {
                bail!("authoritative PayPal order is not the expected completed order");
            }
            let (intent, payment_state) = state.book.payment_for_paypal_order(&parsed.order_id)?;
            if !matches!(
                payment_state,
                PaymentState::Pending | PaymentState::Authorized | PaymentState::Captured
            ) {
                bail!("local payment is not eligible for capture reconciliation");
            }
            validate_order_matches(&order, &intent, &parsed.capture_id)?;

            let recorded = state.book.record_verified_capture(
                &parsed.event_id,
                &parsed.event_type,
                &payload_sha,
                received_at,
                &intent.id,
                &parsed.capture_id,
            )?;
            state.security.log_event(
                "webhook.verified",
                "verified",
                Some(&intent.id),
                &format!("PayPal signature verified for event {}", parsed.event_id),
            )?;
            if !recorded {
                if state.security.evidence_for(&intent.id)?.is_none() {
                    let chain_hash = append_capture_evidence(
                        state,
                        &intent,
                        &parsed.order_id,
                        &parsed.capture_id,
                        &parsed.event_id,
                        &payload_sha,
                        received_at,
                    )?;
                    return Ok(
                        json!({"status":"duplicate_recovered","payment_id":intent.id,
                        "capture_id":parsed.capture_id,"evidence_chain_hash":chain_hash}),
                    );
                }
                return Ok(json!({"status":"duplicate","payment_id":intent.id}));
            }
            let chain_hash = append_capture_evidence(
                state,
                &intent,
                &parsed.order_id,
                &parsed.capture_id,
                &parsed.event_id,
                &payload_sha,
                received_at,
            )?;
            Ok(json!({
                "status":"captured",
                "payment_id":intent.id,
                "capture_id":parsed.capture_id,
                "evidence_chain_hash":chain_hash
            }))
        }
        "CUSTOMER.DISPUTE.CREATED" | "CUSTOMER.DISPUTE.UPDATED" | "CUSTOMER.DISPUTE.RESOLVED" => {
            let resource = event_json
                .get("resource")
                .ok_or_else(|| anyhow::anyhow!("dispute event has no resource"))?;
            let dispute_id = resource
                .get("dispute_id")
                .or_else(|| resource.get("id"))
                .and_then(Value::as_str)
                .filter(|v| !v.is_empty())
                .ok_or_else(|| anyhow::anyhow!("dispute event has no dispute identifier"))?;
            let capture_id = resource
                .pointer("/disputed_transactions/0/seller_transaction_id")
                .or_else(|| resource.get("seller_transaction_id"))
                .and_then(Value::as_str)
                .filter(|v| validate_capture_id(v).is_ok());
            let payment_id = if let Some(capture) = capture_id {
                state
                    .book
                    .capture_details(capture)?
                    .map(|record| record.payment_id)
            } else {
                None
            };
            if let Some(ref id) = payment_id {
                let owner = state.book.payment_intent(id)?;
                if owner.merchant_id != state.merchant_id {
                    bail!("dispute references a transaction outside the configured merchant");
                }
            }
            let correlated = payment_id.is_some();
            let inserted = state.book.record_dispute_event(
                &event_id,
                dispute_id,
                &event_type,
                &state.merchant_id,
                payment_id.as_deref(),
                capture_id,
                resource,
                &payload_sha,
                received_at,
            )?;
            state.security.log_event(
                "dispute.lifecycle",
                if inserted { "warning" } else { "info" },
                payment_id.as_deref(),
                &format!(
                    "verified PayPal dispute event={} dispute_id={} correlated={}",
                    event_type, dispute_id, correlated
                ),
            )?;
            Ok(
                json!({"status": if inserted {"recorded"} else {"duplicate"},
                "event_type":event_type,"dispute_id":dispute_id,"payment_id":payment_id,
                "capture_id":capture_id,"correlated":correlated}),
            )
        }
        "PAYMENT.CAPTURE.REFUNDED" => {
            let refund_id = event_json
                .pointer("/resource/id")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow::anyhow!("refund event has no resource ID"))?
                .to_owned();
            validate_refund_id(&refund_id)?;
            let refund = paypal.get_refund(&refund_id).await?;
            validate_authoritative_refund_id(&refund_id, &refund)?;
            let status = refund
                .get("status")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow::anyhow!("PayPal refund has no status"))?;
            let currency = refund
                .pointer("/amount/currency_code")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow::anyhow!("PayPal refund has no currency"))?;
            let value = refund
                .pointer("/amount/value")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow::anyhow!("PayPal refund has no amount"))?;
            let amount_minor = parse_money_value(value)?;
            validate_currency(currency)?;
            let capture_id = capture_id_from_refund(&refund)?;
            let capture = state.book.capture_details(&capture_id)?;

            let processed = if let Some(capture) = capture {
                let (duplicate, full_refund, total) = state.book.record_refund(
                    &refund_id,
                    &capture_id,
                    &capture.payment_id,
                    status,
                    amount_minor,
                    currency,
                    received_at,
                )?;
                state.security.log_event(
                    "refund.webhook",
                    "verified",
                    Some(&capture.payment_id),
                    &format!(
                        "PayPal refund {} verified; status={} total_refunded_minor={}",
                        refund_id, status, total
                    ),
                )?;
                json!({
                    "status": if duplicate {"duplicate"} else {"refund_recorded"},
                    "payment_id": capture.payment_id,
                    "capture_id": capture_id,
                    "refund_id": refund_id,
                    "refund_status": status,
                    "full_refund": full_refund,
                    "total_refunded_minor": total
                })
            } else {
                json!({
                    "status": "ignored",
                    "reason": "capture is not recorded locally",
                    "capture_id": capture_id,
                    "refund_id": refund_id
                })
            };

            let new_event = state.book.record_verified_webhook(
                &event_id,
                &event_type,
                &payload_sha,
                received_at,
            );
            match new_event {
                Ok(true) => Ok(processed),
                Ok(false) => Ok(json!({"status":"duplicate","refund_id":refund_id})),
                Err(error) => Err(error),
            }
        }
        _ => {
            let recorded = state.book.record_verified_webhook(
                &event_id,
                &event_type,
                &payload_sha,
                received_at,
            )?;
            state.security.log_event(
                "webhook.verified",
                "verified",
                None,
                &format!("PayPal signature verified for event {event_id} ({event_type})"),
            )?;
            Ok(json!({
                "status": if recorded {"ignored"} else {"duplicate"},
                "event_type": event_type
            }))
        }
    }
}

pub(crate) fn validate_order_matches(
    order: &Value,
    intent: &PaymentIntent,
    capture_id: &str,
) -> Result<()> {
    let units = order
        .get("purchase_units")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow::anyhow!("PayPal order has no purchase_units"))?;
    if units.len() != 1 {
        bail!("expected exactly one PayPal purchase unit");
    }
    let unit = &units[0];
    if unit.get("reference_id").and_then(Value::as_str) != Some(intent.id.as_str())
        || unit.get("custom_id").and_then(Value::as_str) != Some(intent.id.as_str())
    {
        bail!("PayPal order reference does not match the local payment");
    }
    let expected_amount = format!(
        "{}.{:02}",
        intent.amount_minor / 100,
        intent.amount_minor % 100
    );
    let amount = unit
        .get("amount")
        .ok_or_else(|| anyhow::anyhow!("PayPal order has no amount"))?;
    if amount.get("currency_code").and_then(Value::as_str) != Some(intent.currency.as_str())
        || amount.get("value").and_then(Value::as_str) != Some(expected_amount.as_str())
    {
        bail!("PayPal order amount or currency does not match the local payment");
    }
    let matched = unit
        .pointer("/payments/captures")
        .and_then(Value::as_array)
        .map(|captures| {
            captures.iter().any(|capture| {
                capture.get("id").and_then(Value::as_str) == Some(capture_id)
                    && capture.get("status").and_then(Value::as_str) == Some("COMPLETED")
                    && capture
                        .pointer("/amount/currency_code")
                        .and_then(Value::as_str)
                        == Some(intent.currency.as_str())
                    && capture.pointer("/amount/value").and_then(Value::as_str)
                        == Some(expected_amount.as_str())
            })
        })
        .unwrap_or(false);
    if !matched {
        bail!("capture ID, status, amount or currency does not match PayPal's order");
    }
    Ok(())
}

async fn capture_payment(state: &ApiState, payment_id: &str) -> Result<Value> {
    let intent = state.book.payment_intent(payment_id)?;
    if intent.merchant_id != state.merchant_id {
        bail!("payment not found");
    }
    let payment_state = state.book.state(payment_id)?;
    if !matches!(
        payment_state,
        PaymentState::Pending | PaymentState::Authorized | PaymentState::Captured
    ) {
        bail!("payment is not eligible for capture: {payment_state:?}");
    }
    let order_id = state
        .book
        .paypal_order_id(payment_id)?
        .ok_or_else(|| anyhow::anyhow!("payment has no bound PayPal order"))?;
    let paypal = paypal_client(state).await?;

    // Verify merchant authorization integrity before any capture call.
    if payment_state != PaymentState::Captured {
        let pre_capture = create_authorization(&state.keys, &intent, &order_id, None, 300)?;
        verify_authorization(
            &state.keys,
            &pre_capture,
            &state.security,
            AuthorizationExpectation {
                intent: &intent,
                paypal_order_id: &order_id,
                capture_id: None,
                expected_key_id: &state.keys.key_id,
                now: now()?,
            },
        )?;
    }

    let captured = if payment_state == PaymentState::Captured {
        paypal.get_order(&order_id).await?
    } else {
        match paypal.capture_order(&order_id).await {
            Ok(value) => value,
            Err(capture_error) => {
                // A lost response or client timeout can leave PayPal captured while
                // the local state is still pending. Recover only from PayPal's
                // authoritative order, never from the browser.
                let authoritative = paypal.get_order(&order_id).await.map_err(|_| {
                    anyhow::anyhow!(
                        "PayPal capture failed and recovery lookup failed: {capture_error}"
                    )
                })?;
                if authoritative.get("status").and_then(Value::as_str) != Some("COMPLETED") {
                    bail!("PayPal capture failed: {capture_error}");
                }
                authoritative
            }
        }
    };
    let capture_id = captured
        .pointer("/purchase_units/0/payments/captures/0/id")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("PayPal capture response has no capture ID"))?
        .to_owned();
    let authoritative = paypal.get_order(&order_id).await?;
    if authoritative.get("status").and_then(Value::as_str) != Some("COMPLETED") {
        bail!("PayPal order is not COMPLETED after capture");
    }
    validate_order_matches(&authoritative, &intent, &capture_id)?;

    let raw = serde_json::to_vec(&captured)?;
    let payload_sha = crate::payment_security::sha256_hex(&raw);
    let at = now()?;
    let recorded =
        state
            .book
            .record_authoritative_capture(&intent.id, &capture_id, &payload_sha, at)?;
    state.security.log_event(
        "capture.authoritative",
        "verified",
        Some(&intent.id),
        "PayPal capture API and authoritative order matched",
    )?;
    if !recorded {
        let repaired = if state.security.evidence_for(&intent.id)?.is_none() {
            append_capture_evidence(
                state,
                &intent,
                &order_id,
                &capture_id,
                &format!("capture_{capture_id}"),
                &payload_sha,
                at,
            )?;
            true
        } else {
            false
        };
        return Ok(
            json!({"status":"duplicate","payment_id":intent.id,"capture_id":capture_id,
            "evidence_repaired": repaired}),
        );
    }

    let authorization = create_authorization(
        &state.keys,
        &intent,
        &order_id,
        Some(capture_id.clone()),
        300,
    )?;
    verify_authorization(
        &state.keys,
        &authorization,
        &state.security,
        AuthorizationExpectation {
            intent: &intent,
            paypal_order_id: &order_id,
            capture_id: Some(&capture_id),
            expected_key_id: &state.keys.key_id,
            now: at,
        },
    )?;
    let evidence = build_evidence(EvidenceInput {
        intent: &intent,
        paypal_order_id: &order_id,
        capture_id: &capture_id,
        event_id: &format!("capture_{capture_id}"),
        payload_sha256: &payload_sha,
        reconciled_at: at,
        authorization: &authorization,
        authorization_verified: true,
        keys: &state.keys,
    })?;
    state.security.append_evidence(&evidence, &state.keys)?;
    Ok(json!({
        "status":"captured",
        "payment_id":intent.id,
        "capture_id":capture_id,
        "evidence_chain_hash":evidence.chain_hash
    }))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RiskDecision {
    score: u8,
    action: &'static str,
    reasons: Vec<&'static str>,
}

/// Deterministic rules, not machine learning. Reject decisions are explainable and auditable.
fn assess_payment_risk(amount_minor: u64, currency: &str, description: &str) -> RiskDecision {
    let mut score = 0u8;
    let mut reasons = Vec::new();
    if amount_minor >= 1_000_000 {
        score = score.saturating_add(45);
        reasons.push("high_transaction_amount");
    } else if amount_minor >= 500_000 {
        score = score.saturating_add(25);
        reasons.push("elevated_transaction_amount");
    }
    if !matches!(
        currency,
        "USD"
            | "EUR"
            | "GBP"
            | "CAD"
            | "AUD"
            | "JPY"
            | "INR"
            | "SGD"
            | "HKD"
            | "NZD"
            | "CHF"
            | "SEK"
            | "NOK"
            | "DKK"
            | "PLN"
            | "MXN"
            | "BRL"
    ) {
        score = score.saturating_add(20);
        reasons.push("currency_outside_configured_allowlist");
    }
    let normalized = description.to_ascii_lowercase();
    if ["stolen", "fraud", "carding", "test card"]
        .iter()
        .any(|term| normalized.contains(term))
    {
        score = score.saturating_add(70);
        reasons.push("suspicious_payment_description");
    }
    let action = if score >= 50 { "reject" } else { "allow" };
    RiskDecision {
        score,
        action,
        reasons,
    }
}

async fn create_payment(state: &ApiState, raw: &[u8]) -> Result<Value> {
    let request: CreatePaymentRequest =
        serde_json::from_slice(raw).context("invalid payment request JSON")?;
    let at = now()?;
    if request.merchant_id != state.merchant_id {
        bail!("merchant_id must match the server-configured merchant");
    }
    let risk = assess_payment_risk(
        request.amount_minor,
        &request.currency,
        &request.description,
    );
    state.security.log_event(
        "payment.risk.assessed",
        if risk.action == "reject" {
            "rejected"
        } else {
            "info"
        },
        Some(&request.id),
        &format!(
            "score={} action={} reasons={}",
            risk.score,
            risk.action,
            risk.reasons.join(",")
        ),
    )?;
    if risk.action == "reject" {
        bail!("payment rejected by risk policy (score {})", risk.score);
    }
    let intent = PaymentIntent {
        id: request.id,
        merchant_id: state.merchant_id.clone(),
        amount_minor: request.amount_minor,
        currency: request.currency,
        description: request.description,
        created_at: at,
        expires_at: at + request.expires_in.clamp(60, 900),
    };
    validate_state_transition(&intent)?;
    let created = state
        .book
        .create(intent.clone(), &request.idempotency_key, at)?;
    let payment_state = state.book.state(&created.id)?;
    let mut approval_url = None;
    let mut paypal_order_status = None;
    if payment_state == PaymentState::Created {
        state.book.transition(&created.id, PaymentState::Pending)?;
    }
    let paypal = {
        let runtime = state.paypal_runtime.read().await;
        runtime.0.clone().or_else(|| state.paypal.clone())
    };
    if let Some(paypal) = paypal {
        if state.book.paypal_order_id(&created.id)?.is_none() {
            let order = paypal
                .create_order(&created.id, created.amount_minor, &created.currency)
                .await?;
            state.book.bind_paypal_order(&created.id, &order.id)?;
            state
                .book
                .set_order_status(&created.id, &order.id, &order.status)?;
            approval_url = order.approval_url().map(str::to_owned);
            paypal_order_status = Some(order.status);
            let order_auth = create_authorization(&state.keys, &created, &order.id, None, 300)?;
            verify_authorization(
                &state.keys,
                &order_auth,
                &state.security,
                AuthorizationExpectation {
                    intent: &created,
                    paypal_order_id: &order.id,
                    capture_id: None,
                    expected_key_id: &state.keys.key_id,
                    now: at,
                },
            )?;
            state.security.log_event(
                "paypal.order.created",
                "verified",
                Some(&created.id),
                "PayPal Sandbox order created, bound and authorized",
            )?;
        }
    }
    Ok(json!({
        "payment_id": created.id,
        "state": format!("{:?}", state.book.state(&created.id)?),
        "paypal_order_id": state.book.paypal_order_id(&created.id)?,
        "paypal_order_status": paypal_order_status,
        "approval_url": approval_url,
        "paypal_configured": paypal_client_is_configured(state).await
    }))
}

async fn paypal_client_is_configured(state: &ApiState) -> bool {
    let runtime = state.paypal_runtime.read().await;
    runtime.0.is_some() || state.paypal.is_some()
}

async fn paypal_status(state: &ApiState) -> Result<Value> {
    let (paypal, webhook_configured) = {
        let runtime = state.paypal_runtime.read().await;
        (
            runtime.0.clone().or_else(|| state.paypal.clone()),
            runtime.2.is_some() || state.webhook_id.is_some(),
        )
    };
    let Some(paypal) = paypal else {
        return Ok(json!({
            "paypal_configured": false,
            "environment": "sandbox",
            "oauth_token_acquired": false,
            "webhook_id_configured": false,
            "error": "Sandbox credentials are not configured"
        }));
    };
    match paypal.check_connectivity().await {
        Ok(connectivity) => Ok(json!({
            "paypal_configured": true,
            "environment": connectivity.environment,
            "api_base": connectivity.api_base,
            "oauth_token_acquired": connectivity.oauth_token_acquired,
            "webhook_id_configured": webhook_configured
        })),
        Err(_) => Ok(json!({
            "paypal_configured": true,
            "environment": "sandbox",
            "oauth_token_acquired": false,
            "webhook_id_configured": webhook_configured,
            "error": "Sandbox OAuth connectivity validation failed"
        })),
    }
}

fn parse_paypal_setup(raw: &[u8]) -> Result<PaypalStored> {
    let input: PaypalSetup = serde_json::from_slice(raw).context("invalid PayPal setup request")?;
    let client_id = input.client_id.trim();
    let client_secret = input.client_secret.trim();
    let webhook_id = input.webhook_id.trim();
    if client_id.is_empty()
        || client_id.len() > 256
        || client_secret.is_empty()
        || client_secret.len() > 512
        || webhook_id.len() > 128
        || [&client_id, &client_secret, &webhook_id]
            .iter()
            .any(|value| value.bytes().any(|byte| byte.is_ascii_control()))
    {
        bail!("Client ID and Client Secret are required; all supplied fields must be valid");
    }
    Ok(PaypalStored {
        client_id: client_id.to_owned(),
        client_secret: client_secret.to_owned(),
        webhook_id: webhook_id.to_owned(),
    })
}

async fn save_paypal_config_with_client(
    state: &ApiState,
    stored: PaypalStored,
    client: PayPalSandbox,
) -> Result<Value> {
    persist_paypal_config(&state.paypal_config_path, &state.keys, &stored)?;
    let webhook_id = (!stored.webhook_id.is_empty()).then(|| stored.webhook_id.clone());
    *state.paypal_runtime.write().await = (Some(client.clone()), None, webhook_id.clone());

    // Credential persistence is independent from network availability. The
    // status remains explicitly unverified unless PayPal issues an OAuth token.
    let oauth_verified = client.check_connectivity().await.is_ok();
    Ok(json!({
        "configured": true,
        "credentials_saved": true,
        "environment": "sandbox",
        "webhook_id_configured": webhook_id.is_some(),
        "oauth_verified": oauth_verified,
        "error": if oauth_verified { Value::Null } else {
            json!("Credentials were saved, but Sandbox OAuth could not be verified. Check the Sandbox Client ID and Secret, and confirm the service can reach PayPal.")
        }
    }))
}

async fn setup_paypal(state: &ApiState, raw: &[u8]) -> Result<Value> {
    let stored = parse_paypal_setup(raw)?;
    let client = PayPalSandbox::new(
        stored.client_id.clone(),
        stored.client_secret.clone(),
        crate::paypal::PayPalEnvironment::Sandbox,
    )?;
    save_paypal_config_with_client(state, stored, client).await
}

fn persist_paypal_config(
    path: &std::path::Path,
    keys: &CryptoKeys,
    config: &PaypalStored,
) -> Result<()> {
    let sealed = keys.seal(PAYPAL_CONFIG_AAD, &serde_json::to_vec(config)?)?;
    let bytes = serde_json::to_vec(&sealed)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
        }
    }
    let tmp = path.with_extension(format!("tmp-{}", std::process::id()));
    {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&tmp)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        f.write_all(&bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}
fn remove_paypal_config_file(path: &std::path::Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => anyhow::bail!("could not clear the saved PayPal configuration"),
    }
}

fn load_paypal_config(path: &std::path::Path, keys: &CryptoKeys) -> Result<PaypalStored> {
    let envelope: crate::payment_security::SealedEnvelope =
        serde_json::from_slice(&std::fs::read(path)?)?;
    Ok(serde_json::from_slice(
        &keys.open(PAYPAL_CONFIG_AAD, &envelope)?,
    )?)
}

async fn create_paypal_order(
    state: &ApiState,
    raw: &[u8],
    header_idempotency_key: Option<&str>,
) -> Result<(StatusCode, Value)> {
    let paypal = paypal_client(state).await?;
    let request: CreatePaymentRequest =
        serde_json::from_slice(raw).context("invalid order request JSON")?;
    let idempotency_key =
        choose_idempotency_key(Some(&request.idempotency_key), header_idempotency_key)?
            .expect("body idempotency key is mandatory");

    let at = now()?;
    if !request.description.is_empty() {
        crate::paypal::validate_description(&request.description)?;
    }
    if request.merchant_id != state.merchant_id {
        bail!("merchant_id must match the server-configured merchant");
    }
    let risk = assess_payment_risk(
        request.amount_minor,
        &request.currency,
        &request.description,
    );
    state.security.log_event(
        "payment.risk.assessed",
        if risk.action == "reject" {
            "rejected"
        } else {
            "info"
        },
        Some(&request.id),
        &format!(
            "score={} action={} reasons={}",
            risk.score,
            risk.action,
            risk.reasons.join(",")
        ),
    )?;
    if risk.action == "reject" {
        bail!("payment rejected by risk policy (score {})", risk.score);
    }
    let intent = PaymentIntent {
        id: request.id,
        merchant_id: state.merchant_id.clone(),
        amount_minor: request.amount_minor,
        currency: request.currency,
        description: request.description,
        created_at: at,
        expires_at: at + request.expires_in.clamp(60, 900),
    };
    validate_state_transition(&intent)?;
    let created = state.book.create(intent.clone(), &idempotency_key, at)?;

    if let Some(order_id) = state.book.paypal_order_id(&created.id)? {
        return Ok((
            StatusCode::OK,
            json!({
                "status": "duplicate",
                "payment_id": created.id,
                "paypal_order_id": order_id,
                "paypal_order_status": state.book.order_status(&created.id)?,
                "state": format!("{:?}", state.book.state(&created.id)?)
            }),
        ));
    }

    let payment_state = state.book.state(&created.id)?;
    match payment_state {
        PaymentState::Created => {
            state.book.transition(&created.id, PaymentState::Pending)?;
        }
        PaymentState::Pending => {}
        _ => bail!("payment is not eligible for PayPal order creation: {payment_state:?}"),
    }

    let description = if created.description.is_empty() {
        None
    } else {
        Some(created.description.as_str())
    };
    let order = paypal
        .create_order_with_request_id(
            &created.id,
            created.amount_minor,
            &created.currency,
            &format!("qs-order-{}", created.id),
            description,
        )
        .await?;
    state.book.bind_paypal_order(&created.id, &order.id)?;
    state
        .book
        .set_order_status(&created.id, &order.id, &order.status)?;

    let authorization = create_authorization(&state.keys, &created, &order.id, None, 300)?;
    verify_authorization(
        &state.keys,
        &authorization,
        &state.security,
        AuthorizationExpectation {
            intent: &created,
            paypal_order_id: &order.id,
            capture_id: None,
            expected_key_id: &state.keys.key_id,
            now: at,
        },
    )?;
    state.security.log_event(
        "paypal.order.created",
        "verified",
        Some(&created.id),
        "PayPal order created, bound and merchant-authorized",
    )?;
    let approval_url = order.approval_url().map(str::to_owned);
    Ok((
        StatusCode::CREATED,
        json!({
            "status": "created",
            "payment_id": created.id,
            "paypal_order_id": order.id,
            "paypal_order_status": order.status,
            "state": format!("{:?}", state.book.state(&created.id)?),
            "amount_minor": created.amount_minor,
            "currency": created.currency,
            "approval_url": approval_url,
            "links": order.links
        }),
    ))
}

fn first_completed_capture(order: &Value) -> Option<&Value> {
    order
        .pointer("/purchase_units/0/payments/captures")
        .and_then(Value::as_array)?
        .iter()
        .find(|capture| capture.get("status").and_then(Value::as_str) == Some("COMPLETED"))
}

async fn get_paypal_order(state: &ApiState, order_id: &str) -> Result<Value> {
    validate_order_id(order_id)?;
    let (bound_intent, _) = state
        .book
        .payment_for_paypal_order(order_id)
        .context("PayPal order is not bound to a local payment")?;
    if bound_intent.merchant_id != state.merchant_id {
        bail!("PayPal order does not belong to the configured merchant");
    }
    let paypal = paypal_client(state).await?;
    let order = paypal.get_order(order_id).await?;
    let paypal_order_status = order
        .get("status")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("PayPal order has no status"))?;
    let mut local = Value::Null;
    let mut reconciled = false;

    if let Ok((intent, payment_state)) = state.book.payment_for_paypal_order(order_id) {
        state
            .book
            .set_order_status(&intent.id, order_id, paypal_order_status)?;
        let mut local_state = format!("{payment_state:?}");
        if paypal_order_status == "COMPLETED"
            && matches!(
                payment_state,
                PaymentState::Pending | PaymentState::Authorized | PaymentState::Captured
            )
        {
            let capture = first_completed_capture(&order)
                .ok_or_else(|| anyhow::anyhow!("completed PayPal order has no capture"))?;
            let capture_id = capture
                .get("id")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow::anyhow!("PayPal capture has no ID"))?;
            validate_order_matches(&order, &intent, capture_id)?;
            let raw = serde_json::to_vec(&order)?;
            let payload_sha = crate::payment_security::sha256_hex(&raw);
            let at = now()?;
            let newly_recorded = state.book.record_authoritative_capture(
                &intent.id,
                capture_id,
                &payload_sha,
                at,
            )?;
            if newly_recorded || state.security.evidence_for(&intent.id)?.is_none() {
                append_capture_evidence(
                    state,
                    &intent,
                    order_id,
                    capture_id,
                    &format!("capture_{capture_id}"),
                    &payload_sha,
                    at,
                )?;
                reconciled = true;
            }
            local_state = "Captured".to_owned();
        }
        local = json!({
            "payment_id": intent.id,
            "state": local_state,
            "paypal_order_status": paypal_order_status,
            "capture": state.book.capture_for_order(order_id)?
        });
    }

    Ok(json!({
        "paypal_order_id": order_id,
        "order": order,
        "local": local,
        "reconciled": reconciled
    }))
}

async fn capture_paypal_order(state: &ApiState, order_id: &str) -> Result<Value> {
    validate_order_id(order_id)?;
    let paypal = paypal_client(state).await?;
    let (intent, payment_state) = state
        .book
        .payment_for_paypal_order(order_id)
        .context("payment is not bound to this PayPal order")?;
    if intent.merchant_id != state.merchant_id {
        bail!("PayPal order does not belong to the configured merchant");
    }

    if payment_state == PaymentState::Captured {
        return Ok(json!({
            "status": "duplicate",
            "payment_id": intent.id,
            "capture": state.book.capture_for_order(order_id)?
        }));
    }
    if !matches!(
        payment_state,
        PaymentState::Pending | PaymentState::Authorized
    ) {
        bail!("payment is not eligible for capture: {payment_state:?}");
    }

    let pre_capture = create_authorization(&state.keys, &intent, order_id, None, 300)?;
    verify_authorization(
        &state.keys,
        &pre_capture,
        &state.security,
        AuthorizationExpectation {
            intent: &intent,
            paypal_order_id: order_id,
            capture_id: None,
            expected_key_id: &state.keys.key_id,
            now: now()?,
        },
    )?;

    let captured = match paypal.capture_order(order_id).await {
        Ok(value) => value,
        Err(capture_error) => {
            let authoritative = paypal.get_order(order_id).await.map_err(|_| {
                anyhow::anyhow!("PayPal capture failed and recovery lookup failed: {capture_error}")
            })?;
            if authoritative.get("status").and_then(Value::as_str) != Some("COMPLETED") {
                bail!("PayPal capture failed: {capture_error}");
            }
            authoritative
        }
    };
    let capture_id = captured
        .pointer("/purchase_units/0/payments/captures/0/id")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("PayPal capture response has no capture ID"))?
        .to_owned();
    validate_capture_id(&capture_id)?;
    let authoritative = paypal.get_order(order_id).await?;
    if authoritative.get("status").and_then(Value::as_str) != Some("COMPLETED") {
        bail!("PayPal order is not COMPLETED after capture");
    }
    validate_order_matches(&authoritative, &intent, &capture_id)?;

    let raw = serde_json::to_vec(&captured)?;
    let payload_sha = crate::payment_security::sha256_hex(&raw);
    let at = now()?;
    let recorded =
        state
            .book
            .record_authoritative_capture(&intent.id, &capture_id, &payload_sha, at)?;
    state.security.log_event(
        "capture.authoritative",
        "verified",
        Some(&intent.id),
        "PayPal capture API and authoritative order matched",
    )?;
    if !recorded {
        return Ok(json!({
            "status":"duplicate",
            "payment_id":intent.id,
            "capture_id":capture_id
        }));
    }
    let chain_hash = append_capture_evidence(
        state,
        &intent,
        order_id,
        &capture_id,
        &format!("capture_{capture_id}"),
        &payload_sha,
        at,
    )?;
    Ok(json!({
        "status":"captured",
        "payment_id":intent.id,
        "paypal_order_id":order_id,
        "capture_id":capture_id,
        "evidence_chain_hash":chain_hash
    }))
}

async fn refund_paypal_capture(
    state: &ApiState,
    capture_id: &str,
    raw: &[u8],
    header_idempotency_key: Option<&str>,
) -> Result<(StatusCode, Value)> {
    validate_capture_id(capture_id)?;
    let paypal = paypal_client(state).await?;
    let request = parse_refund_request(raw)?;
    let local_capture = state
        .book
        .capture_details(capture_id)?
        .ok_or_else(|| anyhow::anyhow!("capture not found locally"))?;

    let owner_intent = state.book.payment_intent(&local_capture.payment_id)?;
    if owner_intent.merchant_id != state.merchant_id {
        bail!("capture does not belong to the configured merchant");
    }
    let provider_capture = paypal.get_capture(capture_id).await?;
    let provider_status = provider_capture
        .get("status")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("PayPal capture has no status"))?;
    let provider_currency = provider_capture
        .pointer("/amount/currency_code")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("PayPal capture has no currency"))?;
    let provider_value = provider_capture
        .pointer("/amount/value")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("PayPal capture has no amount"))?;
    let provider_amount = parse_money_value(provider_value)?;
    if provider_currency != local_capture.currency || provider_amount != local_capture.amount_minor
    {
        bail!("PayPal capture amount or currency does not match the local capture");
    }
    if provider_status == "REFUNDED" || provider_status == "DECLINED" || provider_status == "FAILED"
    {
        bail!("PayPal capture is not refundable: {provider_status}");
    }

    let remaining = local_capture
        .amount_minor
        .checked_sub(local_capture.refunded_minor)
        .ok_or_else(|| anyhow::anyhow!("capture is already fully refunded"))?;
    if remaining == 0 {
        bail!("capture is already fully refunded");
    }
    let amount_minor = request.amount_minor.unwrap_or(remaining);
    validate_amount(amount_minor)?;
    if amount_minor > remaining {
        bail!("refund amount exceeds the remaining captured amount");
    }
    let currency = request
        .currency
        .as_deref()
        .unwrap_or(&local_capture.currency);
    validate_currency(currency)?;
    if currency != local_capture.currency {
        bail!("refund currency does not match the capture currency");
    }

    let request_id =
        choose_idempotency_key(request.idempotency_key.as_deref(), header_idempotency_key)?
            .unwrap_or_else(|| format!("qs-refund-{capture_id}-{amount_minor}"));
    validate_request_id(&request_id)?;

    let created = paypal
        .refund_capture(capture_id, Some(amount_minor), currency, &request_id)
        .await?;
    let refund_id = created
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("PayPal refund response has no refund ID"))?
        .to_owned();
    validate_refund_id(&refund_id)?;
    let authoritative = paypal.get_refund(&refund_id).await?;
    validate_authoritative_refund_id(&refund_id, &authoritative)?;
    let status = authoritative
        .get("status")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("PayPal refund has no status"))?;
    let refund_currency = authoritative
        .pointer("/amount/currency_code")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("PayPal refund has no currency"))?;
    let refund_value = authoritative
        .pointer("/amount/value")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("PayPal refund has no amount"))?;
    let refund_amount = parse_money_value(refund_value)?;
    if refund_currency != currency || refund_amount != amount_minor {
        bail!("PayPal refund amount or currency does not match the request");
    }

    let at = now()?;
    let (duplicate, full_refund, total) = state.book.record_refund(
        &refund_id,
        capture_id,
        &local_capture.payment_id,
        status,
        refund_amount,
        refund_currency,
        at,
    )?;
    state.security.log_event(
        "refund.authoritative",
        "verified",
        Some(&local_capture.payment_id),
        &format!(
            "PayPal refund {} authoritative; status={} total_refunded_minor={}",
            refund_id, status, total
        ),
    )?;
    let http_status = if duplicate {
        StatusCode::OK
    } else {
        StatusCode::CREATED
    };
    Ok((
        http_status,
        json!({
            "status": if duplicate {"duplicate"} else {"refunded"},
            "refund_id": refund_id,
            "refund_status": status,
            "payment_id": local_capture.payment_id,
            "capture_id": capture_id,
            "amount_minor": refund_amount,
            "currency": refund_currency,
            "full_refund": full_refund,
            "total_refunded_minor": total,
            "refund": authoritative
        }),
    ))
}

async fn get_paypal_refund(state: &ApiState, refund_id: &str) -> Result<Value> {
    validate_refund_id(refund_id)?;
    let local = state
        .book
        .refund_details(refund_id)?
        .ok_or_else(|| anyhow::anyhow!("refund not found locally"))?;
    let owner = state.book.payment_intent(&local.payment_id)?;
    if owner.merchant_id != state.merchant_id {
        bail!("refund does not belong to the configured merchant");
    }
    let paypal = paypal_client(state).await?;
    let refund = paypal.get_refund(refund_id).await?;
    Ok(json!({
        "refund_id": refund_id,
        "refund": refund,
        "local": local
    }))
}

async fn route(
    state: Arc<ApiState>,
    request: Request<Incoming>,
    peer: IpAddr,
) -> Response<ApiBody> {
    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    if let Some(response) = rate_limit(&state, peer, &path, &method) {
        return response;
    }
    if path == "/" || path == "/index.html" {
        return if method == Method::GET {
            html_response(state.api_token.as_deref().filter(|_| peer.is_loopback()))
        } else {
            text_response(StatusCode::METHOD_NOT_ALLOWED, "method not allowed")
        };
    }
    if (path == "/health" || path == "/api/health") && method == Method::GET {
        let database_available = database_is_available(&state.book, &state.merchant_id);
        let key_status = state.keys.public_keys();
        let key_available = key_status
            .as_ref()
            .is_ok_and(|status| status.status == "active");
        let service_status = health_status(database_available, key_available);
        let paypal_error = if paypal_client_is_configured(&state).await {
            None
        } else {
            state.paypal_error.clone()
        };
        return json_response(
            StatusCode::OK,
            &json!({
                "service": "quantum-shield-paypal",
                "status": service_status,
                "uptime_seconds": now().unwrap_or(state.started_at).saturating_sub(state.started_at),
                "version": env!("CARGO_PKG_VERSION"),
                "database": "sqlite",
                "database_status": if database_available { "available" } else { "unavailable" },
                "paypal_sandbox_configured": paypal_client_is_configured(&state).await,
                "paypal_error": paypal_error,
                "algorithms": {
                    "key_establishment": ML_KEM_ALG,
                    "signature": ML_DSA_ALG,
                    "aead": AEAD_ALG,
                    "kdf": KDF_ALG
                },
                "key_status": key_status.ok()
            }),
        );
    }
    if path == "/api/paypal/status" && method == Method::GET {
        if !authorized(&state, &request, peer) {
            return text_response(StatusCode::UNAUTHORIZED, "bearer token required");
        }
        return match paypal_status(&state).await {
            Ok(value) => json_response(StatusCode::OK, &value),
            Err(_) => json_response(
                StatusCode::OK,
                &json!({"paypal_configured":false,"environment":"sandbox","oauth_token_acquired":false,"error":"PayPal status is unavailable"}),
            ),
        };
    }
    if path == "/api/paypal/config" {
        if !authorized(&state, &request, peer) {
            return text_response(StatusCode::UNAUTHORIZED, "authentication required");
        }
        if method == Method::GET {
            let r = state.paypal_runtime.read().await;
            return json_response(
                StatusCode::OK,
                &json!({"configured":r.0.is_some()||state.paypal.is_some(),"environment":"sandbox","webhook_id_configured":r.2.is_some()||state.webhook_id.is_some()}),
            );
        }
        if method == Method::DELETE {
            if let Err(error) = remove_paypal_config_file(&state.paypal_config_path) {
                return json_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &json!({"error":error.to_string()}),
                );
            }
            *state.paypal_runtime.write().await = (None, None, None);
            return json_response(StatusCode::OK, &json!({"configured":false}));
        }
        if method != Method::POST {
            return text_response(StatusCode::METHOD_NOT_ALLOWED, "method not allowed");
        }
        let raw = match read_body_limited(request).await {
            Ok(v) => v,
            Err(r) => return r,
        };
        return match setup_paypal(&state, &raw).await {
            Ok(v) => json_response(StatusCode::OK, &v),
            Err(e) => handler_error(e),
        };
    }
    if path == "/api/paypal/orders" {
        if method != Method::POST {
            return text_response(StatusCode::METHOD_NOT_ALLOWED, "method not allowed");
        }
        if !authorized(&state, &request, peer) {
            return text_response(StatusCode::UNAUTHORIZED, "bearer token required");
        }
        let header_key = idempotency_header(&request).map(str::to_owned);
        let raw = match read_body_limited(request).await {
            Ok(value) => value,
            Err(response) => return response,
        };
        return match create_paypal_order(&state, &raw, header_key.as_deref()).await {
            Ok((status, value)) => json_response(status, &value),
            Err(error) => {
                let _ = state.security.log_event(
                    "paypal.order.rejected",
                    "rejected",
                    None,
                    &error.to_string(),
                );
                handler_error(error)
            }
        };
    }
    if let Some(rest) = path.strip_prefix("/api/paypal/orders/") {
        if let Some(order_id) = rest.strip_suffix("/capture") {
            if method != Method::POST {
                return text_response(StatusCode::METHOD_NOT_ALLOWED, "method not allowed");
            }
            if !authorized(&state, &request, peer) {
                return text_response(StatusCode::UNAUTHORIZED, "bearer token required");
            }
            return match capture_paypal_order(&state, order_id).await {
                Ok(value) => json_response(StatusCode::OK, &value),
                Err(error) => {
                    let _ = state.security.log_event(
                        "paypal.capture.rejected",
                        "rejected",
                        None,
                        &error.to_string(),
                    );
                    handler_error(error)
                }
            };
        }
        if method == Method::GET && !rest.is_empty() && !rest.contains('/') {
            if !authorized(&state, &request, peer) {
                return text_response(StatusCode::UNAUTHORIZED, "bearer token required");
            }
            return match get_paypal_order(&state, rest).await {
                Ok(value) => json_response(StatusCode::OK, &value),
                Err(error) => handler_error(error),
            };
        }
    }
    if let Some(rest) = path.strip_prefix("/api/paypal/captures/") {
        if let Some(capture_id) = rest.strip_suffix("/refund") {
            if method != Method::POST {
                return text_response(StatusCode::METHOD_NOT_ALLOWED, "method not allowed");
            }
            if !authorized(&state, &request, peer) {
                return text_response(StatusCode::UNAUTHORIZED, "bearer token required");
            }
            let header_key = idempotency_header(&request).map(str::to_owned);
            let raw = match read_body_limited(request).await {
                Ok(value) => value,
                Err(response) => return response,
            };
            return match refund_paypal_capture(&state, capture_id, &raw, header_key.as_deref())
                .await
            {
                Ok((status, value)) => json_response(status, &value),
                Err(error) => {
                    let _ = state.security.log_event(
                        "paypal.refund.rejected",
                        "rejected",
                        None,
                        &error.to_string(),
                    );
                    handler_error(error)
                }
            };
        }
    }
    if let Some(refund_id) = path.strip_prefix("/api/paypal/refunds/") {
        if method == Method::GET && !refund_id.is_empty() && !refund_id.contains('/') {
            if !authorized(&state, &request, peer) {
                return text_response(StatusCode::UNAUTHORIZED, "bearer token required");
            }
            return match get_paypal_refund(&state, refund_id).await {
                Ok(value) => json_response(StatusCode::OK, &value),
                Err(error) => handler_error(error),
            };
        }
    }
    if path == "/api/overview" && method == Method::GET {
        if !authorized(&state, &request, peer) {
            return text_response(StatusCode::UNAUTHORIZED, "bearer token required");
        }
        let payments = state
            .book
            .list_payments_for_merchant(&state.merchant_id)
            .unwrap_or_default();
        let counts = state.security.counts().unwrap_or_default();
        let events = state.security.recent_events(12).unwrap_or_default();
        let keys = state.keys.public_keys().ok();
        let paypal_error = if paypal_client_is_configured(&state).await {
            None
        } else {
            state.paypal_error.clone()
        };
        return json_response(
            StatusCode::OK,
            &json!({
                "payments": payments,
                "merchant_id": state.merchant_id,
                "counts": counts,
                "events": events,
                "keys": keys,
                "paypal_sandbox_configured": paypal_client_is_configured(&state).await,
                "paypal_error": paypal_error,
                "algorithms": {
                    "key_establishment": ML_KEM_ALG,
                    "signature": ML_DSA_ALG,
                    "aead": AEAD_ALG,
                    "kdf": KDF_ALG
                }
            }),
        );
    }
    if path == "/api/payments" {
        if method == Method::GET {
            if !authorized(&state, &request, peer) {
                return text_response(StatusCode::UNAUTHORIZED, "bearer token required");
            }
            return match state.book.list_payments_for_merchant(&state.merchant_id) {
                Ok(list) => json_response(StatusCode::OK, &json!(list)),
                Err(e) => json_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &json!({"error": e.to_string()}),
                ),
            };
        }
        if method == Method::POST {
            if !authorized(&state, &request, peer) {
                return text_response(StatusCode::UNAUTHORIZED, "bearer token required");
            }
            let raw = match read_body_limited(request).await {
                Ok(v) => v,
                Err(response) => return response,
            };
            return match create_payment(&state, &raw).await {
                Ok(value) => json_response(StatusCode::CREATED, &value),
                Err(e) => {
                    let _ = state.security.log_event(
                        "payment.create.rejected",
                        "rejected",
                        None,
                        &e.to_string(),
                    );
                    json_response(StatusCode::BAD_REQUEST, &json!({"error": e.to_string()}))
                }
            };
        }
        return text_response(StatusCode::METHOD_NOT_ALLOWED, "method not allowed");
    }
    if let Some(id) = path.strip_prefix("/api/payments/") {
        if let Some(payment_id) = id.strip_suffix("/capture") {
            if method != Method::POST {
                return text_response(StatusCode::METHOD_NOT_ALLOWED, "method not allowed");
            }
            if !authorized(&state, &request, peer) {
                return text_response(StatusCode::UNAUTHORIZED, "bearer token required");
            }
            return match capture_payment(&state, payment_id).await {
                Ok(value) => json_response(StatusCode::OK, &value),
                Err(e) => {
                    let _ = state.security.log_event(
                        "capture.rejected",
                        "rejected",
                        Some(payment_id),
                        &e.to_string(),
                    );
                    json_response(StatusCode::BAD_REQUEST, &json!({"error": e.to_string()}))
                }
            };
        }
        if method == Method::GET && !id.is_empty() && !id.contains('/') {
            if !authorized(&state, &request, peer) {
                return text_response(StatusCode::UNAUTHORIZED, "bearer token required");
            }
            let intent = state.book.payment_intent(id);
            if !matches!(&intent, Ok(value) if value.merchant_id == state.merchant_id) {
                return text_response(StatusCode::NOT_FOUND, "payment not found");
            }
            let payment_state = state.book.state(id);
            let order = state.book.paypal_order_id(id);
            let order_status = state.book.order_status(id);
            let evidence = evidence_json(&state, id);
            return match (intent, payment_state, order, order_status, evidence) {
                (Ok(intent), Ok(payment_state), Ok(order), Ok(order_status), Ok(evidence)) => {
                    let capture = match evidence
                        .as_ref()
                        .and_then(|record| record.get("capture_id"))
                        .and_then(Value::as_str)
                    {
                        Some(capture_id) => match state.book.capture_details(capture_id) {
                            Ok(record) => record,
                            Err(_) => {
                                return json_response(
                                    StatusCode::INTERNAL_SERVER_ERROR,
                                    &json!({"error":"payment reconciliation lookup failed"}),
                                )
                            }
                        },
                        None => None,
                    };
                    json_response(
                        StatusCode::OK,
                        &json!({"intent": intent, "state": format!("{payment_state:?}"),
                                "paypal_order_id": order,
                                "paypal_order_status": order_status,
                                "evidence": evidence, "capture": capture}),
                    )
                }
                (Err(e), ..) => {
                    json_response(StatusCode::NOT_FOUND, &json!({"error": e.to_string()}))
                }
                _ => json_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &json!({"error":"lookup failed"}),
                ),
            };
        }
    }
    if path == "/api/disputes" && method == Method::GET {
        if !authorized(&state, &request, peer) {
            return text_response(StatusCode::UNAUTHORIZED, "bearer token required");
        }
        return match state.book.list_dispute_events(&state.merchant_id) {
            Ok(disputes) => json_response(StatusCode::OK, &json!({"disputes":disputes})),
            Err(error) => handler_error(error),
        };
    }
    if path == "/api/events" && method == Method::GET {
        if !authorized(&state, &request, peer) {
            return text_response(StatusCode::UNAUTHORIZED, "bearer token required");
        }
        return match state.security.recent_events(100) {
            Ok(events) => json_response(StatusCode::OK, &json!(events)),
            Err(e) => json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &json!({"error":e.to_string()}),
            ),
        };
    }
    if path == "/api/audit/verify" && method == Method::GET {
        if !authorized(&state, &request, peer) {
            return text_response(StatusCode::UNAUTHORIZED, "bearer token required");
        }
        return match state.security.verify_event_chain() {
            Ok(entries) => json_response(
                StatusCode::OK,
                &json!({"verified": true, "entries": entries}),
            ),
            Err(e) => json_response(
                StatusCode::UNPROCESSABLE_ENTITY,
                &json!({"verified": false, "error": e.to_string()}),
            ),
        };
    }
    if path == "/api/keys" && method == Method::GET {
        if !authorized(&state, &request, peer) {
            return text_response(StatusCode::UNAUTHORIZED, "bearer token required");
        }
        return match state.keys.public_keys() {
            Ok(keys) => json_response(StatusCode::OK, &json!(keys)),
            Err(e) => json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &json!({"error":e.to_string()}),
            ),
        };
    }
    if path == "/api/evidence" && method == Method::GET {
        if !authorized(&state, &request, peer) {
            return text_response(StatusCode::UNAUTHORIZED, "bearer token required");
        }
        return match state.security.export_all_evidence() {
            Ok(records) => json_response(StatusCode::OK, &json!(records)),
            Err(e) => json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &json!({"error":e.to_string()}),
            ),
        };
    }
    if path == "/api/evidence/verify-chain" && method == Method::GET {
        if !authorized(&state, &request, peer) {
            return text_response(StatusCode::UNAUTHORIZED, "bearer token required");
        }
        return match state.security.export_all_evidence() {
            Ok(records) if records.is_empty() => json_response(
                StatusCode::OK,
                &json!({"tested":false,"verified":false,"status":"no_evidence","records":0}),
            ),
            Ok(records) => match crate::payment_security::verify_evidence_chain(&records) {
                Ok(()) => json_response(
                    StatusCode::OK,
                    &json!({"tested":true,"verified":true,"status":"verified","records":records.len()}),
                ),
                Err(error) => json_response(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    &json!({"tested":true,"verified":false,"status":"failed","records":records.len(),"error":error.to_string()}),
                ),
            },
            Err(_) => json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &json!({"tested":false,"verified":false,"status":"unavailable","error":"evidence store unavailable"}),
            ),
        };
    }
    if path == "/api/evidence/verify" && method == Method::POST {
        if !authorized(&state, &request, peer) {
            return text_response(StatusCode::UNAUTHORIZED, "bearer token required");
        }
        let raw = match read_body_limited(request).await {
            Ok(v) => v,
            Err(response) => return response,
        };
        return match serde_json::from_slice::<crate::payment_security::EvidenceRecord>(&raw)
            .map_err(anyhow::Error::from)
            .and_then(|record| verify_evidence(&record).map(|_| record))
        {
            Ok(record) => json_response(
                StatusCode::OK,
                &json!({
                    "verified": true, "payment_id": record.payment_id, "chain_hash": record.chain_hash
                }),
            ),
            Err(e) => json_response(
                StatusCode::UNPROCESSABLE_ENTITY,
                &json!({
                    "verified": false, "error": e.to_string()
                }),
            ),
        };
    }
    if path == "/api/lab/run" && method == Method::POST {
        if !authorized(&state, &request, peer) {
            return text_response(StatusCode::UNAUTHORIZED, "bearer token required");
        }
        return match tokio::task::spawn_blocking(run_security_lab).await {
            Ok(Ok(results)) => {
                let passed = results.iter().filter(|r| r.passed).count();
                json_response(
                    StatusCode::OK,
                    &json!({
                        "passed": passed, "total": results.len(), "results": results
                    }),
                )
            }
            Ok(Err(e)) => json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &json!({"error":e.to_string()}),
            ),
            Err(e) => json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &json!({"error":e.to_string()}),
            ),
        };
    }
    if path == "/paypal/webhook" || path == "/api/paypal/webhooks" {
        if method != Method::POST {
            return text_response(StatusCode::METHOD_NOT_ALLOWED, "method not allowed");
        }
        let headers = match extract_webhook_headers(&request) {
            Ok(headers) => headers,
            Err(_) => {
                return text_response(
                    StatusCode::BAD_REQUEST,
                    "missing PayPal transmission headers",
                )
            }
        };
        let raw = match read_body_limited(request).await {
            Ok(v) => v,
            Err(response) => return response,
        };
        return match handle_webhook(&state, &raw, headers).await {
            Ok(value) => json_response(StatusCode::OK, &value),
            Err(e) => {
                let status = external_error_status(&e);
                let _ =
                    state
                        .security
                        .log_event("webhook.rejected", "rejected", None, &e.to_string());
                json_response(status, &json!({"error": e.to_string()}))
            }
        };
    }
    text_response(StatusCode::NOT_FOUND, "not found")
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut terminate = signal(SignalKind::terminate()).expect("register SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            _ = terminate.recv() => {},
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

pub async fn serve(listen: SocketAddr, allow_public: bool) -> Result<()> {
    let token = std::env::var("QS_API_TOKEN")
        .ok()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!("QS_API_TOKEN is required; generate one with: openssl rand -hex 32")
        })?;
    if token.len() < 32 {
        eprintln!("warning: QS_API_TOKEN is shorter than 32 characters");
    }
    if !listen.ip().is_loopback() && !allow_public {
        bail!("non-loopback listener requires --allow-public-listener");
    }

    let merchant_id = std::env::var("QS_MERCHANT_ID")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!("QS_MERCHANT_ID is required; configure the merchant tenant explicitly")
        })?;
    if !merchant_id
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        bail!("QS_MERCHANT_ID contains invalid characters");
    }
    let book = SqlitePaymentBook::open_default()?;
    let security = SecurityStore::open_default()?;
    let key_dir = std::env::var_os("QS_KEY_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            std::path::PathBuf::from(std::env::var_os("HOME").unwrap_or_else(|| ".".into()))
                .join(".local/state/quantum-shield/payment-pq-keys")
        });
    let key_id = std::env::var("QS_KEY_ID").unwrap_or_else(|_| "payment-key-1".to_owned());
    let keys = CryptoKeys::open_or_create(&key_dir, &key_id)?;
    let (paypal, paypal_error) = match PayPalSandbox::from_environment() {
        Ok(client) => (Some(client), None),
        Err(e) => (None, Some(e.to_string())),
    };
    let webhook_id = std::env::var("PAYPAL_WEBHOOK_ID")
        .ok()
        .filter(|value| !value.trim().is_empty());
    let state = Arc::new(ApiState {
        book,
        security,
        keys,
        paypal,
        paypal_error,
        webhook_id,
        rate_limiter: RateLimiter::default(),
        started_at: now()?,
        api_token: Some(token),
        merchant_id,
        paypal_config_path: std::env::var_os("QS_PAYPAL_CONFIG")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| key_dir.join("paypal-sandbox.enc")),
        paypal_runtime: tokio::sync::RwLock::new((None, None, None)),
    });
    if state.paypal_config_path.exists() {
        match load_paypal_config(&state.paypal_config_path, &state.keys).and_then(|config| {
            let webhook_id = (!config.webhook_id.is_empty()).then(|| config.webhook_id.clone());
            PayPalSandbox::new(
                config.client_id,
                config.client_secret,
                crate::paypal::PayPalEnvironment::Sandbox,
            )
            .map(|client| (client, webhook_id))
        }) {
            Ok((client, webhook_id)) => {
                *state.paypal_runtime.write().await = (Some(client), None, webhook_id);
            }
            Err(_) => {
                let _ = state.security.log_event(
                    "paypal.config.load.failed",
                    "rejected",
                    None,
                    "Saved encrypted Sandbox PayPal configuration could not be loaded",
                );
            }
        }
    }
    state.security.log_event(
        "service.started",
        "info",
        None,
        "Payment API and dashboard started",
    )?;

    let listener = TcpListener::bind(listen)
        .await
        .with_context(|| format!("cannot bind payment API on {listen}"))?;
    println!("Quantum Shield PayPal API listening on http://{listen}");
    println!("Health:    GET  http://{listen}/health");
    println!("PayPal:    GET  http://{listen}/api/paypal/status");
    println!("Webhook:   POST http://{listen}/api/paypal/webhooks");
    if state.paypal.is_none() {
        println!(
            "PayPal is NOT configured; PayPal endpoints will refuse to call PayPal instead of simulating payment."
        );
    }
    if state.webhook_id.is_none() {
        println!("PAYPAL_WEBHOOK_ID is not configured; webhook verification will refuse requests.");
    }
    let mut tasks = tokio::task::JoinSet::new();
    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {},
            accepted = listener.accept() => {
        let (stream, peer) = accepted?;
        let state = Arc::clone(&state);
        let peer_ip = peer.ip();
        tasks.spawn(async move {
            let service = service_fn(move |request| {
                let state = Arc::clone(&state);
                async move {
                    let response =
                        match tokio::time::timeout(HANDLER_TIMEOUT, route(state, request, peer_ip))
                            .await
                        {
                            Ok(response) => response,
                            Err(_) => text_response(
                                StatusCode::GATEWAY_TIMEOUT,
                                "request exceeded the 60 second handler limit",
                            ),
                        };
                    Ok::<_, Infallible>(response)
                }
            });
            let mut builder = hyper::server::conn::http1::Builder::new();
            builder
                .keep_alive(false)
                .max_headers(64)
                .max_buf_size(64 * 1024);
            if let Err(error) = builder
                .serve_connection(TokioIo::new(stream), service)
                .await
            {
                eprintln!("payment API connection error from {peer}: {error}");
            }
        });
            }
        }
    }
    println!("Shutdown requested; draining active payment API requests.");
    let drained = tokio::time::timeout(Duration::from_secs(30), async {
        while tasks.join_next().await.is_some() {}
    })
    .await;
    if drained.is_err() {
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
        eprintln!("Active requests exceeded the shutdown grace period and were cancelled.");
    }
    state.security.log_event(
        "service.stopped",
        "info",
        None,
        "Payment API and dashboard stopped",
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_dir(label: &str) -> std::path::PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("qs-{label}-{}-{stamp}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn test_api_state(dir: &std::path::Path) -> ApiState {
        let database = dir.join("payments.sqlite3");
        ApiState {
            book: SqlitePaymentBook::open_path(&database).unwrap(),
            security: SecurityStore::open(&database).unwrap(),
            keys: CryptoKeys::open_or_create(dir.join("keys"), "test-key-1").unwrap(),
            paypal: None,
            paypal_error: None,
            webhook_id: None,
            rate_limiter: RateLimiter::default(),
            started_at: now().unwrap(),
            api_token: None,
            merchant_id: "merchant_test".to_owned(),
            paypal_config_path: dir.join("paypal-sandbox.enc"),
            paypal_runtime: tokio::sync::RwLock::new((None, None, None)),
        }
    }

    #[test]
    fn paypal_config_is_encrypted_private_atomic_and_recovers() {
        let dir = std::env::temp_dir().join(format!(
            "qs-paypal-config-test-{}-{}",
            std::process::id(),
            now().unwrap()
        ));
        let keys = CryptoKeys::open_or_create(dir.join("keys"), "test-key-1").unwrap();
        let path = dir.join("state").join("paypal.enc");
        let first = PaypalStored {
            client_id: "judge-id".into(),
            client_secret: "unique-secret-never-plaintext".into(),
            webhook_id: "hook-1".into(),
        };
        persist_paypal_config(&path, &keys, &first).unwrap();
        let bytes = std::fs::read(&path).unwrap();
        assert!(!String::from_utf8_lossy(&bytes).contains(&first.client_secret));
        assert_eq!(
            load_paypal_config(&path, &keys).unwrap().client_secret,
            first.client_secret
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        let second = PaypalStored {
            client_id: "replacement".into(),
            client_secret: "second-secret".into(),
            webhook_id: "hook-2".into(),
        };
        persist_paypal_config(&path, &keys, &second).unwrap();
        assert_eq!(
            load_paypal_config(&path, &keys).unwrap().client_id,
            "replacement"
        );
        std::fs::write(&path, b"corrupt").unwrap();
        assert!(load_paypal_config(&path, &keys).is_err());
        remove_paypal_config_file(&path).unwrap();
        assert!(!path.exists());
        remove_paypal_config_file(&path).unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn paypal_config_requires_client_credentials_but_not_a_webhook_id() {
        for input in [
            br#"{}"#.as_slice(),
            br#"{"client_id":"x","client_secret":"","webhook_id":"h"}"#.as_slice(),
            b"not json".as_slice(),
        ] {
            assert!(parse_paypal_setup(input).is_err());
        }
        let valid_without_webhook =
            parse_paypal_setup(br#"{"client_id":"sandbox-id","client_secret":"sandbox-secret"}"#)
                .unwrap();
        assert!(valid_without_webhook.webhook_id.is_empty());
        assert!(parse_paypal_setup(
            br#"{"client_id":"sandbox-id","client_secret":"sandbox-secret","webhook_id":"bad\nvalue"}"#
        )
        .is_err());
        assert_eq!(
            crate::paypal::PayPalEnvironment::Sandbox.as_str(),
            "sandbox"
        );
    }

    #[tokio::test]
    async fn paypal_credentials_are_persisted_when_oauth_verification_fails() {
        let dir = test_dir("paypal-save-on-oauth-failure");
        let state = test_api_state(&dir);
        let client = PayPalSandbox::for_test_with_handler(Arc::new(|request| {
            assert_eq!(request.url().path(), "/v1/oauth2/token");
            Ok((
                StatusCode::UNAUTHORIZED,
                br#"{"error":"invalid_client"}"#.to_vec(),
            ))
        }))
        .unwrap();
        let stored = PaypalStored {
            client_id: "sandbox-test-client".to_owned(),
            client_secret: "sandbox-test-secret".to_owned(),
            webhook_id: String::new(),
        };

        let result = save_paypal_config_with_client(&state, stored, client)
            .await
            .unwrap();

        assert_eq!(result["credentials_saved"], true);
        assert_eq!(result["configured"], true);
        assert_eq!(result["oauth_verified"], false);
        assert_eq!(result["webhook_id_configured"], false);
        let bytes = std::fs::read(&state.paypal_config_path).unwrap();
        assert!(!String::from_utf8_lossy(&bytes).contains("sandbox-test-secret"));
        let recovered = load_paypal_config(&state.paypal_config_path, &state.keys).unwrap();
        assert_eq!(recovered.client_id, "sandbox-test-client");
        assert_eq!(recovered.client_secret, "sandbox-test-secret");
        assert!(recovered.webhook_id.is_empty());
        assert!(state.paypal_runtime.read().await.0.is_some());

        drop(state);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn payment_creation_persists_paypal_order_id_and_provider_status() {
        let dir = test_dir("paypal-order-persistence");
        let state = test_api_state(&dir);
        let order_id = "ORDERREGRESSION01";
        let client = PayPalSandbox::for_test_with_handler(Arc::new(move |request| {
            let response = match (request.method().as_str(), request.url().path()) {
                ("POST", "/v1/oauth2/token") => (
                    StatusCode::OK,
                    br#"{"access_token":"test-token","token_type":"Bearer","expires_in":3600}"#.to_vec(),
                ),
                ("POST", "/v2/checkout/orders") => (
                    StatusCode::CREATED,
                    serde_json::to_vec(&json!({
                        "id": order_id,
                        "status": "CREATED",
                        "links": [{
                            "href": "https://www.sandbox.paypal.com/checkoutnow?token=ORDERREGRESSION01",
                            "rel": "approve",
                            "method": "GET"
                        }]
                    }))?,
                ),
                _ => bail!("unexpected PayPal test request"),
            };
            Ok(response)
        }))
        .unwrap();
        *state.paypal_runtime.write().await = (Some(client), None, None);
        let request = json!({
            "id": "pay_order_status_regression",
            "merchant_id": "merchant_test",
            "amount_minor": 1299,
            "currency": "USD",
            "description": "Sandbox order status regression",
            "idempotency_key": "idem_order_status_regression"
        });

        let result = create_payment(&state, request.to_string().as_bytes())
            .await
            .unwrap();

        assert_eq!(result["paypal_order_id"], order_id);
        assert_eq!(result["paypal_order_status"], "CREATED");
        assert_eq!(
            state
                .book
                .paypal_order_id("pay_order_status_regression")
                .unwrap()
                .as_deref(),
            Some(order_id)
        );
        assert_eq!(
            state
                .book
                .order_status("pay_order_status_regression")
                .unwrap()
                .as_deref(),
            Some("CREATED")
        );
        let payments = state
            .book
            .list_payments_for_merchant("merchant_test")
            .unwrap();
        assert_eq!(payments.len(), 1);
        assert_eq!(payments[0].paypal_order_id.as_deref(), Some(order_id));
        assert_eq!(payments[0].paypal_order_status.as_deref(), Some("CREATED"));

        drop(state);
        std::fs::remove_dir_all(dir).unwrap();
    }

    fn intent() -> PaymentIntent {
        PaymentIntent {
            id: "pay_reconcile_1".into(),
            merchant_id: "merchant_reconcile".into(),
            amount_minor: 1299,
            currency: "USD".into(),
            description: "reconciliation fixture".into(),
            created_at: 1_000,
            expires_at: 1_600,
        }
    }

    fn order() -> Value {
        json!({
            "id": "ORDER1",
            "status": "COMPLETED",
            "purchase_units": [{
                "reference_id": "pay_reconcile_1",
                "custom_id": "pay_reconcile_1",
                "amount": {"currency_code": "USD", "value": "12.99"},
                "payments": {"captures": [{
                    "id": "CAP1",
                    "status": "COMPLETED",
                    "amount": {"currency_code": "USD", "value": "12.99"}
                }]}
            }]
        })
    }

    #[test]
    fn risk_engine_is_deterministic_and_rejects_suspicious_high_risk_payments() {
        let ordinary = assess_payment_risk(2500, "USD", "order 123");
        assert_eq!(ordinary.score, 0);
        assert_eq!(ordinary.action, "allow");
        let suspicious = assess_payment_risk(1_200_000, "XYZ", "stolen card test");
        assert_eq!(suspicious.action, "reject");
        assert!(suspicious.score >= 80);
        assert!(suspicious
            .reasons
            .contains(&"suspicious_payment_description"));
    }

    #[test]
    fn authoritative_order_matching_accepts_exact_binding() {
        assert!(validate_order_matches(&order(), &intent(), "CAP1").is_ok());
    }

    #[test]
    fn authoritative_order_matching_rejects_amount_currency_and_reference_mismatch() {
        let mut wrong_amount = order();
        wrong_amount["purchase_units"][0]["amount"]["value"] = json!("13.99");
        assert!(validate_order_matches(&wrong_amount, &intent(), "CAP1").is_err());

        let mut wrong_currency = order();
        wrong_currency["purchase_units"][0]["amount"]["currency_code"] = json!("EUR");
        assert!(validate_order_matches(&wrong_currency, &intent(), "CAP1").is_err());

        let mut wrong_reference = order();
        wrong_reference["purchase_units"][0]["custom_id"] = json!("pay_other");
        assert!(validate_order_matches(&wrong_reference, &intent(), "CAP1").is_err());

        let mut wrong_capture = order();
        wrong_capture["purchase_units"][0]["payments"]["captures"][0]["id"] = json!("CAP2");
        assert!(validate_order_matches(&wrong_capture, &intent(), "CAP1").is_err());

        let mut wrong_status = order();
        wrong_status["purchase_units"][0]["payments"]["captures"][0]["status"] = json!("PENDING");
        assert!(validate_order_matches(&wrong_status, &intent(), "CAP1").is_err());
    }

    #[test]
    fn constant_time_comparison_is_length_safe() {
        assert!(constant_time_eq(b"token", b"token"));
        assert!(!constant_time_eq(b"token", b"token2"));
        assert!(!constant_time_eq(b"token", b"tokem"));
    }

    #[test]
    fn bearer_authentication_fails_closed_without_configured_token() {
        assert!(!bearer_token_matches(None, Some("anything")));
        assert!(!bearer_token_matches(Some("expected"), None));
        assert!(!bearer_token_matches(Some("expected"), Some("wrong")));
        assert!(bearer_token_matches(Some("expected"), Some("expected")));
    }

    #[test]
    fn rate_limiter_returns_retry_after_and_recovers_after_the_window() {
        let limiter = RateLimiter::default();
        let window = Duration::from_millis(40);
        assert!(limiter.check("peer:test", 2, window).is_ok());
        assert!(limiter.check("peer:test", 2, window).is_ok());
        let retry = limiter.check("peer:test", 2, window).unwrap_err();
        assert!(retry >= 1);
        std::thread::sleep(Duration::from_millis(60));
        assert!(limiter.check("peer:test", 2, window).is_ok());
    }

    #[test]
    fn paypal_money_values_are_parsed_strictly() {
        assert_eq!(parse_money_value("12.99").unwrap(), 1299);
        assert_eq!(parse_money_value("1.00").unwrap(), 100);
        assert!(parse_money_value("1").is_err());
        assert!(parse_money_value("1.0").is_err());
        assert!(parse_money_value("1.000").is_err());
        assert!(parse_money_value("-1.00").is_err());
        assert!(parse_money_value("0.00").is_err());
    }

    #[test]
    fn authoritative_refund_id_accepts_exact_match() {
        let refund = json!({"id": "REFUND123"});
        assert!(validate_authoritative_refund_id("REFUND123", &refund).is_ok());
    }

    #[test]
    fn authoritative_refund_id_rejects_missing_id() {
        let refund = json!({"status": "COMPLETED"});
        assert!(validate_authoritative_refund_id("REFUND123", &refund).is_err());
    }

    #[test]
    fn authoritative_refund_id_rejects_mismatch() {
        let refund = json!({"id": "REFUND999"});
        assert!(validate_authoritative_refund_id("REFUND123", &refund).is_err());
    }

    #[test]
    fn refund_capture_id_is_read_from_authoritative_fields() {
        let supplementary = json!({
            "supplementary_data": {"related_ids": {"capture_id": "CAPRELATED001"}}
        });
        assert_eq!(
            capture_id_from_refund(&supplementary).unwrap(),
            "CAPRELATED001"
        );

        let linked = json!({
            "links": [
                {"rel": "self", "href": "https://api-m.sandbox.paypal.com/v2/payments/refunds/REF1"},
                {"rel": "up", "href": "https://api-m.sandbox.paypal.com/v2/payments/captures/CAPLINKED001"}
            ]
        });
        assert_eq!(capture_id_from_refund(&linked).unwrap(), "CAPLINKED001");
        assert!(capture_id_from_refund(&json!({"links": []})).is_err());
    }

    #[test]
    fn idempotency_keys_must_agree_between_body_and_header() {
        assert_eq!(
            choose_idempotency_key(Some("idem_1"), Some("idem_1"))
                .unwrap()
                .as_deref(),
            Some("idem_1")
        );
        assert!(choose_idempotency_key(Some("idem_1"), Some("idem_2")).is_err());
        assert!(choose_idempotency_key(Some("bad key"), None).is_err());
        assert_eq!(choose_idempotency_key(None, None).unwrap(), None);
    }

    #[test]
    fn external_errors_map_to_stable_http_statuses() {
        assert_eq!(
            external_error_status(&anyhow::anyhow!("PayPal is not configured")),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            external_error_status(&anyhow::anyhow!("PAYPAL_WEBHOOK_ID is not configured")),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            external_error_status(&anyhow::anyhow!("PayPal create-order failed with HTTP 422")),
            StatusCode::BAD_GATEWAY
        );
        assert_eq!(
            external_error_status(&anyhow::anyhow!("capture not found locally")),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            external_error_status(&anyhow::anyhow!("invalid refund request JSON")),
            StatusCode::BAD_REQUEST
        );
    }

    #[test]
    fn health_diagnostics_check_storage_and_fail_closed_for_unavailable_controls() {
        let dir = std::env::temp_dir().join(format!(
            "qs-health-test-{}-{}",
            std::process::id(),
            now().unwrap()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let book = SqlitePaymentBook::open_path(dir.join("payments.sqlite")).unwrap();

        assert!(database_is_available(&book, "merchant_health"));
        assert_eq!(health_status(true, true), "ok");
        assert_eq!(health_status(false, true), "degraded");
        assert_eq!(health_status(true, false), "degraded");
        assert_eq!(health_status(false, false), "degraded");

        drop(book);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
