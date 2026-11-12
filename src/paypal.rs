//! Official PayPal REST API client used by the payment gateway.
//!
//! All endpoints, request fields and authentication behaviour in this module
//! follow PayPal's documented REST API:
//! - OAuth 2.0 client credentials: `POST /v1/oauth2/token`
//! - Orders v2: `POST /v2/checkout/orders`, `GET /v2/checkout/orders/{id}`,
//!   `POST /v2/checkout/orders/{id}/capture`
//! - Payments v2: `GET /v2/payments/captures/{id}`,
//!   `POST /v2/payments/captures/{id}/refund`,
//!   `GET /v2/payments/refunds/{id}`
//! - Webhooks: `POST /v1/notifications/verify-webhook-signature`
//!
//! The client never logs or serializes the client secret or access token.

use anyhow::{bail, Context, Result};
use reqwest::{Client, Method, RequestBuilder, Response, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    fmt,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;
use zeroize::Zeroizing;

type RequestHandler = Arc<dyn Fn(reqwest::Request) -> Result<(StatusCode, Vec<u8>)> + Send + Sync>;

pub const SANDBOX_BASE: &str = "https://api-m.sandbox.paypal.com";
pub const LIVE_BASE: &str = "https://api-m.paypal.com";
pub const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const TOKEN_REFRESH_MARGIN: Duration = Duration::from_secs(60);
const MAX_REQUEST_ID: usize = 108;

/// PayPal API environment. Sandbox is the default so that an operator who
/// forgets `PAYPAL_ENVIRONMENT` cannot accidentally reach the live API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PayPalEnvironment {
    Sandbox,
    Live,
}

impl PayPalEnvironment {
    pub fn from_environment_value(value: Option<&str>) -> Result<Self> {
        match value.map(str::trim) {
            None | Some("") => Ok(Self::Sandbox),
            Some(v) if v.eq_ignore_ascii_case("sandbox") => Ok(Self::Sandbox),
            Some(v) if v.eq_ignore_ascii_case("live") => Ok(Self::Live),
            Some(_) => bail!("PAYPAL_ENVIRONMENT must be either sandbox or live"),
        }
    }

    pub fn from_environment() -> Result<Self> {
        let value = std::env::var("PAYPAL_ENVIRONMENT").ok();
        Self::from_environment_value(value.as_deref())
    }

    pub fn base_url(self) -> &'static str {
        match self {
            Self::Sandbox => SANDBOX_BASE,
            Self::Live => LIVE_BASE,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sandbox => "sandbox",
            Self::Live => "live",
        }
    }
}

impl fmt::Display for PayPalEnvironment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

struct CachedToken {
    access_token: Zeroizing<String>,
    expires_at: Instant,
}

impl CachedToken {
    fn is_fresh(&self) -> bool {
        Instant::now() + TOKEN_REFRESH_MARGIN < self.expires_at
    }
}

struct Inner {
    client: Client,
    base_url: String,
    environment: PayPalEnvironment,
    client_id: String,
    client_secret: Zeroizing<String>,
    token: Mutex<Option<CachedToken>>,
    request_handler: Option<RequestHandler>,
}

/// Cloneable PayPal REST client. Cloning shares the cached OAuth token.
#[derive(Clone)]
pub struct PayPalClient {
    inner: Arc<Inner>,
}

/// Previous name retained for the existing CLI wiring.
pub type PayPalSandbox = PayPalClient;

#[derive(Debug, Serialize)]
pub struct Connectivity {
    pub environment: &'static str,
    pub api_base: &'static str,
    pub oauth_token_acquired: bool,
}

#[derive(Debug, Deserialize)]
struct OAuthResponse {
    access_token: String,
    #[serde(default)]
    token_type: String,
    expires_in: u64,
}

#[derive(Debug, Serialize)]
struct CreateOrderRequest {
    intent: &'static str,
    purchase_units: Vec<PurchaseUnit>,
}

#[derive(Debug, Serialize)]
struct PurchaseUnit {
    reference_id: String,
    custom_id: String,
    description: String,
    amount: OrderAmount,
}

#[derive(Debug, Serialize)]
struct OrderAmount {
    currency_code: String,
    value: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CreatedOrder {
    pub id: String,
    pub status: String,
    #[serde(default)]
    pub links: Vec<OrderLink>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct OrderLink {
    pub href: String,
    pub rel: String,
    #[serde(default)]
    pub method: String,
}

/// Maximum length accepted for a buyer approval URL returned by PayPal.
pub const MAX_APPROVAL_URL_LEN: usize = 4096;

impl CreatedOrder {
    /// Return PayPal's buyer approval URL, if the response contains a valid
    /// `approve` or `payer-action` link.
    ///
    /// Approval links are only displayed for the buyer. Following the link is
    /// not proof of payment; the order must still be captured and verified.
    pub fn approval_url(&self) -> Option<&str> {
        approval_url(&self.links)
    }
}

/// Extract a safe buyer approval URL from PayPal order links.
///
/// PayPal normally returns `rel: "approve"` or, on newer checkout flows,
/// `rel: "payer-action"`. Links without a valid absolute HTTPS URL are ignored.
pub fn approval_url(links: &[OrderLink]) -> Option<&str> {
    links
        .iter()
        .filter(|link| {
            link.rel.eq_ignore_ascii_case("approve")
                || link.rel.eq_ignore_ascii_case("payer-action")
        })
        .find_map(|link| {
            let href = link.href.as_str();
            let valid = href.len() > "https://".len()
                && href.len() <= MAX_APPROVAL_URL_LEN
                && href.starts_with("https://")
                && !href
                    .bytes()
                    .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace());
            valid.then_some(href)
        })
}

impl PayPalClient {
    /// Construct a client from `PAYPAL_CLIENT_ID`, `PAYPAL_CLIENT_SECRET` and
    /// the optional `PAYPAL_ENVIRONMENT` (Sandbox by default).
    pub fn from_environment() -> Result<Self> {
        let environment = PayPalEnvironment::from_environment()?;
        let client_id = std::env::var("PAYPAL_CLIENT_ID").context("PAYPAL_CLIENT_ID is not set")?;
        let client_secret =
            std::env::var("PAYPAL_CLIENT_SECRET").context("PAYPAL_CLIENT_SECRET is not set")?;
        Self::new(client_id, client_secret, environment)
    }

    /// Construct a client explicitly. Used by tests and by callers that load
    /// credentials from a secret manager rather than the process environment.
    pub fn new(
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        environment: PayPalEnvironment,
    ) -> Result<Self> {
        let client_id = client_id.into();
        let client_secret = client_secret.into();
        Self::build(
            client_id,
            client_secret,
            environment,
            environment.base_url().to_owned(),
            true,
            None,
        )
    }

    fn build(
        client_id: String,
        client_secret: String,
        environment: PayPalEnvironment,
        base_url: String,
        https_only: bool,
        request_handler: Option<RequestHandler>,
    ) -> Result<Self> {
        let client_id = client_id.trim().to_owned();
        let client_secret = client_secret.trim().to_owned();
        if client_id.is_empty() || client_secret.is_empty() {
            bail!("PayPal client credentials must not be empty");
        }
        if client_id.len() > 256 || client_secret.len() > 512 {
            bail!("PayPal client credentials exceed the permitted length");
        }
        if client_id.bytes().any(|b| b.is_ascii_control())
            || client_secret.bytes().any(|b| b.is_ascii_control())
        {
            bail!("PayPal client credentials contain control characters");
        }
        if !base_url.starts_with("https://")
            && !(cfg!(test) && base_url.starts_with("http://127.0.0.1:"))
        {
            bail!("PayPal API base URL must use HTTPS");
        }

        let client_builder = Client::builder()
            .https_only(https_only)
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("quantum-shield-paypal/", env!("CARGO_PKG_VERSION")));
        let client = client_builder
            .build()
            .context("could not initialize PayPal HTTPS client")?;

        Ok(Self {
            inner: Arc::new(Inner {
                client,
                base_url,
                environment,
                client_id,
                client_secret: Zeroizing::new(client_secret),
                token: Mutex::new(None),
                request_handler,
            }),
        })
    }

    #[cfg(test)]
    pub(crate) fn for_test(base_url: &str, client_id: &str, client_secret: &str) -> Result<Self> {
        Self::build(
            client_id.to_owned(),
            client_secret.to_owned(),
            PayPalEnvironment::Sandbox,
            base_url.to_owned(),
            false,
            None,
        )
    }

    #[cfg(test)]
    pub(crate) fn for_test_with_handler(handler: RequestHandler) -> Result<Self> {
        Self::build(
            "mock-client-id".to_owned(),
            "mock-client-secret".to_owned(),
            PayPalEnvironment::Sandbox,
            "http://127.0.0.1:1".to_owned(),
            false,
            Some(handler),
        )
    }

    pub fn environment(&self) -> PayPalEnvironment {
        self.inner.environment
    }

    pub fn api_base(&self) -> &str {
        &self.inner.base_url
    }

    fn endpoint(&self, path: &str) -> String {
        format!("{}{}", self.inner.base_url, path)
    }

    /// Verify credentials by obtaining a real OAuth access token. The token
    /// itself is never returned to callers of this method.
    pub async fn check_connectivity(&self) -> Result<Connectivity> {
        let _token = self.access_token(false).await?;
        Ok(Connectivity {
            environment: self.inner.environment.as_str(),
            api_base: self.inner.environment.base_url(),
            oauth_token_acquired: true,
        })
    }

    async fn fetch_access_token(&self) -> Result<CachedToken> {
        let request = self
            .inner
            .client
            .post(self.endpoint("/v1/oauth2/token"))
            .basic_auth(
                &self.inner.client_id,
                Some(self.inner.client_secret.as_str()),
            )
            .header("Accept", "application/json")
            .header("Accept-Language", "en_US")
            .form(&[("grant_type", "client_credentials")])
            .build()
            .context("could not build PayPal OAuth request")?;

        let (status, bytes) = self
            .execute_request(request)
            .await
            .context("PayPal OAuth request failed")?;
        if !status.is_success() {
            return Err(api_error("OAuth token", status, &bytes));
        }

        let token: OAuthResponse =
            serde_json::from_slice(&bytes).context("invalid PayPal OAuth response")?;
        if token.access_token.is_empty() || token.access_token.len() > 4096 {
            bail!("PayPal returned an invalid access token");
        }
        if !token.token_type.is_empty() && !token.token_type.eq_ignore_ascii_case("bearer") {
            bail!("PayPal returned an unsupported token type");
        }
        if token.expires_in == 0 || token.expires_in > 7 * 24 * 60 * 60 {
            bail!("PayPal returned an invalid token lifetime");
        }

        Ok(CachedToken {
            access_token: Zeroizing::new(token.access_token),
            expires_at: Instant::now() + Duration::from_secs(token.expires_in),
        })
    }

    async fn access_token(&self, force_refresh: bool) -> Result<Zeroizing<String>> {
        let mut cached = self.inner.token.lock().await;
        if !force_refresh {
            if let Some(token) = cached.as_ref() {
                if token.is_fresh() {
                    return Ok(token.access_token.clone());
                }
            }
        }
        let token = self.fetch_access_token().await?;
        let value = token.access_token.clone();
        *cached = Some(token);
        Ok(value)
    }

    async fn invalidate_token(&self) {
        *self.inner.token.lock().await = None;
    }

    async fn execute_request(&self, request: reqwest::Request) -> Result<(StatusCode, Vec<u8>)> {
        if let Some(handler) = &self.inner.request_handler {
            let (status, bytes) = handler(request)?;
            if bytes.len() > MAX_RESPONSE_BYTES {
                bail!("PayPal response exceeded the 1 MiB size limit");
            }
            return Ok((status, bytes));
        }
        let response = self
            .inner
            .client
            .execute(request)
            .await
            .context("PayPal HTTP transport failed")?;
        let status = response.status();
        let bytes = read_limited(response).await?;
        Ok((status, bytes))
    }

    async fn read_json(&self, status: StatusCode, bytes: &[u8], operation: &str) -> Result<Value> {
        if !status.is_success() {
            return Err(api_error(operation, status, bytes));
        }
        if bytes.is_empty() {
            return Ok(Value::Null);
        }
        serde_json::from_slice(bytes)
            .with_context(|| format!("invalid JSON in PayPal {operation} response"))
    }

    /// Send an authenticated request. `401` responses invalidate the cached
    /// token and are retried once. Transport errors and retryable HTTP statuses
    /// are retried only when the request is safe to repeat (GET) or carries a
    /// `PayPal-Request-Id` idempotency key.
    async fn send_authenticated(
        &self,
        method: Method,
        path: &str,
        body: Option<&Value>,
        request_id: Option<&str>,
        operation: &str,
    ) -> Result<Value> {
        if let Some(id) = request_id {
            validate_request_id(id)?;
        }
        let safe_to_retry = request_id.is_some() || method == Method::GET;
        let mut refreshed_after_401 = false;

        for attempt in 0u32..3 {
            let token = self.access_token(false).await?;
            let mut builder: RequestBuilder = self
                .inner
                .client
                .request(method.clone(), self.endpoint(path))
                .bearer_auth(token.as_str())
                .header("Accept", "application/json")
                .header("Accept-Language", "en_US");
            if let Some(id) = request_id {
                builder = builder.header("PayPal-Request-Id", id);
            }
            if let Some(payload) = body {
                builder = builder
                    .header("Content-Type", "application/json")
                    .json(payload);
            }

            let request = match builder.build() {
                Ok(request) => request,
                Err(error) => {
                    return Err(error)
                        .with_context(|| format!("could not build PayPal {operation} request"))
                }
            };
            let (status, bytes) = match self.execute_request(request).await {
                Ok(response) => response,
                Err(error) => {
                    if format!("{error:#}")
                        .contains("PayPal response exceeded the 1 MiB size limit")
                    {
                        return Err(error);
                    }
                    self.invalidate_token().await;
                    if safe_to_retry && attempt < 2 {
                        tokio::time::sleep(Duration::from_millis(200 * (1 << attempt))).await;
                        continue;
                    }
                    return Err(error)
                        .with_context(|| format!("PayPal {operation} request failed"));
                }
            };

            if status == StatusCode::UNAUTHORIZED && !refreshed_after_401 {
                refreshed_after_401 = true;
                self.invalidate_token().await;
                continue;
            }
            if (status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error())
                && safe_to_retry
                && attempt < 2
            {
                tokio::time::sleep(Duration::from_millis(200 * (1 << attempt))).await;
                continue;
            }
            return self.read_json(status, &bytes, operation).await;
        }

        bail!("PayPal {operation} failed after bounded retries")
    }

    /// Create an Orders v2 order. `payment_id` is used as both PayPal's
    /// `reference_id`/`custom_id` and the idempotency key when no explicit
    /// request ID is supplied.
    pub async fn create_order(
        &self,
        payment_id: &str,
        amount_minor: u64,
        currency: &str,
    ) -> Result<CreatedOrder> {
        let request_id = format!("qs-order-{payment_id}");
        self.create_order_with_request_id(payment_id, amount_minor, currency, &request_id, None)
            .await
    }

    /// Create an order with an explicit idempotency key and optional
    /// description. A repeated `PayPal-Request-Id` returns PayPal's original
    /// order instead of creating a second one.
    pub async fn create_order_with_request_id(
        &self,
        payment_id: &str,
        amount_minor: u64,
        currency: &str,
        request_id: &str,
        description: Option<&str>,
    ) -> Result<CreatedOrder> {
        validate_payment_reference(payment_id)?;
        validate_amount(amount_minor)?;
        validate_currency(currency)?;
        if let Some(description) = description {
            validate_description(description)?;
        }

        let payload = CreateOrderRequest {
            intent: "CAPTURE",
            purchase_units: vec![PurchaseUnit {
                reference_id: payment_id.to_owned(),
                custom_id: payment_id.to_owned(),
                description: description.unwrap_or("Quantum Shield payment").to_owned(),
                amount: OrderAmount {
                    currency_code: currency.to_owned(),
                    value: format_amount(amount_minor),
                },
            }],
        };

        let value = self
            .send_authenticated(
                Method::POST,
                "/v2/checkout/orders",
                Some(&serde_json::to_value(payload)?),
                Some(request_id),
                "create-order",
            )
            .await?;
        let order: CreatedOrder =
            serde_json::from_value(value).context("invalid PayPal order response")?;
        validate_order_id(&order.id)?;
        if order.status.is_empty() {
            bail!("PayPal returned an order without a status");
        }
        Ok(order)
    }

    /// `GET /v2/checkout/orders/{order_id}` — authoritative order details.
    pub async fn get_order(&self, order_id: &str) -> Result<Value> {
        validate_order_id(order_id)?;
        self.send_authenticated(
            Method::GET,
            &format!("/v2/checkout/orders/{order_id}"),
            None,
            None,
            "get-order",
        )
        .await
    }

    /// Capture an approved order with a deterministic idempotency key.
    pub async fn capture_order(&self, order_id: &str) -> Result<Value> {
        let request_id = format!("qs-capture-{order_id}");
        self.capture_order_with_request_id(order_id, &request_id)
            .await
    }

    /// Capture an approved order with an explicit idempotency key.
    pub async fn capture_order_with_request_id(
        &self,
        order_id: &str,
        request_id: &str,
    ) -> Result<Value> {
        validate_order_id(order_id)?;
        self.send_authenticated(
            Method::POST,
            &format!("/v2/checkout/orders/{order_id}/capture"),
            Some(&json!({})),
            Some(request_id),
            "capture-order",
        )
        .await
    }

    /// `GET /v2/payments/captures/{capture_id}` — authoritative capture
    /// details, including status and amount.
    pub async fn get_capture(&self, capture_id: &str) -> Result<Value> {
        validate_capture_id(capture_id)?;
        self.send_authenticated(
            Method::GET,
            &format!("/v2/payments/captures/{capture_id}"),
            None,
            None,
            "get-capture",
        )
        .await
    }

    /// `POST /v2/payments/captures/{capture_id}/refund`.
    ///
    /// `amount_minor` may be `None` for a full refund. A partial refund sends
    /// PayPal's documented `amount` object. The request is idempotent through
    /// `PayPal-Request-Id`.
    pub async fn refund_capture(
        &self,
        capture_id: &str,
        amount_minor: Option<u64>,
        currency: &str,
        request_id: &str,
    ) -> Result<Value> {
        validate_capture_id(capture_id)?;
        if let Some(amount) = amount_minor {
            validate_amount(amount)?;
        }
        validate_currency(currency)?;

        let payload = match amount_minor {
            Some(amount) => json!({
                "amount": {
                    "value": format_amount(amount),
                    "currency_code": currency
                }
            }),
            None => json!({}),
        };

        self.send_authenticated(
            Method::POST,
            &format!("/v2/payments/captures/{capture_id}/refund"),
            Some(&payload),
            Some(request_id),
            "refund-capture",
        )
        .await
    }

    /// `GET /v2/payments/refunds/{refund_id}` — authoritative refund status.
    pub async fn get_refund(&self, refund_id: &str) -> Result<Value> {
        validate_refund_id(refund_id)?;
        self.send_authenticated(
            Method::GET,
            &format!("/v2/payments/refunds/{refund_id}"),
            None,
            None,
            "get-refund",
        )
        .await
    }

    /// Verify a webhook signature through PayPal's official verification API.
    /// The certificate URL is forwarded only to PayPal and is never fetched by
    /// this process.
    pub async fn verify_webhook_signature(
        &self,
        webhook_id: &str,
        headers: &WebhookHeaders,
        event: &Value,
    ) -> Result<()> {
        if webhook_id.trim().is_empty() || webhook_id.len() > 256 {
            bail!("PAYPAL_WEBHOOK_ID is missing or invalid");
        }
        headers.validate()?;

        let payload = json!({
            "auth_algo": headers.auth_algo,
            "cert_url": headers.cert_url,
            "transmission_id": headers.transmission_id,
            "transmission_sig": headers.transmission_sig,
            "transmission_time": headers.transmission_time,
            "webhook_id": webhook_id,
            "webhook_event": event
        });

        let result = self
            .send_authenticated(
                Method::POST,
                "/v1/notifications/verify-webhook-signature",
                Some(&payload),
                None,
                "verify-webhook-signature",
            )
            .await?;

        if result.get("verification_status").and_then(Value::as_str) != Some("SUCCESS") {
            bail!("PayPal did not verify the webhook signature");
        }
        Ok(())
    }
}

async fn read_limited(mut response: Response) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        match response.chunk().await {
            Ok(Some(chunk)) => {
                if out.len() + chunk.len() > MAX_RESPONSE_BYTES {
                    bail!("PayPal response exceeded the 1 MiB size limit");
                }
                out.extend_from_slice(&chunk);
            }
            Ok(None) => break,
            Err(error) => return Err(error).context("could not read PayPal response body"),
        }
    }
    Ok(out)
}

fn api_error(operation: &str, status: StatusCode, bytes: &[u8]) -> anyhow::Error {
    let parsed: Value = serde_json::from_slice(bytes).unwrap_or(Value::Null);
    let name = safe_field(parsed.get("name").and_then(Value::as_str), 80);
    let message = safe_field(parsed.get("message").and_then(Value::as_str), 300);
    let issue = parsed
        .pointer("/details/0/issue")
        .and_then(Value::as_str)
        .map(|value| safe_field(Some(value), 80))
        .unwrap_or_default();
    let debug_id = safe_field(parsed.get("debug_id").and_then(Value::as_str), 80);

    let mut text = format!("PayPal {operation} failed with HTTP {}", status.as_u16());
    if !name.is_empty() {
        text.push_str(&format!(" ({name})"));
    }
    if !message.is_empty() {
        text.push_str(&format!(": {message}"));
    }
    if !issue.is_empty() {
        text.push_str(&format!(" [issue: {issue}]"));
    }
    if !debug_id.is_empty() {
        text.push_str(&format!(" [debug_id: {debug_id}]"));
    }
    anyhow::anyhow!(text)
}

fn safe_field(value: Option<&str>, max: usize) -> String {
    value
        .unwrap_or_default()
        .chars()
        .filter(|c| !c.is_control())
        .take(max)
        .collect()
}

pub fn format_amount(amount_minor: u64) -> String {
    format!("{}.{:02}", amount_minor / 100, amount_minor % 100)
}

pub fn validate_amount(amount_minor: u64) -> Result<()> {
    if amount_minor == 0 || amount_minor > crate::payments::MAX_AMOUNT_MINOR {
        bail!("payment amount is outside the permitted range");
    }
    Ok(())
}

pub fn validate_currency(currency: &str) -> Result<()> {
    if currency.len() != 3 || !currency.bytes().all(|b| b.is_ascii_uppercase()) {
        bail!("currency must be a three-letter uppercase ISO currency code");
    }
    Ok(())
}

pub fn validate_payment_reference(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        bail!("invalid payment reference");
    }
    Ok(())
}

pub fn validate_order_id(value: &str) -> Result<()> {
    validate_provider_id(value, "PayPal order ID")
}

pub fn validate_capture_id(value: &str) -> Result<()> {
    validate_provider_id(value, "PayPal capture ID")
}

pub fn validate_refund_id(value: &str) -> Result<()> {
    validate_provider_id(value, "PayPal refund ID")
}

fn validate_provider_id(value: &str, label: &str) -> Result<()> {
    if value.is_empty() || value.len() > 64 || !value.bytes().all(|b| b.is_ascii_alphanumeric()) {
        bail!("invalid {label}");
    }
    Ok(())
}

pub fn validate_request_id(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_REQUEST_ID
        || value
            .bytes()
            .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
    {
        bail!("invalid PayPal idempotency request ID");
    }
    Ok(())
}

pub fn validate_description(value: &str) -> Result<()> {
    if value.is_empty() || value.len() > 127 || value.chars().any(char::is_control) {
        bail!("invalid payment description");
    }
    Ok(())
}

/// PayPal transmission headers required by its signature-verification API.
#[derive(Debug, Clone)]
pub struct WebhookHeaders {
    pub auth_algo: String,
    pub cert_url: String,
    pub transmission_id: String,
    pub transmission_sig: String,
    pub transmission_time: String,
}

impl WebhookHeaders {
    pub fn validate(&self) -> Result<()> {
        for (name, value, max) in [
            ("auth_algo", &self.auth_algo, 128usize),
            ("cert_url", &self.cert_url, 2048usize),
            ("transmission_id", &self.transmission_id, 128usize),
            ("transmission_sig", &self.transmission_sig, 2048usize),
            ("transmission_time", &self.transmission_time, 128usize),
        ] {
            if value.is_empty() || value.len() > max || value.bytes().any(|b| b.is_ascii_control())
            {
                bail!("invalid PayPal webhook header: {name}");
            }
        }
        if !self.cert_url.starts_with("https://") {
            bail!("PayPal certificate URL must use HTTPS");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use http_body_util::{BodyExt, Full};
    use hyper::{body::Incoming, service::service_fn, Request, Response, StatusCode as MockStatus};
    use hyper_util::rt::TokioIo;
    use std::{
        collections::HashMap,
        convert::Infallible,
        sync::{
            atomic::{AtomicBool, AtomicUsize, Ordering},
            Arc, Mutex, OnceLock,
        },
    };
    use tokio::{
        io::{AsyncRead, AsyncWrite},
        net::TcpListener,
    };

    #[derive(Debug, Clone)]
    struct RecordedRequest {
        method: String,
        path: String,
        request_id: Option<String>,
        authorization: Option<String>,
        body: Vec<u8>,
    }

    struct MockConfig {
        token_calls: AtomicUsize,
        fail_first_data_401: AtomicBool,
        fail_auth: AtomicBool,
        api_error: AtomicBool,
        retryable_server_failures: AtomicUsize,
        webhook_success: AtomicBool,
    }

    struct MockFixture {
        config: Arc<MockConfig>,
        requests: Arc<Mutex<Vec<RecordedRequest>>>,
    }

    static MOCK_FIXTURES: OnceLock<Mutex<HashMap<String, MockFixture>>> = OnceLock::new();
    static NEXT_MOCK: AtomicUsize = AtomicUsize::new(0);

    impl Default for MockConfig {
        fn default() -> Self {
            Self {
                token_calls: AtomicUsize::new(0),
                fail_first_data_401: AtomicBool::new(false),
                fail_auth: AtomicBool::new(false),
                api_error: AtomicBool::new(false),
                retryable_server_failures: AtomicUsize::new(0),
                webhook_success: AtomicBool::new(true),
            }
        }
    }

    async fn handle_mock_stream<S>(
        stream: S,
        config: Arc<MockConfig>,
        requests: Arc<Mutex<Vec<RecordedRequest>>>,
    ) where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let service = service_fn(move |request: Request<Incoming>| {
            let config = Arc::clone(&config);
            let requests = Arc::clone(&requests);
            async move {
                let method = request.method().as_str().to_owned();
                let path = request.uri().path().to_owned();
                let request_id = request
                    .headers()
                    .get("paypal-request-id")
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_owned);
                let authorization = request
                    .headers()
                    .get("authorization")
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_owned);
                let body = request
                    .into_body()
                    .collect()
                    .await
                    .map(|value| value.to_bytes().to_vec())
                    .unwrap_or_default();
                requests.lock().unwrap().push(RecordedRequest {
                    method: method.clone(),
                    path: path.clone(),
                    request_id,
                    authorization,
                    body,
                });
                let (status, payload) = mock_response(&config, &method, &path);
                Ok::<_, Infallible>(
                    Response::builder()
                        .status(status)
                        .header("content-type", "application/json")
                        .body(Full::new(Bytes::from(payload)))
                        .expect("mock response"),
                )
            }
        });
        let _ = hyper::server::conn::http1::Builder::new()
            .serve_connection(TokioIo::new(stream), service)
            .await;
    }

    async fn start_mock() -> (String, Arc<MockConfig>, Arc<Mutex<Vec<RecordedRequest>>>) {
        let config = Arc::new(MockConfig::default());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let server_config = Arc::clone(&config);
        let server_requests = Arc::clone(&requests);
        if let Ok(listener) = TcpListener::bind("127.0.0.1:0").await {
            let addr = listener.local_addr().unwrap();
            tokio::spawn(async move {
                loop {
                    let Ok((stream, _)) = listener.accept().await else {
                        break;
                    };
                    tokio::spawn(handle_mock_stream(
                        stream,
                        Arc::clone(&server_config),
                        Arc::clone(&server_requests),
                    ));
                }
            });
            return (format!("http://{addr}"), config, requests);
        }

        let id = NEXT_MOCK.fetch_add(1, Ordering::Relaxed);
        let key = format!("mock-{id}");
        MOCK_FIXTURES
            .get_or_init(|| Mutex::new(HashMap::new()))
            .lock()
            .unwrap()
            .insert(
                key.clone(),
                MockFixture {
                    config: Arc::clone(&config),
                    requests: Arc::clone(&requests),
                },
            );
        (format!("mock://{key}"), config, requests)
    }

    fn consume_mock_failure(counter: &AtomicUsize) -> bool {
        let mut remaining = counter.load(Ordering::SeqCst);
        loop {
            if remaining == 0 {
                return false;
            }
            match counter.compare_exchange_weak(
                remaining,
                remaining - 1,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => return true,
                Err(actual) => remaining = actual,
            }
        }
    }

    fn mock_response(config: &MockConfig, method: &str, path: &str) -> (MockStatus, String) {
        if path == "/v1/oauth2/token" && method == "POST" {
            if config.fail_auth.load(Ordering::SeqCst) {
                return (
                    MockStatus::UNAUTHORIZED,
                    json!({"error":"invalid_client","error_description":"mock rejected client"})
                        .to_string(),
                );
            }
            let calls = config.token_calls.fetch_add(1, Ordering::SeqCst) + 1;
            return (
                MockStatus::OK,
                json!({
                    "access_token": format!("TOKEN-{calls}"),
                    "token_type": "Bearer",
                    "expires_in": 3600
                })
                .to_string(),
            );
        }

        if config.fail_first_data_401.swap(false, Ordering::SeqCst) {
            return (
                MockStatus::UNAUTHORIZED,
                json!({"name":"AUTHENTICATION_FAILURE","message":"mock token rejected"})
                    .to_string(),
            );
        }

        if path == "/v2/checkout/orders" && consume_mock_failure(&config.retryable_server_failures)
        {
            return (
                MockStatus::SERVICE_UNAVAILABLE,
                json!({"name":"SERVICE_UNAVAILABLE","message":"retryable mock outage"}).to_string(),
            );
        }

        if config.api_error.load(Ordering::SeqCst) && path == "/v2/checkout/orders" {
            return (
                MockStatus::UNPROCESSABLE_ENTITY,
                json!({
                    "name":"UNPROCESSABLE_ENTITY",
                    "message":"mock order rejected",
                    "debug_id":"debug-123",
                    "details":[{"issue":"INVALID_PARAMETER"}]
                })
                .to_string(),
            );
        }

        match (method, path) {
            ("POST", "/v2/checkout/orders") => (
                MockStatus::CREATED,
                json!({
                    "id":"ORDER1",
                    "status":"CREATED",
                    "links":[
                        {"href":"https://sandbox.example/approve","rel":"approve","method":"GET"},
                        {"href":"https://api-m.sandbox.paypal.com/v2/checkout/orders/ORDER1","rel":"self","method":"GET"}
                    ]
                })
                .to_string(),
            ),
            ("GET", "/v2/checkout/orders/ORDER1") => (
                MockStatus::OK,
                json!({
                    "id":"ORDER1",
                    "status":"APPROVED",
                    "purchase_units":[{
                        "reference_id":"pay_test_001",
                        "custom_id":"pay_test_001",
                        "amount":{"currency_code":"USD","value":"12.99"}
                    }]
                })
                .to_string(),
            ),
            ("GET", "/v2/checkout/orders/OVERSIZE") => (
                MockStatus::OK,
                "x".repeat(MAX_RESPONSE_BYTES + 1),
            ),
            ("POST", "/v2/checkout/orders/ORDER1/capture") => (
                MockStatus::CREATED,
                json!({
                    "id":"ORDER1",
                    "status":"COMPLETED",
                    "purchase_units":[{
                        "reference_id":"pay_test_001",
                        "custom_id":"pay_test_001",
                        "amount":{"currency_code":"USD","value":"12.99"},
                        "payments":{"captures":[{
                            "id":"CAP1",
                            "status":"COMPLETED",
                            "amount":{"currency_code":"USD","value":"12.99"}
                        }]}
                    }]
                })
                .to_string(),
            ),
            ("GET", "/v2/payments/captures/CAP1") => (
                MockStatus::OK,
                json!({
                    "id":"CAP1",
                    "status":"COMPLETED",
                    "amount":{"currency_code":"USD","value":"12.99"}
                })
                .to_string(),
            ),
            ("POST", "/v2/payments/captures/CAP1/refund") => (
                MockStatus::CREATED,
                json!({
                    "id":"REF1",
                    "status":"COMPLETED",
                    "amount":{"currency_code":"USD","value":"1.00"},
                    "links":[{"rel":"up","href":"https://api-m.sandbox.paypal.com/v2/payments/captures/CAP1"}]
                })
                .to_string(),
            ),
            ("GET", "/v2/payments/refunds/REF1") => (
                MockStatus::OK,
                json!({
                    "id":"REF1",
                    "status":"COMPLETED",
                    "amount":{"currency_code":"USD","value":"1.00"},
                    "links":[{"rel":"up","href":"https://api-m.sandbox.paypal.com/v2/payments/captures/CAP1"}]
                })
                .to_string(),
            ),
            ("POST", "/v1/notifications/verify-webhook-signature") => (
                MockStatus::OK,
                json!({
                    "verification_status": if config.webhook_success.load(Ordering::SeqCst) {"SUCCESS"} else {"FAILURE"}
                })
                .to_string(),
            ),
            _ => (
                MockStatus::NOT_FOUND,
                json!({"name":"RESOURCE_NOT_FOUND","message":"mock not found"}).to_string(),
            ),
        }
    }

    fn test_client(base: &str) -> PayPalClient {
        if let Some(id) = base.strip_prefix("mock://") {
            let MockFixture { config, requests } = MOCK_FIXTURES
                .get()
                .and_then(|fixtures| fixtures.lock().ok()?.remove(id))
                .expect("registered in-process mock fixture");
            let handler = Arc::new(move |request: reqwest::Request| {
                let method = request.method().as_str().to_owned();
                let path = request.url().path().to_owned();
                let request_id = request
                    .headers()
                    .get("paypal-request-id")
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_owned);
                let authorization = request
                    .headers()
                    .get("authorization")
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_owned);
                let body = request
                    .body()
                    .and_then(reqwest::Body::as_bytes)
                    .unwrap_or_default()
                    .to_vec();
                requests.lock().unwrap().push(RecordedRequest {
                    method: method.clone(),
                    path: path.clone(),
                    request_id,
                    authorization,
                    body,
                });
                let (status, payload) = mock_response(&config, &method, &path);
                Ok((status, payload.into_bytes()))
            });
            return PayPalClient::for_test_with_handler(handler).unwrap();
        }
        PayPalClient::for_test(base, "mock-client-id", "mock-client-secret").unwrap()
    }

    fn headers() -> WebhookHeaders {
        WebhookHeaders {
            auth_algo: "SHA256withRSA".into(),
            cert_url: "https://api.paypal.com/cert.pem".into(),
            transmission_id: "transmission-1".into(),
            transmission_sig: "signature".into(),
            transmission_time: "2026-01-01T00:00:00Z".into(),
        }
    }

    #[tokio::test]
    async fn oauth_token_is_cached_between_requests() {
        let (base, config, requests) = start_mock().await;
        let client = test_client(&base);
        client.get_order("ORDER1").await.unwrap();
        client.get_order("ORDER1").await.unwrap();
        assert_eq!(config.token_calls.load(Ordering::SeqCst), 1);
        let requests = requests.lock().unwrap();
        let oauth = requests
            .iter()
            .find(|request| request.path == "/v1/oauth2/token")
            .expect("OAuth request");
        assert!(oauth
            .authorization
            .as_deref()
            .is_some_and(|value| value.starts_with("Basic ")));
        assert_eq!(oauth.body, b"grant_type=client_credentials");
        assert!(requests
            .iter()
            .filter(|request| request.path == "/v2/checkout/orders/ORDER1")
            .all(|request| request
                .authorization
                .as_deref()
                .is_some_and(|value| value.starts_with("Bearer TOKEN-"))));
    }

    #[tokio::test]
    async fn rejected_token_is_invalidated_and_refreshed_once() {
        let (base, config, _) = start_mock().await;
        let client = test_client(&base);
        config.fail_first_data_401.store(true, Ordering::SeqCst);
        let order = client.get_order("ORDER1").await.unwrap();
        assert_eq!(order["id"], "ORDER1");
        assert_eq!(config.token_calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn idempotent_order_request_retries_retryable_server_response() {
        let (base, config, requests) = start_mock().await;
        let client = test_client(&base);
        config.retryable_server_failures.store(1, Ordering::SeqCst);

        let order = client
            .create_order("pay_test_001", 1299, "USD")
            .await
            .unwrap();
        assert_eq!(order.id, "ORDER1");
        let requests = requests.lock().unwrap();
        let attempts: Vec<_> = requests
            .iter()
            .filter(|request| request.path == "/v2/checkout/orders")
            .collect();
        assert_eq!(attempts.len(), 2);
        assert!(attempts
            .iter()
            .all(|request| { request.request_id.as_deref() == Some("qs-order-pay_test_001") }));
    }

    #[tokio::test]
    async fn create_order_uses_documented_endpoint_and_idempotency() {
        let (base, _, requests) = start_mock().await;
        let client = test_client(&base);
        let order = client
            .create_order("pay_test_001", 1299, "USD")
            .await
            .unwrap();
        assert_eq!(order.id, "ORDER1");
        let requests = requests.lock().unwrap();
        let create = requests
            .iter()
            .find(|request| request.path == "/v2/checkout/orders")
            .expect("create order request");
        assert_eq!(create.method, "POST");
        assert_eq!(create.request_id.as_deref(), Some("qs-order-pay_test_001"));
        let body: Value = serde_json::from_slice(&create.body).unwrap();
        assert_eq!(body["intent"], "CAPTURE");
        assert_eq!(body["purchase_units"][0]["amount"]["currency_code"], "USD");
        assert_eq!(body["purchase_units"][0]["amount"]["value"], "12.99");
    }

    #[test]
    fn approval_url_accepts_approve_and_payer_action_links() {
        let order: CreatedOrder = serde_json::from_value(json!({
            "id":"ORDER1",
            "status":"CREATED",
            "links":[
                {"href":"https://api-m.sandbox.paypal.com/v2/checkout/orders/ORDER1","rel":"self","method":"GET"},
                {"href":"https://www.sandbox.paypal.com/checkoutnow?token=ORDER1","rel":"payer-action","method":"GET"}
            ]
        }))
        .unwrap();
        assert_eq!(
            order.approval_url(),
            Some("https://www.sandbox.paypal.com/checkoutnow?token=ORDER1")
        );

        let order: CreatedOrder = serde_json::from_value(json!({
            "id":"ORDER2",
            "status":"CREATED",
            "links":[
                {"href":"https://www.sandbox.paypal.com/checkoutnow?token=ORDER2","rel":"approve","method":"GET"}
            ]
        }))
        .unwrap();
        assert_eq!(
            order.approval_url(),
            Some("https://www.sandbox.paypal.com/checkoutnow?token=ORDER2")
        );
    }

    #[test]
    fn approval_url_ignores_missing_and_malformed_links() {
        let order: CreatedOrder = serde_json::from_value(json!({
            "id":"ORDER1",
            "status":"CREATED"
        }))
        .unwrap();
        assert_eq!(order.approval_url(), None);

        let links = vec![
            OrderLink {
                href: String::new(),
                rel: "approve".into(),
                method: "GET".into(),
            },
            OrderLink {
                href: "http://www.sandbox.paypal.com/checkoutnow?token=ORDER1".into(),
                rel: "approve".into(),
                method: "GET".into(),
            },
            OrderLink {
                href: "/checkoutnow?token=ORDER1".into(),
                rel: "payer-action".into(),
                method: "GET".into(),
            },
            OrderLink {
                href: "https://www.sandbox.paypal.com/checkout now?token=ORDER1".into(),
                rel: "approve".into(),
                method: "GET".into(),
            },
            OrderLink {
                href: "https://".into(),
                rel: "approve".into(),
                method: "GET".into(),
            },
            OrderLink {
                href: format!(
                    "https://www.sandbox.paypal.com/{}",
                    "x".repeat(MAX_APPROVAL_URL_LEN)
                ),
                rel: "approve".into(),
                method: "GET".into(),
            },
            OrderLink {
                href: "https://api-m.sandbox.paypal.com/v2/checkout/orders/ORDER1".into(),
                rel: "self".into(),
                method: "GET".into(),
            },
        ];
        assert_eq!(approval_url(&links), None);
    }

    #[test]
    fn approval_url_skips_a_malformed_link_and_uses_a_later_valid_one() {
        let links = vec![
            OrderLink {
                href: "not-a-url".into(),
                rel: "approve".into(),
                method: "GET".into(),
            },
            OrderLink {
                href: "https://www.sandbox.paypal.com/checkoutnow?token=ORDER1".into(),
                rel: "payer-action".into(),
                method: "GET".into(),
            },
        ];
        assert_eq!(
            approval_url(&links),
            Some("https://www.sandbox.paypal.com/checkoutnow?token=ORDER1")
        );
    }

    #[tokio::test]
    async fn capture_refund_and_retrieval_use_official_paths() {
        let (base, _, requests) = start_mock().await;
        let client = test_client(&base);
        let capture = client.capture_order("ORDER1").await.unwrap();
        assert_eq!(capture["status"], "COMPLETED");
        let capture_details = client.get_capture("CAP1").await.unwrap();
        assert_eq!(capture_details["id"], "CAP1");
        let refund = client
            .refund_capture("CAP1", Some(100), "USD", "refund-request-1")
            .await
            .unwrap();
        assert_eq!(refund["id"], "REF1");
        let refund_details = client.get_refund("REF1").await.unwrap();
        assert_eq!(refund_details["status"], "COMPLETED");

        let requests = requests.lock().unwrap();
        assert!(requests.iter().any(|request| {
            request.method == "POST" && request.path == "/v2/checkout/orders/ORDER1/capture"
        }));
        assert!(requests.iter().any(|request| {
            request.method == "GET" && request.path == "/v2/payments/captures/CAP1"
        }));
        let refund_request = requests
            .iter()
            .find(|request| request.path == "/v2/payments/captures/CAP1/refund")
            .expect("refund request");
        assert_eq!(
            refund_request.request_id.as_deref(),
            Some("refund-request-1")
        );
        let body: Value = serde_json::from_slice(&refund_request.body).unwrap();
        assert_eq!(body["amount"]["value"], "1.00");
        assert!(requests.iter().any(|request| {
            request.method == "GET" && request.path == "/v2/payments/refunds/REF1"
        }));
    }

    #[tokio::test]
    async fn webhook_verification_requires_paypal_success() {
        let (base, config, quests) = start_mock().await;
        let client = test_client(&base);
        let event = json!({"id":"WH-EVENT-1","event_type":"PAYMENT.CAPTURE.COMPLETED"});
        client
            .verify_webhook_signature("WEBHOOK1", &headers(), &event)
            .await
            .unwrap();
        config.webhook_success.store(false, Ordering::SeqCst);
        assert!(client
            .verify_webhook_signature("WEBHOOK1", &headers(), &event)
            .await
            .is_err());
        let quests = quests.lock().unwrap();
        assert!(quests.iter().all(|request| {
            request.path != "/v1/notifications/verify-webhook-signature" || request.method == "POST"
        }));
    }

    #[tokio::test]
    async fn invalid_amount_and_currency_fail_before_network() {
        let (base, _, requests) = start_mock().await;
        let client = test_client(&base);
        assert!(client.create_order("pay_test_001", 0, "USD").await.is_err());
        assert!(client
            .create_order("pay_test_001", 1299, "usd")
            .await
            .is_err());
        assert!(client
            .create_order("pay_test_001", 1299, "US")
            .await
            .is_err());
        assert!(requests.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn paypal_api_errors_include_issue_and_debug_id() {
        let (base, config, _) = start_mock().await;
        let client = test_client(&base);
        config.api_error.store(true, Ordering::SeqCst);
        let error = client
            .create_order("pay_test_001", 1299, "USD")
            .await
            .unwrap_err();
        let text = error.to_string();
        assert!(text.contains("UNPROCESSABLE_ENTITY"));
        assert!(text.contains("INVALID_PARAMETER"));
        assert!(text.contains("debug-123"));
        assert!(!text.contains("mock-client-secret"));
    }

    #[tokio::test]
    async fn oversized_paypal_response_is_rejected() {
        let (base, _, _) = start_mock().await;
        let client = test_client(&base);
        let error = client.get_order("OVERSIZE").await.unwrap_err();
        assert!(error.to_string().contains("1 MiB"));
    }

    #[tokio::test]
    async fn invalid_credentials_are_rejected_by_oauth() {
        let (base, config, _) = start_mock().await;
        let client = test_client(&base);
        config.fail_auth.store(true, Ordering::SeqCst);
        assert!(client.check_connectivity().await.is_err());
    }

    #[tokio::test]
    async fn network_failure_is_reported() {
        let client = test_client("http://127.0.0.1:1");
        let error = client.check_connectivity().await.unwrap_err();
        assert!(error.to_string().contains("PayPal OAuth"));
    }

    #[test]
    fn amount_and_identifier_validation_is_strict() {
        assert_eq!(format_amount(1299), "12.99");
        assert_eq!(format_amount(100), "1.00");
        assert!(validate_amount(1).is_ok());
        assert!(validate_amount(0).is_err());
        assert!(validate_currency("USD").is_ok());
        assert!(validate_currency("Usd").is_err());
        assert!(validate_order_id("5O190127TN364715T").is_ok());
        assert!(validate_order_id("bad/id").is_err());
        assert!(validate_request_id("qs-order-pay_1").is_ok());
        assert!(validate_request_id("bad request id").is_err());
    }

    #[test]
    fn sandbox_is_the_default_environment() {
        assert_eq!(
            PayPalEnvironment::from_environment_value(None).unwrap(),
            PayPalEnvironment::Sandbox
        );
        assert_eq!(
            PayPalEnvironment::from_environment_value(Some("LIVE")).unwrap(),
            PayPalEnvironment::Live
        );
        assert!(PayPalEnvironment::from_environment_value(Some("staging")).is_err());
    }
}

/// Real PayPal Sandbox network tests.
///
/// These are deliberately `#[ignore]`d so that the normal test suite never
/// contacts PayPal and never moves Sandbox money. Run them explicitly after
/// exporting `PAYPAL_CLIENT_ID`, `PAYPAL_CLIENT_SECRET` and
/// `PAYPAL_ENVIRONMENT=sandbox`:
///
/// ```text
/// cargo test --locked paypal_sandbox -- --ignored --nocapture
/// ```
///
/// Tests skip (with a clear message) when the required credentials or
/// pre-approved Sandbox resources are absent. They refuse to run against Live.
#[cfg(test)]
mod sandbox_tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn sandbox_client(test_name: &str) -> Option<PayPalClient> {
        let environment = match PayPalEnvironment::from_environment() {
            Ok(environment) => environment,
            Err(error) => {
                eprintln!("SKIP {test_name}: invalid PAYPAL_ENVIRONMENT: {error}");
                return None;
            }
        };
        if environment != PayPalEnvironment::Sandbox {
            panic!("refusing to run real Sandbox tests because PAYPAL_ENVIRONMENT={environment:?}");
        }
        match PayPalClient::from_environment() {
            Ok(client) => Some(client),
            Err(error) => {
                eprintln!(
                    "SKIP {test_name}: PayPal Sandbox credentials are not configured: {error}"
                );
                None
            }
        }
    }

    fn unique_suffix() -> String {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before Unix epoch")
            .as_millis()
            .to_string()
    }

    fn approved_order_id() -> Option<String> {
        std::env::var("PAYPAL_SANDBOX_APPROVED_ORDER_ID")
            .ok()
            .filter(|value| !value.trim().is_empty())
    }

    fn capture_id() -> Option<String> {
        std::env::var("PAYPAL_SANDBOX_CAPTURE_ID")
            .ok()
            .filter(|value| !value.trim().is_empty())
    }

    fn refund_amount_minor() -> u64 {
        std::env::var("PAYPAL_SANDBOX_REFUND_AMOUNT_MINOR")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(100)
    }

    #[tokio::test]
    #[ignore = "real PayPal Sandbox network test; requires Sandbox credentials"]
    async fn paypal_sandbox_oauth_and_connectivity() {
        let Some(client) = sandbox_client("oauth") else {
            return;
        };
        let connectivity = client.check_connectivity().await.unwrap();
        assert_eq!(connectivity.environment, "sandbox");
        assert_eq!(connectivity.api_base, SANDBOX_BASE);
        assert!(connectivity.oauth_token_acquired);
    }

    #[tokio::test]
    #[ignore = "real PayPal Sandbox network test; creates a real Sandbox order"]
    async fn paypal_sandbox_creates_and_retrieves_an_order() {
        let Some(client) = sandbox_client("create-order") else {
            return;
        };
        let payment_id = format!("qsitest{}", unique_suffix());
        let order = client
            .create_order_with_request_id(
                &payment_id,
                199,
                "USD",
                &format!("qs-it-order-{payment_id}"),
                Some("Quantum Shield Sandbox integration test"),
            )
            .await
            .unwrap();
        assert!(validate_order_id(&order.id).is_ok());
        assert!(!order.status.is_empty());

        let fetched = client.get_order(&order.id).await.unwrap();
        assert_eq!(fetched["id"], order.id);
        assert_eq!(fetched["purchase_units"][0]["custom_id"], payment_id);
        assert_eq!(
            fetched["purchase_units"][0]["amount"]["currency_code"],
            "USD"
        );
        assert_eq!(fetched["purchase_units"][0]["amount"]["value"], "1.99");
    }

    #[tokio::test]
    #[ignore = "real PayPal Sandbox network test; captures and refunds Sandbox money"]
    async fn paypal_sandbox_capture_and_refund() {
        let Some(client) = sandbox_client("capture-refund") else {
            return;
        };

        let (capture_id, expected_capture_amount) = if let Some(order_id) = approved_order_id() {
            let captured = client
                .capture_order_with_request_id(
                    &order_id,
                    &format!("qs-it-capture-{order_id}-{}", unique_suffix()),
                )
                .await
                .unwrap();
            assert_eq!(captured["status"], "COMPLETED");
            let capture_id = captured
                .pointer("/purchase_units/0/payments/captures/0/id")
                .and_then(Value::as_str)
                .expect("capture response has no capture ID")
                .to_owned();
            let capture_amount = captured
                .pointer("/purchase_units/0/payments/captures/0/amount/value")
                .and_then(Value::as_str)
                .expect("capture response has no amount")
                .to_owned();
            let order = client.get_order(&order_id).await.unwrap();
            assert_eq!(order["status"], "COMPLETED");
            (capture_id, Some(capture_amount))
        } else if let Some(capture_id) = capture_id() {
            (capture_id, None)
        } else {
            eprintln!(
                "SKIP capture-refund: set PAYPAL_SANDBOX_APPROVED_ORDER_ID (approved buyer order) \
                 or PAYPAL_SANDBOX_CAPTURE_ID (existing completed capture)"
            );
            return;
        };

        let capture = client.get_capture(&capture_id).await.unwrap();
        assert_eq!(capture["id"], capture_id);
        assert_eq!(capture["status"], "COMPLETED");
        assert_eq!(capture["amount"]["currency_code"], "USD");
        let authoritative_capture_amount = capture["amount"]["value"]
            .as_str()
            .expect("authoritative capture response has no amount");
        assert!(!authoritative_capture_amount.is_empty());
        if let Some(expected) = expected_capture_amount {
            assert_eq!(authoritative_capture_amount, expected);
        }

        let amount = refund_amount_minor();
        let refund = client
            .refund_capture(
                &capture_id,
                Some(amount),
                "USD",
                &format!("qs-it-refund-{capture_id}-{amount}-{}", unique_suffix()),
            )
            .await
            .unwrap();
        let refund_id = refund["id"].as_str().expect("refund response has no ID");
        assert!(validate_refund_id(refund_id).is_ok());

        let authoritative = client.get_refund(refund_id).await.unwrap();
        assert_eq!(authoritative["id"], refund_id);
        assert_eq!(authoritative["status"], "COMPLETED");
        assert_eq!(authoritative["amount"]["currency_code"], "USD");
        assert_eq!(authoritative["amount"]["value"], format_amount(amount));
    }

    #[tokio::test]
    #[ignore = "real PayPal Sandbox network test; requires PAYPAL_WEBHOOK_ID"]
    async fn paypal_sandbox_rejects_a_forged_webhook_signature() {
        let Some(client) = sandbox_client("forged-webhook") else {
            return;
        };
        let webhook_id = match std::env::var("PAYPAL_WEBHOOK_ID") {
            Ok(value) if !value.trim().is_empty() => value,
            _ => {
                eprintln!("SKIP forged-webhook: PAYPAL_WEBHOOK_ID is not configured");
                return;
            }
        };
        let headers = WebhookHeaders {
            auth_algo: "SHA256withRSA".into(),
            cert_url:
                "https://api.paypal.com/v1/notifications/certs/CERT-360caa42-fca2a594-1d93a270"
                    .into(),
            transmission_id: "quantum-shield-forged-transmission".into(),
            transmission_sig: "Zm9yZ2VkLXNpZ25hdHVyZQ==".into(),
            transmission_time: "2026-01-01T00:00:00Z".into(),
        };
        let event = json!({
            "id": format!("QSITEST{}", unique_suffix()),
            "event_type": "PAYMENT.CAPTURE.COMPLETED",
            "resource": {"id": "CAPFORGED001", "status": "COMPLETED"}
        });
        assert!(client
            .verify_webhook_signature(&webhook_id, &headers, &event)
            .await
            .is_err());
    }

    #[tokio::test]
    #[ignore = "real PayPal Sandbox network test; uses deliberately invalid credentials"]
    async fn paypal_sandbox_rejects_invalid_credentials() {
        let client = PayPalClient::new(
            "quantum-shield-deliberately-invalid-client-id",
            "quantum-shield-deliberately-invalid-secret",
            PayPalEnvironment::Sandbox,
        )
        .unwrap();
        assert!(client.check_connectivity().await.is_err());
    }
}
