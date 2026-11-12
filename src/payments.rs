//! Quantum Shield payment domain.
//! This module validates payment intents; it does not process or settle money.

use rusqlite::OptionalExtension;

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

pub const MAX_AMOUNT_MINOR: u64 = 100_000_000;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PaymentIntent {
    pub id: String,
    pub merchant_id: String,
    pub amount_minor: u64,
    pub currency: String,
    pub description: String,
    pub created_at: u64,
    pub expires_at: u64,
}

impl PaymentIntent {
    pub fn validate(&self, now: u64) -> Result<()> {
        if !valid_identifier(&self.id) || !valid_identifier(&self.merchant_id) {
            bail!("invalid payment or merchant identifier");
        }
        if self.amount_minor == 0 || self.amount_minor > MAX_AMOUNT_MINOR {
            bail!("payment amount is outside the permitted range");
        }
        if self.currency.len() != 3 || !self.currency.bytes().all(|b| b.is_ascii_uppercase()) {
            bail!("currency must be a three-letter uppercase ISO-style code");
        }
        if self.description.len() > 200 || self.description.chars().any(char::is_control) {
            bail!("payment description is invalid or too long");
        }
        if self.created_at > now.saturating_add(30) {
            bail!("payment intent creation time is in the future");
        }
        if self.expires_at <= self.created_at || self.expires_at <= now {
            bail!("payment intent is expired or has an invalid expiry");
        }
        if self.expires_at - self.created_at > 900 {
            bail!("payment intent lifetime cannot exceed 15 minutes");
        }
        Ok(())
    }
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PaymentState {
    Created,
    Pending,
    Authorized,
    Captured,
    Failed,
    Cancelled,
}

impl PaymentState {
    pub fn can_transition_to(self, next: Self) -> bool {
        use PaymentState::*;
        matches!(
            (self, next),
            (Created, Pending)
                | (Created, Cancelled)
                | (Pending, Authorized)
                | (Pending, Failed)
                | (Pending, Cancelled)
                | (Authorized, Captured)
                | (Authorized, Failed)
                | (Authorized, Cancelled)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn intent() -> PaymentIntent {
        PaymentIntent {
            id: "pay_test_001".into(),
            merchant_id: "merchant_test".into(),
            amount_minor: 1299,
            currency: "USD".into(),
            description: "Test purchase".into(),
            created_at: 1_000,
            expires_at: 1_600,
        }
    }

    #[test]
    fn accepts_valid_payment_intent() {
        assert!(intent().validate(1_100).is_ok());
    }

    #[test]
    fn rejects_zero_amount() {
        let mut p = intent();
        p.amount_minor = 0;
        assert!(p.validate(1_100).is_err());
    }

    #[test]
    fn rejects_expired_intent() {
        assert!(intent().validate(1_700).is_err());
    }

    #[test]
    fn rejects_overlong_lifetime() {
        let mut p = intent();
        p.expires_at = 2_000;
        assert!(p.validate(1_100).is_err());
    }

    #[test]
    fn rejects_invalid_currency() {
        let mut p = intent();
        p.currency = "usd".into();
        assert!(p.validate(1_100).is_err());
    }

    #[test]
    fn payment_transitions_are_one_way() {
        assert!(PaymentState::Created.can_transition_to(PaymentState::Pending));
        assert!(PaymentState::Pending.can_transition_to(PaymentState::Authorized));
        assert!(PaymentState::Authorized.can_transition_to(PaymentState::Captured));
        assert!(!PaymentState::Captured.can_transition_to(PaymentState::Failed));
        assert!(!PaymentState::Failed.can_transition_to(PaymentState::Captured));
    }
}

#[cfg(test)]
use std::collections::HashMap;
#[cfg(test)]
use std::sync::Mutex;

#[derive(Default)]
#[cfg(test)]
struct PaymentBookInner {
    entries: HashMap<String, (String, PaymentIntent, PaymentState)>,
}

#[cfg(test)]
#[derive(Default)]
pub struct PaymentBook {
    inner: Mutex<PaymentBookInner>,
}

#[cfg(test)]
impl PaymentBook {
    pub fn create(
        &self,
        intent: PaymentIntent,
        idempotency_key: &str,
        now: u64,
    ) -> Result<PaymentIntent> {
        intent.validate(now)?;
        if !valid_identifier(idempotency_key) {
            bail!("invalid idempotency key");
        }

        let mut inner = self
            .inner
            .lock()
            .map_err(|_| anyhow::anyhow!("payment store lock poisoned"))?;

        if let Some((stored_key, stored_intent, _)) = inner.entries.get(&intent.id) {
            if stored_key == idempotency_key && stored_intent == &intent {
                return Ok(stored_intent.clone());
            }
            bail!("payment identifier already exists");
        }

        if inner
            .entries
            .values()
            .any(|(key, _, _)| key == idempotency_key)
        {
            bail!("idempotency key has already been used");
        }

        inner.entries.insert(
            intent.id.clone(),
            (
                idempotency_key.to_owned(),
                intent.clone(),
                PaymentState::Created,
            ),
        );
        Ok(intent)
    }

    pub fn transition(&self, payment_id: &str, next: PaymentState) -> Result<PaymentState> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| anyhow::anyhow!("payment store lock poisoned"))?;

        let (_, _, state) = inner
            .entries
            .get_mut(payment_id)
            .ok_or_else(|| anyhow::anyhow!("payment not found"))?;

        if !state.can_transition_to(next) {
            bail!("invalid payment state transition");
        }

        *state = next;
        Ok(*state)
    }

    pub fn state(&self, payment_id: &str) -> Result<PaymentState> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| anyhow::anyhow!("payment store lock poisoned"))?;

        inner
            .entries
            .get(payment_id)
            .map(|(_, _, state)| *state)
            .ok_or_else(|| anyhow::anyhow!("payment not found"))
    }
}

#[cfg(test)]
mod payment_book_tests {
    use super::*;

    fn intent(id: &str, amount: u64) -> PaymentIntent {
        PaymentIntent {
            id: id.into(),
            merchant_id: "merchant_test".into(),
            amount_minor: amount,
            currency: "USD".into(),
            description: "Test purchase".into(),
            created_at: 1_000,
            expires_at: 1_600,
        }
    }

    #[test]
    fn identical_retry_returns_existing_intent() {
        let book = PaymentBook::default();
        let first = intent("pay_retry", 1299);
        assert_eq!(book.create(first.clone(), "idem_001", 1100).unwrap(), first);
        assert_eq!(book.create(first.clone(), "idem_001", 1100).unwrap(), first);
    }

    #[test]
    fn rejects_reused_key_for_different_payment() {
        let book = PaymentBook::default();
        book.create(intent("pay_one", 1299), "idem_001", 1100)
            .unwrap();
        assert!(book
            .create(intent("pay_two", 2500), "idem_001", 1100)
            .is_err());
    }

    #[test]
    fn rejects_same_payment_id_with_different_key() {
        let book = PaymentBook::default();
        book.create(intent("pay_one", 1299), "idem_001", 1100)
            .unwrap();
        assert!(book
            .create(intent("pay_one", 1299), "idem_002", 1100)
            .is_err());
    }

    #[test]
    fn state_transition_is_enforced() {
        let book = PaymentBook::default();
        book.create(intent("pay_state", 1299), "idem_state", 1100)
            .unwrap();
        assert_eq!(
            book.transition("pay_state", PaymentState::Pending).unwrap(),
            PaymentState::Pending
        );
        assert!(book
            .transition("pay_state", PaymentState::Captured)
            .is_err());
        assert_eq!(book.state("pay_state").unwrap(), PaymentState::Pending);
    }
}

/// Persistent SQLite payment store. This stores payment metadata only;
/// it never stores PayPal credentials or access tokens.
pub struct SqlitePaymentBook {
    conn: std::sync::Mutex<rusqlite::Connection>,
}

impl SqlitePaymentBook {
    pub fn open_default() -> Result<Self> {
        let path = default_db_path()?;
        let book = Self::open_path(&path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(book)
    }

    /// Open a store at an explicit path. Used by tests and the HTTP service.
    pub fn open_path(path: impl AsRef<std::path::Path>) -> Result<Self> {
        let conn = rusqlite::Connection::open(path)?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        conn.execute_batch(
            "PRAGMA foreign_keys=ON;
             PRAGMA journal_mode=DELETE;
             CREATE TABLE IF NOT EXISTS payments (
               id TEXT PRIMARY KEY,
               merchant_id TEXT NOT NULL,
               idempotency_key TEXT NOT NULL,
               intent_json TEXT NOT NULL,
               state TEXT NOT NULL,
               paypal_order_id TEXT UNIQUE,
               paypal_order_status TEXT,
               UNIQUE(merchant_id, idempotency_key)
             );
             CREATE TABLE IF NOT EXISTS webhook_events (
               event_id TEXT PRIMARY KEY,
               event_type TEXT NOT NULL,
               payload_sha256 TEXT NOT NULL,
               received_at INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS payment_captures (
               capture_id TEXT PRIMARY KEY,
               payment_id TEXT NOT NULL,
               order_id TEXT NOT NULL,
               status TEXT NOT NULL,
               amount_minor INTEGER NOT NULL,
               currency TEXT NOT NULL,
               refunded_minor INTEGER NOT NULL DEFAULT 0,
               created_at INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS payment_refunds (
               refund_id TEXT PRIMARY KEY,
               capture_id TEXT NOT NULL,
               payment_id TEXT NOT NULL,
               status TEXT NOT NULL,
               amount_minor INTEGER NOT NULL,
               currency TEXT NOT NULL,
               created_at INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS payment_disputes (
               event_id TEXT PRIMARY KEY,
               dispute_id TEXT NOT NULL,
               event_type TEXT NOT NULL,
               merchant_id TEXT NOT NULL,
               payment_id TEXT,
               capture_id TEXT,
               resource_json TEXT NOT NULL,
               payload_sha256 TEXT NOT NULL,
               received_at INTEGER NOT NULL
             );
             CREATE INDEX IF NOT EXISTS payment_disputes_dispute_idx
               ON payment_disputes(dispute_id, received_at);
             CREATE INDEX IF NOT EXISTS payment_captures_order_idx
               ON payment_captures(order_id);
             CREATE INDEX IF NOT EXISTS payment_refunds_capture_idx
               ON payment_refunds(capture_id);
             PRAGMA user_version=2;",
        )?;

        let has_order_column: i64 = conn.query_row(
            "SELECT COUNT(*) FROM pragma_table_info('payments') WHERE name='paypal_order_id'",
            [],
            |row| row.get(0),
        )?;
        if has_order_column == 0 {
            conn.execute("ALTER TABLE payments ADD COLUMN paypal_order_id TEXT", [])?;
            conn.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS payments_paypal_order_id_unique
                 ON payments(paypal_order_id) WHERE paypal_order_id IS NOT NULL",
                [],
            )?;
        }

        let has_status_column: i64 = conn.query_row(
            "SELECT COUNT(*) FROM pragma_table_info('payments') WHERE name='paypal_order_status'",
            [],
            |row| row.get(0),
        )?;
        if has_status_column == 0 {
            conn.execute(
                "ALTER TABLE payments ADD COLUMN paypal_order_status TEXT",
                [],
            )?;
        }

        Ok(Self {
            conn: std::sync::Mutex::new(conn),
        })
    }

    /// Test-only helper that opens an existing database without touching HOME.
    pub fn open_existing_for_tests(path: impl AsRef<std::path::Path>) -> Result<Self> {
        Self::open_path(path)
    }

    pub fn create(
        &self,
        intent: PaymentIntent,
        idempotency_key: &str,
        now: u64,
    ) -> Result<PaymentIntent> {
        if !valid_identifier(idempotency_key) {
            bail!("invalid idempotency key");
        }

        let mut conn = self
            .conn
            .lock()
            .map_err(|_| anyhow::anyhow!("payment database lock poisoned"))?;
        let tx = conn.transaction()?;
        let json = serde_json::to_string(&intent)?;

        let existing: Option<(String, String)> = tx
            .query_row(
                "SELECT intent_json, id FROM payments
             WHERE merchant_id=?1 AND idempotency_key=?2",
                rusqlite::params![intent.merchant_id, idempotency_key],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;

        if let Some((stored_json, stored_id)) = existing {
            let stored: PaymentIntent = serde_json::from_str(&stored_json)?;
            // `created_at`/`expires_at` are derived from the server clock on
            // every request, so an honest retry must not be rejected merely
            // because its timestamps differ. Compare the caller-controlled
            // business fields and the requested lifetime instead.
            let same_request = stored.id == intent.id
                && stored.merchant_id == intent.merchant_id
                && stored.amount_minor == intent.amount_minor
                && stored.currency == intent.currency
                && stored.description == intent.description
                && stored.expires_at.saturating_sub(stored.created_at)
                    == intent.expires_at.saturating_sub(intent.created_at);
            if same_request {
                tx.commit()?;
                return Ok(stored);
            }
            bail!("idempotency key already belongs to a different payment ({stored_id})");
        }

        intent.validate(now)?;
        tx.execute(
            "INSERT INTO payments
             (id, merchant_id, idempotency_key, intent_json, state)
             VALUES (?1, ?2, ?3, ?4, 'created')",
            rusqlite::params![intent.id, intent.merchant_id, idempotency_key, json],
        )?;
        tx.commit()?;
        Ok(intent)
    }

    pub fn state(&self, payment_id: &str) -> Result<PaymentState> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| anyhow::anyhow!("payment database lock poisoned"))?;
        let state: String = conn.query_row(
            "SELECT state FROM payments WHERE id=?1",
            [payment_id],
            |row| row.get(0),
        )?;
        match state.as_str() {
            "created" => Ok(PaymentState::Created),
            "pending" => Ok(PaymentState::Pending),
            "authorized" => Ok(PaymentState::Authorized),
            "captured" => Ok(PaymentState::Captured),
            "failed" => Ok(PaymentState::Failed),
            "cancelled" => Ok(PaymentState::Cancelled),
            _ => bail!("unknown payment state in database"),
        }
    }

    pub fn transition(&self, payment_id: &str, next: PaymentState) -> Result<PaymentState> {
        let mut conn = self
            .conn
            .lock()
            .map_err(|_| anyhow::anyhow!("payment database lock poisoned"))?;
        let tx = conn.transaction()?;
        let current: String = tx.query_row(
            "SELECT state FROM payments WHERE id=?1",
            [payment_id],
            |row| row.get(0),
        )?;

        let current_state = match current.as_str() {
            "created" => PaymentState::Created,
            "pending" => PaymentState::Pending,
            "authorized" => PaymentState::Authorized,
            "captured" => PaymentState::Captured,
            "failed" => PaymentState::Failed,
            "cancelled" => PaymentState::Cancelled,
            _ => bail!("unknown payment state in database"),
        };
        if !current_state.can_transition_to(next) {
            bail!("invalid payment state transition");
        }

        let next_text = match next {
            PaymentState::Created => "created",
            PaymentState::Pending => "pending",
            PaymentState::Authorized => "authorized",
            PaymentState::Captured => "captured",
            PaymentState::Failed => "failed",
            PaymentState::Cancelled => "cancelled",
        };
        tx.execute(
            "UPDATE payments SET state=?1 WHERE id=?2",
            rusqlite::params![next_text, payment_id],
        )?;
        tx.commit()?;
        Ok(next)
    }

    pub fn payment_intent(&self, payment_id: &str) -> Result<PaymentIntent> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| anyhow::anyhow!("payment database lock poisoned"))?;
        let json: String = conn.query_row(
            "SELECT intent_json FROM payments WHERE id=?1",
            [payment_id],
            |row| row.get(0),
        )?;
        Ok(serde_json::from_str(&json)?)
    }

    /// Bind a provider order to exactly one locally stored payment.
    /// Repeating the same binding is safe; changing an existing binding is refused.
    pub fn bind_paypal_order(&self, payment_id: &str, order_id: &str) -> Result<()> {
        if !valid_identifier(payment_id)
            || order_id.is_empty()
            || order_id.len() > 64
            || !order_id.bytes().all(|b| b.is_ascii_alphanumeric())
        {
            bail!("invalid payment or PayPal order identifier");
        }
        let conn = self
            .conn
            .lock()
            .map_err(|_| anyhow::anyhow!("payment database lock poisoned"))?;
        let changed = conn.execute(
            "UPDATE payments SET paypal_order_id=?1
             WHERE id=?2 AND (paypal_order_id IS NULL OR paypal_order_id=?1)",
            rusqlite::params![order_id, payment_id],
        )?;
        if changed != 1 {
            bail!("payment does not exist or is already bound to a different PayPal order");
        }
        Ok(())
    }

    pub fn paypal_order_id(&self, payment_id: &str) -> Result<Option<String>> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| anyhow::anyhow!("payment database lock poisoned"))?;
        Ok(conn.query_row(
            "SELECT paypal_order_id FROM payments WHERE id=?1",
            [payment_id],
            |row| row.get(0),
        )?)
    }

    /// Find the locally stored payment bound to a PayPal order.
    pub fn payment_for_paypal_order(
        &self,
        order_id: &str,
    ) -> Result<(PaymentIntent, PaymentState)> {
        if order_id.is_empty()
            || order_id.len() > 64
            || !order_id.bytes().all(|b| b.is_ascii_alphanumeric())
        {
            bail!("invalid PayPal order ID");
        }

        let conn = self
            .conn
            .lock()
            .map_err(|_| anyhow::anyhow!("payment database lock poisoned"))?;

        let (json, state): (String, String) = conn.query_row(
            "SELECT intent_json, state FROM payments WHERE paypal_order_id=?1",
            [order_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;

        let intent = serde_json::from_str(&json)?;
        let state = match state.as_str() {
            "created" => PaymentState::Created,
            "pending" => PaymentState::Pending,
            "authorized" => PaymentState::Authorized,
            "captured" => PaymentState::Captured,
            "failed" => PaymentState::Failed,
            "cancelled" => PaymentState::Cancelled,
            _ => bail!("unknown payment state in database"),
        };

        Ok((intent, state))
    }

    /// Atomically record a verified webhook and transition its payment.
    /// Call only after PayPal has confirmed the webhook signature and the
    /// caller has validated the event's order, amount, currency and reference.
    /// Returns false when the event ID was already processed.
    pub fn record_verified_capture(
        &self,
        event_id: &str,
        event_type: &str,
        payload_sha256: &str,
        received_at: u64,
        payment_id: &str,
        capture_id: &str,
    ) -> Result<bool> {
        if !valid_identifier(event_id)
            || !valid_identifier(payment_id)
            || event_type != "PAYMENT.CAPTURE.COMPLETED"
            || payload_sha256.len() != 64
            || !payload_sha256.bytes().all(|b| b.is_ascii_hexdigit())
            || capture_id.is_empty()
            || capture_id.len() > 64
            || !capture_id.bytes().all(|b| b.is_ascii_alphanumeric())
        {
            bail!("invalid verified capture metadata");
        }

        let mut conn = self
            .conn
            .lock()
            .map_err(|_| anyhow::anyhow!("payment database lock poisoned"))?;
        let tx = conn.transaction()?;

        let existing: Option<(String, String)> = tx
            .query_row(
                "SELECT event_type, payload_sha256 FROM webhook_events WHERE event_id=?1",
                [event_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;

        if let Some((existing_type, existing_hash)) = existing {
            if existing_type != event_type || existing_hash != payload_sha256 {
                bail!("webhook event ID was reused with different content");
            }
            tx.commit()?;
            return Ok(false);
        }

        let current: String = tx.query_row(
            "SELECT state FROM payments WHERE id=?1",
            [payment_id],
            |row| row.get(0),
        )?;

        // A capture may already have been reconciled from the authoritative
        // capture/order API before PayPal's webhook is delivered. In that case
        // the webhook is a duplicate, not an error: record the event for audit
        // and acknowledge it so PayPal stops retrying.
        if current == "captured" {
            let already_recorded = Self::capture_from_connection_tx(&tx, capture_id)?
                .map(|capture| capture.payment_id == payment_id)
                .unwrap_or(false);
            if !already_recorded {
                bail!("payment is already captured with a different capture");
            }
            tx.execute(
                "INSERT OR IGNORE INTO webhook_events
                 (event_id, event_type, payload_sha256, received_at)
                 VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![event_id, event_type, payload_sha256, received_at],
            )?;
            tx.commit()?;
            return Ok(false);
        }

        tx.execute(
            "INSERT INTO webhook_events
             (event_id, event_type, payload_sha256, received_at)
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![event_id, event_type, payload_sha256, received_at],
        )?;

        match current.as_str() {
            "pending" => {
                let authorized = tx.execute(
                    "UPDATE payments SET state='authorized'
                     WHERE id=?1 AND state='pending'",
                    [payment_id],
                )?;
                if authorized != 1 {
                    bail!("payment authorization transition failed");
                }
            }
            "authorized" => {}
            "captured" => {
                bail!("payment is already captured with a different webhook event");
            }
            _ => bail!("payment is not eligible for capture"),
        }

        let capture: (String, Option<String>) = tx.query_row(
            "SELECT intent_json, paypal_order_id FROM payments WHERE id=?1",
            [payment_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let order_id = capture
            .1
            .ok_or_else(|| anyhow::anyhow!("payment has no bound PayPal order"))?;
        let intent: PaymentIntent = serde_json::from_str(&capture.0)?;

        let captured = tx.execute(
            "UPDATE payments SET state='captured', paypal_order_status='COMPLETED'
             WHERE id=?1 AND state='authorized'",
            [payment_id],
        )?;

        if captured != 1 {
            bail!("payment capture transition failed");
        }

        tx.execute(
            "INSERT INTO payment_captures
             (capture_id, payment_id, order_id, status, amount_minor, currency, refunded_minor, created_at)
             VALUES (?1, ?2, ?3, 'COMPLETED', ?4, ?5, 0, ?6)
             ON CONFLICT(capture_id) DO UPDATE SET status=excluded.status",
            rusqlite::params![
                capture_id,
                payment_id,
                order_id,
                intent.amount_minor as i64,
                intent.currency,
                received_at as i64
            ],
        )?;

        tx.commit()?;
        Ok(true)
    }

    /// Call only after the provider's webhook signature has been verified.
    /// Returns false for an event ID already recorded.
    pub fn record_verified_webhook(
        &self,
        event_id: &str,
        event_type: &str,
        payload_sha256: &str,
        received_at: u64,
    ) -> Result<bool> {
        if !valid_identifier(event_id)
            || event_type.is_empty()
            || event_type.len() > 128
            || payload_sha256.len() != 64
            || !payload_sha256.bytes().all(|b| b.is_ascii_hexdigit())
        {
            bail!("invalid verified webhook metadata");
        }
        let conn = self
            .conn
            .lock()
            .map_err(|_| anyhow::anyhow!("payment database lock poisoned"))?;
        let existing: Option<(String, String)> = conn
            .query_row(
                "SELECT event_type, payload_sha256 FROM webhook_events WHERE event_id=?1",
                [event_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if let Some((existing_type, existing_hash)) = existing {
            if existing_type != event_type || existing_hash != payload_sha256 {
                bail!("webhook event ID was reused with different content");
            }
            return Ok(false);
        }
        conn.execute(
            "INSERT INTO webhook_events
             (event_id, event_type, payload_sha256, received_at)
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![event_id, event_type, payload_sha256, received_at],
        )?;
        Ok(true)
    }

    /// Record a capture confirmed by an authoritative PayPal capture API
    /// response (not by a browser). Deduplicates by capture ID.
    pub fn record_authoritative_capture(
        &self,
        payment_id: &str,
        capture_id: &str,
        payload_sha256: &str,
        received_at: u64,
    ) -> Result<bool> {
        if !valid_identifier(payment_id)
            || capture_id.is_empty()
            || capture_id.len() > 64
            || !capture_id.bytes().all(|b| b.is_ascii_alphanumeric())
            || payload_sha256.len() != 64
            || !payload_sha256.bytes().all(|b| b.is_ascii_hexdigit())
        {
            bail!("invalid authoritative capture metadata");
        }
        let event_id = format!("cap_{capture_id}");
        let mut conn = self
            .conn
            .lock()
            .map_err(|_| anyhow::anyhow!("payment database lock poisoned"))?;
        let tx = conn.transaction()?;

        let (intent_json, order_id): (String, Option<String>) = tx.query_row(
            "SELECT intent_json, paypal_order_id FROM payments WHERE id=?1",
            [payment_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let order_id =
            order_id.ok_or_else(|| anyhow::anyhow!("payment has no bound PayPal order"))?;
        let intent: PaymentIntent = serde_json::from_str(&intent_json)?;

        // A capture ID may only ever refer to the same payment, order, amount
        // and currency. This also makes a repeated authoritative capture call
        // an idempotent success rather than an event-ID collision.
        if let Some(existing) = Self::capture_from_connection_tx(&tx, capture_id)? {
            if existing.payment_id != payment_id
                || existing.order_id != order_id
                || existing.amount_minor != intent.amount_minor
                || existing.currency != intent.currency
            {
                bail!("capture ID was reused with different content");
            }
            tx.commit()?;
            return Ok(false);
        }

        let event_collision: Option<String> = tx
            .query_row(
                "SELECT payload_sha256 FROM webhook_events WHERE event_id=?1",
                [&event_id],
                |r| r.get(0),
            )
            .optional()?;
        if event_collision.is_some() {
            bail!("authoritative capture event ID collides with an existing event");
        }

        let current: String = tx.query_row(
            "SELECT state FROM payments WHERE id=?1",
            [payment_id],
            |r| r.get(0),
        )?;
        match current.as_str() {
            "pending" => {
                tx.execute(
                    "UPDATE payments SET state='authorized' WHERE id=?1 AND state='pending'",
                    [payment_id],
                )?;
            }
            "authorized" => {}
            "captured" => bail!("payment is captured without a matching capture record"),
            _ => bail!("payment is not eligible for capture"),
        }
        let changed = tx.execute(
            "UPDATE payments SET state='captured', paypal_order_status='COMPLETED'
             WHERE id=?1 AND state='authorized'",
            [payment_id],
        )?;
        if changed != 1 {
            bail!("payment capture transition failed");
        }
        tx.execute(
            "INSERT INTO payment_captures
             (capture_id, payment_id, order_id, status, amount_minor, currency, refunded_minor, created_at)
             VALUES (?1, ?2, ?3, 'COMPLETED', ?4, ?5, 0, ?6)
             ON CONFLICT(capture_id) DO UPDATE SET status=excluded.status",
            rusqlite::params![
                capture_id,
                payment_id,
                order_id,
                intent.amount_minor as i64,
                intent.currency,
                received_at as i64
            ],
        )?;
        tx.execute(
            "INSERT INTO webhook_events (event_id, event_type, payload_sha256, received_at)
             VALUES (?1, 'AUTHORITATIVE.CAPTURE', ?2, ?3)",
            rusqlite::params![event_id, payload_sha256, received_at],
        )?;
        tx.commit()?;
        Ok(true)
    }

    /// Record the latest PayPal-reported order status. The order binding is
    /// verified so a provider status can never be attached to another payment.
    pub fn set_order_status(&self, payment_id: &str, order_id: &str, status: &str) -> Result<()> {
        if !valid_identifier(payment_id)
            || order_id.is_empty()
            || order_id.len() > 64
            || !order_id.bytes().all(|b| b.is_ascii_alphanumeric())
            || !valid_provider_status(status)
        {
            bail!("invalid PayPal order status metadata");
        }
        let conn = self
            .conn
            .lock()
            .map_err(|_| anyhow::anyhow!("payment database lock poisoned"))?;
        let changed = conn.execute(
            "UPDATE payments SET paypal_order_status=?1
             WHERE id=?2 AND paypal_order_id=?3",
            rusqlite::params![status, payment_id, order_id],
        )?;
        if changed != 1 {
            bail!("payment is not bound to the supplied PayPal order");
        }
        Ok(())
    }

    pub fn order_status(&self, payment_id: &str) -> Result<Option<String>> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| anyhow::anyhow!("payment database lock poisoned"))?;
        Ok(conn.query_row(
            "SELECT paypal_order_status FROM payments WHERE id=?1",
            [payment_id],
            |row| row.get(0),
        )?)
    }

    /// Persist authoritative capture details, deduplicating by PayPal capture
    /// ID. A capture can only be attached to a locally bound payment and order.
    #[allow(clippy::too_many_arguments)]
    pub fn record_capture_details(
        &self,
        payment_id: &str,
        order_id: &str,
        capture_id: &str,
        status: &str,
        amount_minor: u64,
        currency: &str,
        at: u64,
    ) -> Result<bool> {
        if !valid_identifier(payment_id)
            || order_id.is_empty()
            || order_id.len() > 64
            || !order_id.bytes().all(|b| b.is_ascii_alphanumeric())
            || capture_id.is_empty()
            || capture_id.len() > 64
            || !capture_id.bytes().all(|b| b.is_ascii_alphanumeric())
            || !valid_provider_status(status)
            || amount_minor == 0
            || amount_minor > MAX_AMOUNT_MINOR
            || currency.len() != 3
            || !currency.bytes().all(|b| b.is_ascii_uppercase())
        {
            bail!("invalid capture metadata");
        }
        let conn = self
            .conn
            .lock()
            .map_err(|_| anyhow::anyhow!("payment database lock poisoned"))?;
        let intent_json: String = conn.query_row(
            "SELECT intent_json FROM payments
             WHERE id=?1 AND paypal_order_id=?2",
            rusqlite::params![payment_id, order_id],
            |row| row.get(0),
        )?;
        let intent: PaymentIntent = serde_json::from_str(&intent_json)?;
        if intent.amount_minor != amount_minor || intent.currency != currency {
            bail!("capture amount or currency does not match the local payment");
        }

        let existing = Self::capture_from_connection(&conn, capture_id)?;
        if let Some(existing) = existing {
            if existing.payment_id != payment_id
                || existing.order_id != order_id
                || existing.amount_minor != amount_minor
                || existing.currency != currency
            {
                bail!("capture ID was reused with different content");
            }
            conn.execute(
                "UPDATE payment_captures SET status=?1 WHERE capture_id=?2",
                rusqlite::params![status, capture_id],
            )?;
            return Ok(false);
        }

        conn.execute(
            "INSERT INTO payment_captures
             (capture_id, payment_id, order_id, status, amount_minor, currency, refunded_minor, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, ?7)",
            rusqlite::params![
                capture_id,
                payment_id,
                order_id,
                status,
                amount_minor as i64,
                currency,
                at as i64
            ],
        )?;
        Ok(true)
    }

    pub fn capture_details(&self, capture_id: &str) -> Result<Option<CaptureRecord>> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| anyhow::anyhow!("payment database lock poisoned"))?;
        Self::capture_from_connection(&conn, capture_id)
    }

    pub fn capture_for_order(&self, order_id: &str) -> Result<Option<CaptureRecord>> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| anyhow::anyhow!("payment database lock poisoned"))?;
        let mut stmt = conn.prepare(
            "SELECT capture_id, payment_id, order_id, status, amount_minor, currency,
                    refunded_minor, created_at
             FROM payment_captures WHERE order_id=?1 ORDER BY rowid DESC LIMIT 1",
        )?;
        let mut rows = stmt.query([order_id])?;
        match rows.next()? {
            Some(row) => Ok(Some(capture_record_from_row(row)?)),
            None => Ok(None),
        }
    }

    fn capture_from_connection(
        conn: &rusqlite::Connection,
        capture_id: &str,
    ) -> Result<Option<CaptureRecord>> {
        let mut stmt = conn.prepare(
            "SELECT capture_id, payment_id, order_id, status, amount_minor, currency,
                    refunded_minor, created_at
             FROM payment_captures WHERE capture_id=?1",
        )?;
        let mut rows = stmt.query([capture_id])?;
        match rows.next()? {
            Some(row) => Ok(Some(capture_record_from_row(row)?)),
            None => Ok(None),
        }
    }

    /// Record an authoritative refund and prevent cumulative over-refunding.
    /// Returns `(duplicate, full_refund, total_refunded_minor)`.
    #[allow(clippy::too_many_arguments)]
    pub fn record_refund(
        &self,
        refund_id: &str,
        capture_id: &str,
        payment_id: &str,
        status: &str,
        amount_minor: u64,
        currency: &str,
        at: u64,
    ) -> Result<(bool, bool, u64)> {
        if refund_id.is_empty()
            || refund_id.len() > 64
            || !refund_id.bytes().all(|b| b.is_ascii_alphanumeric())
            || capture_id.is_empty()
            || capture_id.len() > 64
            || !capture_id.bytes().all(|b| b.is_ascii_alphanumeric())
            || !valid_identifier(payment_id)
            || !valid_provider_status(status)
            || amount_minor == 0
            || amount_minor > MAX_AMOUNT_MINOR
            || currency.len() != 3
            || !currency.bytes().all(|b| b.is_ascii_uppercase())
        {
            bail!("invalid refund metadata");
        }

        let mut conn = self
            .conn
            .lock()
            .map_err(|_| anyhow::anyhow!("payment database lock poisoned"))?;
        let tx = conn.transaction()?;

        let existing: Option<(String, String, i64, String)> = tx
            .query_row(
                "SELECT capture_id, payment_id, amount_minor, currency
                 FROM payment_refunds WHERE refund_id=?1",
                [refund_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;
        if let Some((stored_capture, stored_payment, stored_amount, stored_currency)) = existing {
            if stored_capture != capture_id
                || stored_payment != payment_id
                || stored_amount != amount_minor as i64
                || stored_currency != currency
            {
                bail!("refund ID was reused with different content");
            }
            let total = Self::refunded_total(&tx, capture_id)?;
            let capture = Self::capture_from_connection_tx(&tx, capture_id)?
                .ok_or_else(|| anyhow::anyhow!("capture is not recorded locally"))?;
            tx.commit()?;
            return Ok((true, total >= capture.amount_minor, total));
        }

        let capture = Self::capture_from_connection_tx(&tx, capture_id)?
            .ok_or_else(|| anyhow::anyhow!("capture is not recorded locally"))?;
        if capture.payment_id != payment_id {
            bail!("capture does not belong to the supplied payment");
        }
        if capture.currency != currency {
            bail!("refund currency does not match the capture currency");
        }
        if capture.status != "COMPLETED" && capture.status != "PARTIALLY_REFUNDED" {
            bail!("capture is not in a refundable state");
        }

        let already_refunded = Self::refunded_total(&tx, capture_id)?;
        let remaining = capture
            .amount_minor
            .checked_sub(already_refunded)
            .ok_or_else(|| anyhow::anyhow!("capture is already fully refunded"))?;
        if amount_minor > remaining {
            bail!("refund amount exceeds the remaining captured amount");
        }

        tx.execute(
            "INSERT INTO payment_refunds
             (refund_id, capture_id, payment_id, status, amount_minor, currency, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![
                refund_id,
                capture_id,
                payment_id,
                status,
                amount_minor as i64,
                currency,
                at as i64
            ],
        )?;

        let counts_towards_refund = matches!(status, "COMPLETED" | "PENDING");
        let total = if counts_towards_refund {
            already_refunded + amount_minor
        } else {
            already_refunded
        };
        if counts_towards_refund {
            let capture_status = if total >= capture.amount_minor {
                "REFUNDED"
            } else {
                "PARTIALLY_REFUNDED"
            };
            tx.execute(
                "UPDATE payment_captures SET refunded_minor=?1, status=?2 WHERE capture_id=?3",
                rusqlite::params![total as i64, capture_status, capture_id],
            )?;
        }
        tx.commit()?;
        Ok((
            false,
            counts_towards_refund && total >= capture.amount_minor,
            total,
        ))
    }

    fn refunded_total(tx: &rusqlite::Transaction<'_>, capture_id: &str) -> Result<u64> {
        let total: i64 = tx.query_row(
            "SELECT COALESCE(SUM(amount_minor), 0) FROM payment_refunds
             WHERE capture_id=?1 AND status IN ('COMPLETED', 'PENDING')",
            [capture_id],
            |row| row.get(0),
        )?;
        u64::try_from(total).map_err(|_| anyhow::anyhow!("invalid refund total"))
    }

    fn capture_from_connection_tx(
        tx: &rusqlite::Transaction<'_>,
        capture_id: &str,
    ) -> Result<Option<CaptureRecord>> {
        let mut stmt = tx.prepare(
            "SELECT capture_id, payment_id, order_id, status, amount_minor, currency,
                    refunded_minor, created_at
             FROM payment_captures WHERE capture_id=?1",
        )?;
        let mut rows = stmt.query([capture_id])?;
        match rows.next()? {
            Some(row) => Ok(Some(capture_record_from_row(row)?)),
            None => Ok(None),
        }
    }

    pub fn refund_details(&self, refund_id: &str) -> Result<Option<RefundRecord>> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| anyhow::anyhow!("payment database lock poisoned"))?;
        let mut stmt = conn.prepare(
            "SELECT refund_id, capture_id, payment_id, status, amount_minor, currency, created_at
             FROM payment_refunds WHERE refund_id=?1",
        )?;
        let mut rows = stmt.query([refund_id])?;
        match rows.next()? {
            Some(row) => Ok(Some(refund_record_from_row(row)?)),
            None => Ok(None),
        }
    }

    /// Persist a PayPal-signature-verified dispute lifecycle event exactly once.
    // Keep the validated provider fields explicit at this storage boundary.
    #[allow(clippy::too_many_arguments)]
    pub fn record_dispute_event(
        &self,
        event_id: &str,
        dispute_id: &str,
        event_type: &str,
        merchant_id: &str,
        payment_id: Option<&str>,
        capture_id: Option<&str>,
        resource: &serde_json::Value,
        payload_sha256: &str,
        received_at: u64,
    ) -> Result<bool> {
        if event_id.is_empty()
            || event_id.len() > 128
            || dispute_id.is_empty()
            || dispute_id.len() > 128
            || !valid_identifier(merchant_id)
            || payload_sha256.len() != 64
            || !payload_sha256.bytes().all(|b| b.is_ascii_hexdigit())
        {
            bail!("invalid dispute event metadata");
        }
        let conn = self
            .conn
            .lock()
            .map_err(|_| anyhow::anyhow!("payment database lock poisoned"))?;
        let changed = conn.execute(
            "INSERT OR IGNORE INTO payment_disputes
             (event_id, dispute_id, event_type, merchant_id, payment_id, capture_id, resource_json, payload_sha256, received_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            rusqlite::params![event_id, dispute_id, event_type, merchant_id, payment_id, capture_id,
                serde_json::to_string(resource)?, payload_sha256, received_at],
        )?;
        if changed == 0 {
            let existing: (String, String, String) = conn.query_row(
                "SELECT dispute_id, payload_sha256, merchant_id FROM payment_disputes WHERE event_id=?1", [event_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )?;
            if existing.0 != dispute_id || existing.1 != payload_sha256 || existing.2 != merchant_id
            {
                bail!("PayPal dispute event ID was replayed with different content");
            }
        }
        Ok(changed == 1)
    }

    pub fn list_dispute_events(&self, merchant_id: &str) -> Result<Vec<serde_json::Value>> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| anyhow::anyhow!("payment database lock poisoned"))?;
        let mut stmt = conn.prepare(
            "SELECT d.event_id, d.dispute_id, d.event_type, d.payment_id, d.capture_id,
                    d.resource_json, d.received_at
             FROM payment_disputes d WHERE d.merchant_id=?1 ORDER BY d.received_at DESC LIMIT 200",
        )?;
        let rows = stmt.query_map([merchant_id], |r| {
            let raw: String = r.get(5)?;
            let resource: serde_json::Value = serde_json::from_str(&raw).map_err(|e|
                rusqlite::Error::FromSqlConversionFailure(5, rusqlite::types::Type::Text, Box::new(e))
            )?;
            Ok(serde_json::json!({"event_id":r.get::<_,String>(0)?,"dispute_id":r.get::<_,String>(1)?,
                "event_type":r.get::<_,String>(2)?,"payment_id":r.get::<_,Option<String>>(3)?,
                "capture_id":r.get::<_,Option<String>>(4)?,"resource":resource,"received_at":r.get::<_,i64>(6)? as u64}))
        })?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    /// List only payments belonging to the configured merchant tenant.
    pub fn list_payments_for_merchant(&self, merchant_id: &str) -> Result<Vec<PaymentSummary>> {
        if !valid_identifier(merchant_id) {
            bail!("invalid merchant identifier");
        }
        let conn = self
            .conn
            .lock()
            .map_err(|_| anyhow::anyhow!("payment database lock poisoned"))?;
        let mut stmt = conn.prepare(
            "SELECT id, merchant_id, intent_json, state, paypal_order_id, paypal_order_status
                    ,COALESCE((SELECT amount_minor FROM payment_captures c WHERE c.payment_id=payments.id ORDER BY created_at DESC LIMIT 1),0)
                    ,COALESCE((SELECT refunded_minor FROM payment_captures c WHERE c.payment_id=payments.id ORDER BY created_at DESC LIMIT 1),0)
             FROM payments WHERE merchant_id=?1 ORDER BY rowid DESC LIMIT 200",
        )?;
        let rows = stmt.query_map([merchant_id], |row| {
            let json: String = row.get(2)?;
            let intent: PaymentIntent = serde_json::from_str(&json).map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(
                    2,
                    rusqlite::types::Type::Text,
                    Box::new(e),
                )
            })?;
            Ok(PaymentSummary {
                id: row.get(0)?,
                merchant_id: row.get(1)?,
                amount_minor: intent.amount_minor,
                currency: intent.currency,
                description: intent.description,
                state: row.get(3)?,
                paypal_order_id: row.get(4)?,
                paypal_order_status: row.get(5)?,
                captured_minor: row.get(6)?,
                refunded_minor: row.get(7)?,
                created_at: intent.created_at,
                expires_at: intent.expires_at,
            })
        })?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    pub fn list_payments(&self) -> Result<Vec<PaymentSummary>> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| anyhow::anyhow!("payment database lock poisoned"))?;
        let mut stmt = conn.prepare(
            "SELECT id, merchant_id, intent_json, state, paypal_order_id, paypal_order_status
                    ,COALESCE((SELECT amount_minor FROM payment_captures c WHERE c.payment_id=payments.id ORDER BY created_at DESC LIMIT 1),0)
                    ,COALESCE((SELECT refunded_minor FROM payment_captures c WHERE c.payment_id=payments.id ORDER BY created_at DESC LIMIT 1),0)
             FROM payments ORDER BY rowid DESC LIMIT 200",
        )?;
        let rows = stmt.query_map([], |row| {
            let json: String = row.get(2)?;
            let intent: PaymentIntent = serde_json::from_str(&json).map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(
                    2,
                    rusqlite::types::Type::Text,
                    Box::new(e),
                )
            })?;
            Ok(PaymentSummary {
                id: row.get(0)?,
                merchant_id: row.get(1)?,
                amount_minor: intent.amount_minor,
                currency: intent.currency,
                description: intent.description,
                state: row.get(3)?,
                paypal_order_id: row.get(4)?,
                paypal_order_status: row.get(5)?,
                captured_minor: row.get(6)?,
                refunded_minor: row.get(7)?,
                created_at: intent.created_at,
                expires_at: intent.expires_at,
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentSummary {
    pub id: String,
    pub merchant_id: String,
    pub amount_minor: u64,
    pub currency: String,
    pub description: String,
    pub state: String,
    pub paypal_order_id: Option<String>,
    pub paypal_order_status: Option<String>,
    pub captured_minor: u64,
    pub refunded_minor: u64,
    pub created_at: u64,
    pub expires_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureRecord {
    pub capture_id: String,
    pub payment_id: String,
    pub order_id: String,
    pub status: String,
    pub amount_minor: u64,
    pub currency: String,
    pub refunded_minor: u64,
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefundRecord {
    pub refund_id: String,
    pub capture_id: String,
    pub payment_id: String,
    pub status: String,
    pub amount_minor: u64,
    pub currency: String,
    pub created_at: u64,
}

fn capture_record_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<CaptureRecord> {
    let amount: i64 = row.get(4)?;
    let refunded: i64 = row.get(6)?;
    Ok(CaptureRecord {
        capture_id: row.get(0)?,
        payment_id: row.get(1)?,
        order_id: row.get(2)?,
        status: row.get(3)?,
        amount_minor: u64::try_from(amount).map_err(|_| {
            rusqlite::Error::FromSqlConversionFailure(
                4,
                rusqlite::types::Type::Integer,
                Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "negative capture amount",
                )),
            )
        })?,
        currency: row.get(5)?,
        refunded_minor: u64::try_from(refunded).map_err(|_| {
            rusqlite::Error::FromSqlConversionFailure(
                6,
                rusqlite::types::Type::Integer,
                Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "negative refunded amount",
                )),
            )
        })?,
        created_at: row.get::<_, i64>(7)? as u64,
    })
}

fn refund_record_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RefundRecord> {
    let amount: i64 = row.get(4)?;
    Ok(RefundRecord {
        refund_id: row.get(0)?,
        capture_id: row.get(1)?,
        payment_id: row.get(2)?,
        status: row.get(3)?,
        amount_minor: u64::try_from(amount).map_err(|_| {
            rusqlite::Error::FromSqlConversionFailure(
                4,
                rusqlite::types::Type::Integer,
                Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "negative refund amount",
                )),
            )
        })?,
        currency: row.get(5)?,
        created_at: row.get::<_, i64>(6)? as u64,
    })
}

fn valid_provider_status(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 32
        && value
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b == b'_' || b.is_ascii_digit())
}

/// Resolve the private payment database path, creating a mode-0700 directory.
pub(crate) fn default_db_path() -> Result<std::path::PathBuf> {
    use std::path::PathBuf;
    let root = if let Some(xdg) = std::env::var_os("XDG_DATA_HOME") {
        let path = PathBuf::from(xdg);
        if !path.is_absolute() {
            bail!("XDG_DATA_HOME must be an absolute path");
        }
        path
    } else {
        PathBuf::from(std::env::var_os("HOME").ok_or_else(|| anyhow::anyhow!("HOME is not set"))?)
            .join(".local/share")
    };
    let dir = root.join("quantum-shield").join("payments");
    std::fs::create_dir_all(&dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(dir.join("payments.sqlite3"))
}

#[cfg(test)]
mod sqlite_order_binding_tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_db() -> (std::path::PathBuf, SqlitePaymentBook) {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "quantum-shield-payments-{}-{nonce}.sqlite3",
            std::process::id()
        ));

        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch(
            "PRAGMA foreign_keys=ON;
             CREATE TABLE payments (
               id TEXT PRIMARY KEY,
               merchant_id TEXT NOT NULL,
               idempotency_key TEXT NOT NULL,
               intent_json TEXT NOT NULL,
               state TEXT NOT NULL,
               paypal_order_id TEXT UNIQUE,
               paypal_order_status TEXT,
               UNIQUE(merchant_id, idempotency_key)
             );
             CREATE TABLE webhook_events (
               event_id TEXT PRIMARY KEY,
               event_type TEXT NOT NULL,
               payload_sha256 TEXT NOT NULL,
               received_at INTEGER NOT NULL
             );
             CREATE TABLE payment_captures (
               capture_id TEXT PRIMARY KEY,
               payment_id TEXT NOT NULL,
               order_id TEXT NOT NULL,
               status TEXT NOT NULL,
               amount_minor INTEGER NOT NULL,
               currency TEXT NOT NULL,
               refunded_minor INTEGER NOT NULL DEFAULT 0,
               created_at INTEGER NOT NULL
             );
             CREATE TABLE payment_refunds (
               refund_id TEXT PRIMARY KEY,
               capture_id TEXT NOT NULL,
               payment_id TEXT NOT NULL,
               status TEXT NOT NULL,
               amount_minor INTEGER NOT NULL,
               currency TEXT NOT NULL,
               created_at INTEGER NOT NULL
             );
             CREATE TABLE payment_disputes (
               event_id TEXT PRIMARY KEY, dispute_id TEXT NOT NULL, event_type TEXT NOT NULL,
               merchant_id TEXT NOT NULL, payment_id TEXT, capture_id TEXT, resource_json TEXT NOT NULL,
               payload_sha256 TEXT NOT NULL, received_at INTEGER NOT NULL
             );",
        )
        .unwrap();

        (
            path,
            SqlitePaymentBook {
                conn: std::sync::Mutex::new(conn),
            },
        )
    }

    fn intent(id: &str, merchant: &str) -> PaymentIntent {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        PaymentIntent {
            id: id.into(),
            merchant_id: merchant.into(),
            amount_minor: 1299,
            currency: "USD".into(),
            description: "Isolated SQLite test".into(),
            created_at: now.saturating_sub(10),
            expires_at: now + 600,
        }
    }

    #[test]
    fn merchant_listing_and_dispute_events_are_tenant_scoped_and_idempotent() {
        let (path, book) = temp_db();
        let one = intent("pay_tenant_one", "merchant_one");
        let two = intent("pay_tenant_two", "merchant_two");
        book.create(one.clone(), "idem_tenant_one", one.created_at + 1)
            .unwrap();
        book.create(two.clone(), "idem_tenant_two", two.created_at + 1)
            .unwrap();
        let listed = book.list_payments_for_merchant("merchant_one").unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, one.id);
        let resource = serde_json::json!({"status":"UNDER_REVIEW"});
        assert!(book
            .record_dispute_event(
                "WH_DISP_1",
                "PP-D-1",
                "CUSTOMER.DISPUTE.CREATED",
                "merchant_one",
                Some(&one.id),
                Some("CAPTURE1"),
                &resource,
                &"a".repeat(64),
                10
            )
            .unwrap());
        assert!(!book
            .record_dispute_event(
                "WH_DISP_1",
                "PP-D-1",
                "CUSTOMER.DISPUTE.CREATED",
                "merchant_one",
                Some(&one.id),
                Some("CAPTURE1"),
                &resource,
                &"a".repeat(64),
                11
            )
            .unwrap());
        assert_eq!(book.list_dispute_events("merchant_one").unwrap().len(), 1);
        assert!(book.list_dispute_events("merchant_two").unwrap().is_empty());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn sqlite_payment_and_paypal_order_binding_are_persistent_and_unique() {
        let (path, book) = temp_db();

        let first = intent("pay_sqlite_one", "merchant_one");
        book.create(first.clone(), "idem_sqlite_one", first.created_at + 1)
            .unwrap();

        assert_eq!(book.payment_intent(&first.id).unwrap(), first);
        assert_eq!(book.state(&first.id).unwrap(), PaymentState::Created);

        book.bind_paypal_order(&first.id, "PAYPALORDER001").unwrap();
        book.bind_paypal_order(&first.id, "PAYPALORDER001").unwrap();

        assert_eq!(
            book.paypal_order_id(&first.id).unwrap().as_deref(),
            Some("PAYPALORDER001")
        );
        assert!(book.bind_paypal_order(&first.id, "PAYPALORDER002").is_err());

        let second = intent("pay_sqlite_two", "merchant_two");
        book.create(second.clone(), "idem_sqlite_two", second.created_at + 1)
            .unwrap();

        assert!(book
            .bind_paypal_order(&second.id, "PAYPALORDER001")
            .is_err());

        drop(book);

        let reopened = rusqlite::Connection::open(&path).unwrap();
        let persisted: String = reopened
            .query_row(
                "SELECT paypal_order_id FROM payments WHERE id=?1",
                ["pay_sqlite_one"],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(persisted, "PAYPALORDER001");

        drop(reopened);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn idempotent_retry_ignores_server_derived_timestamps() {
        let (path, book) = temp_db();
        let first = intent("pay_idem_retry", "merchant_idem");
        let stored = book
            .create(first.clone(), "idem_retry_001", first.created_at + 1)
            .unwrap();
        assert_eq!(stored, first);

        // A retry arrives later, so the request-derived created_at/expires_at
        // differ even though the business payload and lifetime are identical.
        let mut retry = first.clone();
        retry.created_at += 30;
        retry.expires_at += 30;
        let returned = book
            .create(retry, "idem_retry_001", first.created_at + 31)
            .unwrap();
        assert_eq!(returned, first);

        // Changing a business field under the same key is still a conflict.
        let mut changed = first.clone();
        changed.amount_minor = 2500;
        assert!(book
            .create(changed, "idem_retry_001", first.created_at + 32)
            .is_err());

        drop(book);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn verified_capture_after_authoritative_capture_is_acknowledged_as_duplicate() {
        let (path, book) = temp_db();
        let payment = intent("pay_capture_dup", "merchant_capture_dup");
        book.create(payment.clone(), "idem_capture_dup", payment.created_at + 1)
            .unwrap();
        book.transition(&payment.id, PaymentState::Pending).unwrap();
        book.bind_paypal_order(&payment.id, "PAYPALCAPTUREDUP001")
            .unwrap();

        assert!(book
            .record_authoritative_capture(
                &payment.id,
                "CAPDUP001",
                &"f".repeat(64),
                payment.created_at + 2,
            )
            .unwrap());
        assert_eq!(book.state(&payment.id).unwrap(), PaymentState::Captured);

        // Repeating the same authoritative capture is an idempotent no-op.
        assert!(!book
            .record_authoritative_capture(
                &payment.id,
                "CAPDUP001",
                &"f".repeat(64),
                payment.created_at + 3,
            )
            .unwrap());

        // The same capture ID must never be attached to another payment.
        let other = intent("pay_capture_other", "merchant_capture_other");
        book.create(other.clone(), "idem_capture_other", other.created_at + 1)
            .unwrap();
        book.transition(&other.id, PaymentState::Pending).unwrap();
        book.bind_paypal_order(&other.id, "PAYPALCAPTUREOTHER001")
            .unwrap();
        assert!(book
            .record_authoritative_capture(
                &other.id,
                "CAPDUP001",
                &"f".repeat(64),
                other.created_at + 2,
            )
            .is_err());

        // PayPal may deliver the webhook after our capture call has already
        // reconciled. That must be acknowledged, not rejected, to stop retries.
        assert!(!book
            .record_verified_capture(
                "event_capture_dup",
                "PAYMENT.CAPTURE.COMPLETED",
                &"a".repeat(64),
                payment.created_at + 3,
                &payment.id,
                "CAPDUP001",
            )
            .unwrap());

        let conn = book.conn.lock().unwrap();
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM webhook_events WHERE event_id='event_capture_dup'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
        drop(conn);
        drop(book);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn refunds_are_cumulative_and_cannot_exceed_the_capture() {
        let (path, book) = temp_db();
        let payment = intent("pay_refund_limit", "merchant_refund");
        book.create(payment.clone(), "idem_refund_limit", payment.created_at + 1)
            .unwrap();
        book.transition(&payment.id, PaymentState::Pending).unwrap();
        book.bind_paypal_order(&payment.id, "PAYPALREFUNDLIMIT001")
            .unwrap();
        book.record_authoritative_capture(
            &payment.id,
            "CAPREFUND001",
            &"c".repeat(64),
            payment.created_at + 2,
        )
        .unwrap();

        let (duplicate, full, total) = book
            .record_refund(
                "REFONE001",
                "CAPREFUND001",
                &payment.id,
                "COMPLETED",
                500,
                "USD",
                payment.created_at + 3,
            )
            .unwrap();
        assert!(!duplicate);
        assert!(!full);
        assert_eq!(total, 500);
        let summary = book.list_payments_for_merchant("merchant_refund").unwrap();
        assert_eq!(summary[0].captured_minor, 1299);
        assert_eq!(summary[0].refunded_minor, 500);
        assert_eq!(
            book.capture_details("CAPREFUND001")
                .unwrap()
                .unwrap()
                .status,
            "PARTIALLY_REFUNDED"
        );

        // Replaying the same refund ID is idempotent and does not double count.
        let (duplicate, full, total) = book
            .record_refund(
                "REFONE001",
                "CAPREFUND001",
                &payment.id,
                "COMPLETED",
                500,
                "USD",
                payment.created_at + 4,
            )
            .unwrap();
        assert!(duplicate);
        assert!(!full);
        assert_eq!(total, 500);

        let (_, full, total) = book
            .record_refund(
                "REFTWO001",
                "CAPREFUND001",
                &payment.id,
                "COMPLETED",
                799,
                "USD",
                payment.created_at + 5,
            )
            .unwrap();
        assert!(full);
        assert_eq!(total, 1299);
        let capture = book.capture_details("CAPREFUND001").unwrap().unwrap();
        assert_eq!(capture.refunded_minor, 1299);
        assert_eq!(capture.status, "REFUNDED");
        let summary = book.list_payments_for_merchant("merchant_refund").unwrap();
        assert_eq!(summary[0].refunded_minor, 1299);

        assert!(book
            .record_refund(
                "REFTHREE001",
                "CAPREFUND001",
                &payment.id,
                "COMPLETED",
                1,
                "USD",
                payment.created_at + 6,
            )
            .is_err());

        drop(book);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn verified_capture_accepts_pending_and_deduplicates_event() {
        let (path, book) = temp_db();
        let payment = intent("pay_capture_pending", "merchant_capture");
        book.create(
            payment.clone(),
            "idem_capture_pending",
            payment.created_at + 1,
        )
        .unwrap();
        book.transition(&payment.id, PaymentState::Pending).unwrap();
        book.bind_paypal_order(&payment.id, "PAYPALCAPTURE001")
            .unwrap();

        let hash = "a".repeat(64);
        assert!(book
            .record_verified_capture(
                "event_capture_pending",
                "PAYMENT.CAPTURE.COMPLETED",
                &hash,
                payment.created_at + 2,
                &payment.id,
                "CAPPENDING001",
            )
            .unwrap());

        assert_eq!(book.state(&payment.id).unwrap(), PaymentState::Captured);
        assert!(!book
            .record_verified_capture(
                "event_capture_pending",
                "PAYMENT.CAPTURE.COMPLETED",
                &hash,
                payment.created_at + 3,
                &payment.id,
                "CAPPENDING001",
            )
            .unwrap());

        drop(book);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn verified_capture_rejects_event_id_reuse_with_different_hash() {
        let (path, book) = temp_db();
        let payment = intent("pay_capture_reuse", "merchant_reuse");
        book.create(
            payment.clone(),
            "idem_capture_reuse",
            payment.created_at + 1,
        )
        .unwrap();
        book.transition(&payment.id, PaymentState::Pending).unwrap();
        book.bind_paypal_order(&payment.id, "PAYPALCAPTURE004")
            .unwrap();

        let first_hash = "d".repeat(64);
        assert!(book
            .record_verified_capture(
                "event_capture_reuse",
                "PAYMENT.CAPTURE.COMPLETED",
                &first_hash,
                payment.created_at + 2,
                &payment.id,
                "CAPREUSE001",
            )
            .unwrap());

        assert!(book
            .record_verified_capture(
                "event_capture_reuse",
                "PAYMENT.CAPTURE.COMPLETED",
                &"e".repeat(64),
                payment.created_at + 3,
                &payment.id,
                "CAPREUSE001",
            )
            .is_err());

        assert_eq!(book.state(&payment.id).unwrap(), PaymentState::Captured);

        let conn = book.conn.lock().unwrap();
        let stored_hash: String = conn
            .query_row(
                "SELECT payload_sha256 FROM webhook_events WHERE event_id=?1",
                ["event_capture_reuse"],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(stored_hash, first_hash);

        drop(conn);
        drop(book);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn verified_capture_accepts_authorized_payment() {
        let (path, book) = temp_db();
        let payment = intent("pay_capture_auth", "merchant_auth");
        book.create(payment.clone(), "idem_capture_auth", payment.created_at + 1)
            .unwrap();
        book.transition(&payment.id, PaymentState::Pending).unwrap();
        book.transition(&payment.id, PaymentState::Authorized)
            .unwrap();
        book.bind_paypal_order(&payment.id, "PAYPALCAPTURE002")
            .unwrap();

        assert!(book
            .record_verified_capture(
                "event_capture_auth",
                "PAYMENT.CAPTURE.COMPLETED",
                &"b".repeat(64),
                payment.created_at + 2,
                &payment.id,
                "CAPAUTH001",
            )
            .unwrap());
        assert_eq!(book.state(&payment.id).unwrap(), PaymentState::Captured);

        drop(book);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn rejected_capture_rolls_back_webhook_event() {
        let (path, book) = temp_db();
        let payment = intent("pay_capture_invalid", "merchant_invalid");
        book.create(
            payment.clone(),
            "idem_capture_invalid",
            payment.created_at + 1,
        )
        .unwrap();
        book.bind_paypal_order(&payment.id, "PAYPALCAPTURE003")
            .unwrap();

        assert!(book
            .record_verified_capture(
                "event_capture_invalid",
                "PAYMENT.CAPTURE.COMPLETED",
                &"c".repeat(64),
                payment.created_at + 2,
                &payment.id,
                "CAPINVALID001",
            )
            .is_err());

        let conn = book.conn.lock().unwrap();
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM webhook_events WHERE event_id=?1",
                ["event_capture_invalid"],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 0);
        drop(conn);
        drop(book);
        let _ = std::fs::remove_file(path);
    }
}
