//! Disposable synthetic fixtures for offline attack execution.
//!
//! Every fixture gets its own temporary directory, SQLite database and
//! throwaway post-quantum key set. No real payment, PayPal credential, order or
//! key material is used, read or contacted.

use anyhow::{Context, Result};
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::payment_security::{CryptoKeys, PaymentAuthorization, SecurityStore};
use crate::payments::{PaymentIntent, PaymentState, SqlitePaymentBook};

pub const SYNTHETIC_PAYMENT_ID: &str = "pay_redteam_valid";
pub const SYNTHETIC_MERCHANT_ID: &str = "merchant_redteam";
pub const SYNTHETIC_ORDER_ID: &str = "ORDERXRT001";
pub const SYNTHETIC_CAPTURE_ID: &str = "CAPTURXRT001";
pub const SYNTHETIC_AMOUNT_MINOR: u64 = 2599;

pub struct Fixture {
    pub root: PathBuf,
    pub db_path: PathBuf,
    pub keys: CryptoKeys,
    pub security: SecurityStore,
    pub book: SqlitePaymentBook,
    pub intent: PaymentIntent,
    pub now: u64,
}

impl Fixture {
    pub fn new(label: &str) -> Result<Self> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock is before the Unix epoch")?
            .as_secs();
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|value| value.as_nanos())
            .unwrap_or(0);
        let label: String = label
            .chars()
            .filter(|value| value.is_ascii_alphanumeric())
            .take(32)
            .collect();
        let root = std::env::temp_dir().join(format!(
            "qs-redteam-{}-{stamp}-{}",
            std::process::id(),
            if label.is_empty() { "attack" } else { &label }
        ));
        fs::create_dir_all(&root)
            .with_context(|| format!("cannot create fixture directory {}", root.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
        }

        let keys = CryptoKeys::open_or_create(root.join("keys"), "redteam-key-1")?;
        let db_path = root.join("redteam.sqlite3");
        let security = SecurityStore::open(&db_path)?;
        let book = SqlitePaymentBook::open_existing_for_tests(&db_path)?;

        let intent = PaymentIntent {
            id: SYNTHETIC_PAYMENT_ID.into(),
            merchant_id: SYNTHETIC_MERCHANT_ID.into(),
            amount_minor: SYNTHETIC_AMOUNT_MINOR,
            currency: "USD".into(),
            description: "Synthetic offline red-team payment".into(),
            created_at: now.saturating_sub(10),
            expires_at: now.saturating_add(600),
        };
        book.create(intent.clone(), "idem_redteam_valid", now)?;
        book.transition(&intent.id, PaymentState::Pending)?;
        book.bind_paypal_order(&intent.id, SYNTHETIC_ORDER_ID)?;

        Ok(Self {
            root,
            db_path,
            keys,
            security,
            book,
            intent,
            now,
        })
    }

    pub fn auth(&self) -> Result<PaymentAuthorization> {
        crate::payment_security::create_authorization(
            &self.keys,
            &self.intent,
            SYNTHETIC_ORDER_ID,
            None,
            300,
        )
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
