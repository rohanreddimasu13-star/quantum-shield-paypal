//! Deterministic payment-security core: post-quantum authorization integrity,
//! hybrid ML-KEM-768 data protection, replay defence, hash-chained audit and
//! independently verifiable transaction evidence.
//!
//! Algorithms (all real, FIPS-standardised implementations from AWS-LC):
//! - ML-KEM-768 (FIPS 203) for key establishment
//! - ML-DSA-65 (FIPS 204) for authorization/evidence signatures
//! - HKDF-SHA-256 + AES-256-GCM for authenticated payment-data protection
//! - SHA-256 for hashing and hash chaining

use anyhow::{bail, Context, Result};
use aws_lc_rs::{
    aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM},
    digest::{digest, SHA256},
    encoding::AsRawBytes,
    hkdf::{Salt, HKDF_SHA256},
    kem::{Ciphertext, DecapsulationKey, EncapsulationKey, ML_KEM_768},
    rand::{SecureRandom, SystemRandom},
    signature::{KeyPair, PqdsaKeyPair, UnparsedPublicKey, ML_DSA_65, ML_DSA_65_SIGNING},
};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use rusqlite::OptionalExtension;
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;

use crate::payments::{PaymentIntent, PaymentState, SqlitePaymentBook};

pub const EVIDENCE_FORMAT: &str = "qs-payment-evidence-v1";
pub const ENVELOPE_FORMAT: &str = "qs-hybrid-envelope-v1";
pub const AUTH_FORMAT: &str = "qs-payment-authorization-v1";
pub const ML_KEM_ALG: &str = "ML-KEM-768";
pub const ML_DSA_ALG: &str = "ML-DSA-65";
pub const AEAD_ALG: &str = "AES-256-GCM";
pub const KDF_ALG: &str = "HKDF-SHA-256";

fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    digest(&SHA256, bytes)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn b64(bytes: impl AsRef<[u8]>) -> String {
    B64.encode(bytes.as_ref())
}

fn unb64(value: &str, max: usize) -> Result<Vec<u8>> {
    let bytes = B64.decode(value).context("invalid base64 encoding")?;
    if bytes.len() > max {
        bail!("decoded field exceeds size limit");
    }
    Ok(bytes)
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn write_new_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts
        .open(path)
        .with_context(|| format!("could not create {}; refusing to overwrite", path.display()))?;
    if let Err(error) = file.write_all(bytes).and_then(|_| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(error.into());
    }
    Ok(())
}

fn read_private(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    let meta = fs::symlink_metadata(path)?;
    if meta.file_type().is_symlink() || !meta.is_file() {
        bail!("key material {} must be a regular file", path.display());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o077 != 0 {
            bail!("private key {} must have mode 600", path.display());
        }
    }
    Ok(Zeroizing::new(fs::read(path)?))
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SealedEnvelope {
    pub format: String,
    pub version: u8,
    pub kem_algorithm: String,
    pub key_id: String,
    pub kem_ciphertext: String,
    pub nonce: String,
    pub ciphertext: String,
    pub aad_sha256: String,
}

/// Long-lived PQ key material held outside the database, mode 0600.
pub struct CryptoKeys {
    pub key_id: String,
    /// Operator-supplied numeric suffix, e.g. payment-key-3 => version 3.
    pub key_version: u32,
    pub dir: PathBuf,
    decapsulation: DecapsulationKey,
    encapsulation: EncapsulationKey,
    signing: PqdsaKeyPair,
}

impl CryptoKeys {
    pub fn open_or_create(dir: impl AsRef<Path>, key_id: &str) -> Result<Self> {
        if !valid_id(key_id) {
            bail!("invalid key ID");
        }
        let key_version = key_id
            .rsplit('-')
            .next()
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(1);
        if key_version == 0 {
            bail!("key version must be greater than zero");
        }
        let dir = dir.as_ref().to_path_buf();
        fs::create_dir_all(&dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
        }
        let kem_sk_path = dir.join(format!("{key_id}.mlkem768.sk"));
        let kem_pk_path = dir.join(format!("{key_id}.mlkem768.pk"));
        let sig_sk_path = dir.join(format!("{key_id}.mldsa65.sk"));
        let sig_pk_path = dir.join(format!("{key_id}.mldsa65.pk"));

        let exists = [&kem_sk_path, &kem_pk_path, &sig_sk_path, &sig_pk_path];
        if exists.iter().all(|p| p.exists()) {
            let dk = DecapsulationKey::new(&ML_KEM_768, &read_private(&kem_sk_path)?)
                .map_err(|e| anyhow::anyhow!("invalid ML-KEM-768 private key: {e}"))?;
            let ek = EncapsulationKey::new(&ML_KEM_768, &read_private(&kem_pk_path)?)
                .map_err(|e| anyhow::anyhow!("invalid ML-KEM-768 public key: {e}"))?;
            let signing = PqdsaKeyPair::from_raw_private_key(
                &ML_DSA_65_SIGNING,
                &read_private(&sig_sk_path)?,
            )
            .map_err(|e| anyhow::anyhow!("invalid ML-DSA-65 private key: {e}"))?;
            let stored_pk = read_private(&sig_pk_path)?;
            if stored_pk.as_slice() != signing.public_key().as_ref() {
                bail!("ML-DSA-65 public/private key material does not match");
            }
            return Ok(Self {
                key_id: key_id.to_owned(),
                key_version,
                dir,
                decapsulation: dk,
                encapsulation: ek,
                signing,
            });
        }
        if exists.iter().any(|p| p.exists()) {
            bail!("incomplete PQ key set; refusing silent regeneration");
        }

        let dk = DecapsulationKey::generate(&ML_KEM_768)
            .map_err(|e| anyhow::anyhow!("ML-KEM-768 key generation failed: {e}"))?;
        let ek = dk
            .encapsulation_key()
            .map_err(|e| anyhow::anyhow!("ML-KEM-768 public key derivation failed: {e}"))?;
        let sk_bytes = dk.key_bytes().map_err(|e| anyhow::anyhow!("{e}"))?;
        let pk_bytes = ek.key_bytes().map_err(|e| anyhow::anyhow!("{e}"))?;
        let signing = PqdsaKeyPair::generate(&ML_DSA_65_SIGNING)
            .map_err(|e| anyhow::anyhow!("ML-DSA-65 key generation failed: {e}"))?;
        let sig_sk = signing
            .private_key()
            .as_raw_bytes()
            .map_err(|e| anyhow::anyhow!("ML-DSA-65 private key export failed: {e}"))?;
        let sig_pk = signing.public_key().as_ref();

        write_new_private(&kem_sk_path, sk_bytes.as_ref())?;
        write_new_private(&kem_pk_path, pk_bytes.as_ref())?;
        write_new_private(&sig_sk_path, sig_sk.as_ref())?;
        write_new_private(&sig_pk_path, sig_pk)?;

        Ok(Self {
            key_id: key_id.to_owned(),
            key_version,
            dir,
            decapsulation: dk,
            encapsulation: ek,
            signing,
        })
    }

    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        let mut signature = vec![0u8; ML_DSA_65_SIGNING.signature_len()];
        let len = self
            .signing
            .sign(message, &mut signature)
            .map_err(|e| anyhow::anyhow!("ML-DSA-65 signing failed: {e}"))?;
        signature.truncate(len);
        Ok(signature)
    }

    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<()> {
        UnparsedPublicKey::new(&ML_DSA_65, self.signing.public_key().as_ref())
            .verify(message, signature)
            .map_err(|_| anyhow::anyhow!("ML-DSA-65 signature verification failed"))
    }

    pub fn public_keys(&self) -> Result<KeyStatus> {
        let kem = self
            .encapsulation
            .key_bytes()
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        Ok(KeyStatus {
            key_id: self.key_id.clone(),
            ml_kem_768_public_key: b64(kem.as_ref()),
            ml_dsa_65_public_key: b64(self.signing.public_key().as_ref()),
            ml_kem_fingerprint_sha256: sha256_hex(kem.as_ref()),
            ml_dsa_fingerprint_sha256: sha256_hex(self.signing.public_key().as_ref()),
            status: if crate::payment_security::key_revoked(&self.dir, &self.key_id) {
                "revoked".into()
            } else {
                "active".into()
            },
            version: self.key_version,
        })
    }

    pub fn seal(&self, aad: &[u8], plaintext: &[u8]) -> Result<SealedEnvelope> {
        if aad.is_empty() || aad.len() > 65_536 {
            bail!("payment AAD must be 1..=65536 bytes");
        }
        if plaintext.len() > 1024 * 1024 {
            bail!("payment payload exceeds 1 MiB");
        }
        let (ct, secret) = self
            .encapsulation
            .encapsulate()
            .map_err(|e| anyhow::anyhow!("ML-KEM-768 encapsulation failed: {e}"))?;
        let key = derive_key(secret.as_ref(), aad)?;
        let mut nonce_bytes = [0u8; 12];
        SystemRandom::new()
            .fill(&mut nonce_bytes)
            .map_err(|_| anyhow::anyhow!("secure nonce generation failed"))?;
        let unbound = UnboundKey::new(&AES_256_GCM, &key[..])
            .map_err(|e| anyhow::anyhow!("AES-256-GCM init failed: {e}"))?;
        let mut ciphertext = plaintext.to_vec();
        LessSafeKey::new(unbound)
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce_bytes),
                Aad::from(aad),
                &mut ciphertext,
            )
            .map_err(|_| anyhow::anyhow!("AES-256-GCM encryption failed"))?;
        Ok(SealedEnvelope {
            format: ENVELOPE_FORMAT.into(),
            version: 1,
            kem_algorithm: ML_KEM_ALG.into(),
            key_id: self.key_id.clone(),
            kem_ciphertext: b64(ct.as_ref()),
            nonce: b64(nonce_bytes),
            ciphertext: b64(&ciphertext),
            aad_sha256: sha256_hex(aad),
        })
    }

    pub fn open(&self, aad: &[u8], envelope: &SealedEnvelope) -> Result<Vec<u8>> {
        if envelope.format != ENVELOPE_FORMAT
            || envelope.version != 1
            || envelope.kem_algorithm != ML_KEM_ALG
        {
            bail!("unsupported cryptographic envelope version or algorithm");
        }
        if envelope.key_id != self.key_id {
            bail!("envelope key ID is unknown or not the active key");
        }
        if sha256_hex(aad) != envelope.aad_sha256 {
            bail!("envelope context does not match");
        }
        let ct = unb64(&envelope.kem_ciphertext, 4096)?;
        let nonce = unb64(&envelope.nonce, 12)?;
        let mut ciphertext = unb64(&envelope.ciphertext, 1024 * 1024 + 16)?;
        if nonce.len() != 12 || ciphertext.len() < 16 {
            bail!("truncated encrypted envelope");
        }
        let secret = self
            .decapsulation
            .decapsulate(Ciphertext::from(ct.as_slice()))
            .map_err(|_| anyhow::anyhow!("ML-KEM-768 decapsulation failed"))?;
        let key = derive_key(secret.as_ref(), aad)?;
        let unbound = UnboundKey::new(&AES_256_GCM, &key[..])
            .map_err(|e| anyhow::anyhow!("AES-256-GCM init failed: {e}"))?;
        let nonce: [u8; 12] = nonce.try_into().map_err(|_| anyhow::anyhow!("bad nonce"))?;
        let len = LessSafeKey::new(unbound)
            .open_in_place(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(aad),
                &mut ciphertext,
            )
            .map_err(|_| anyhow::anyhow!("authentication failed: modified ciphertext or context"))?
            .len();
        ciphertext.truncate(len);
        Ok(ciphertext)
    }
}

fn derive_key(secret: &[u8], aad: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let context = sha256_hex(aad);
    let salt = Salt::new(HKDF_SHA256, &digest(&SHA256, aad).as_ref()[..16]);
    let prk = salt.extract(secret);
    let info = [b"quantum-shield/payment-data/v1", context.as_bytes()];
    let okm = prk
        .expand(&info, HKDF_SHA256)
        .map_err(|e| anyhow::anyhow!("HKDF-SHA-256 expand failed: {e}"))?;
    let mut key = Zeroizing::new([0u8; 32]);
    okm.fill(&mut *key)
        .map_err(|e| anyhow::anyhow!("HKDF-SHA-256 fill failed: {e}"))?;
    Ok(key)
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct KeyStatus {
    pub key_id: String,
    pub version: u32,
    pub status: String,
    pub ml_kem_768_public_key: String,
    pub ml_dsa_65_public_key: String,
    pub ml_kem_fingerprint_sha256: String,
    pub ml_dsa_fingerprint_sha256: String,
}

fn key_revoked(dir: &Path, key_id: &str) -> bool {
    dir.join(format!("{key_id}.revoked")).is_file()
}

pub fn revoke_key(dir: &Path, key_id: &str) -> Result<()> {
    if !valid_id(key_id) {
        bail!("invalid key ID");
    }
    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(dir.join(format!("{key_id}.revoked")))
    {
        Ok(mut f) => {
            f.write_all(b"revoked\n")?;
            f.sync_all()?;
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// Open the operator key directory from QS_KEY_DIR (or the private default).
pub fn open_default_keys() -> Result<CryptoKeys> {
    let dir = std::env::var_os("QS_KEY_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(std::env::var_os("HOME").unwrap_or_else(|| ".".into()))
                .join(".local/state/quantum-shield/payment-pq-keys")
        });
    let key_id = std::env::var("QS_KEY_ID").unwrap_or_else(|_| "payment-key-1".to_owned());
    CryptoKeys::open_or_create(dir, &key_id)
}

pub fn keys_dir() -> Result<PathBuf> {
    Ok(std::env::var_os("QS_KEY_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(std::env::var_os("HOME").unwrap_or_else(|| ".".into()))
                .join(".local/state/quantum-shield/payment-pq-keys")
        }))
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PaymentAuthorization {
    pub format: String,
    pub version: u8,
    pub algorithm: String,
    pub key_id: String,
    pub merchant_id: String,
    pub payment_id: String,
    pub amount_minor: u64,
    pub currency: String,
    pub paypal_order_id: String,
    pub capture_id: Option<String>,
    pub issued_at: u64,
    pub expires_at: u64,
    pub nonce: String,
    pub signature: String,
}

impl PaymentAuthorization {
    pub(crate) fn signing_bytes(&self) -> Result<Vec<u8>> {
        #[derive(Serialize)]
        struct Unsigned<'a> {
            format: &'a str,
            version: u8,
            algorithm: &'a str,
            key_id: &'a str,
            merchant_id: &'a str,
            payment_id: &'a str,
            amount_minor: u64,
            currency: &'a str,
            paypal_order_id: &'a str,
            capture_id: &'a Option<String>,
            issued_at: u64,
            expires_at: u64,
            nonce: &'a str,
        }
        Ok(serde_json::to_vec(&Unsigned {
            format: &self.format,
            version: self.version,
            algorithm: &self.algorithm,
            key_id: &self.key_id,
            merchant_id: &self.merchant_id,
            payment_id: &self.payment_id,
            amount_minor: self.amount_minor,
            currency: &self.currency,
            paypal_order_id: &self.paypal_order_id,
            capture_id: &self.capture_id,
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            nonce: &self.nonce,
        })?)
    }

    pub fn verify_structure(&self) -> Result<()> {
        if self.format != AUTH_FORMAT || self.version != 1 || self.algorithm != ML_DSA_ALG {
            bail!("unsupported authorization format or algorithm");
        }
        if !valid_id(&self.merchant_id)
            || !valid_id(&self.payment_id)
            || !valid_id(&self.key_id)
            || !valid_id(&self.nonce)
        {
            bail!("authorization contains an invalid identifier");
        }
        if self.amount_minor == 0 || self.amount_minor > crate::payments::MAX_AMOUNT_MINOR {
            bail!("authorization amount is outside the permitted range");
        }
        if self.currency.len() != 3 || !self.currency.bytes().all(|b| b.is_ascii_uppercase()) {
            bail!("authorization currency is invalid");
        }
        if self.expires_at <= self.issued_at {
            bail!("authorization expiry is invalid");
        }
        if let Some(capture) = &self.capture_id {
            if capture.is_empty()
                || capture.len() > 64
                || !capture.bytes().all(|b| b.is_ascii_alphanumeric())
            {
                bail!("capture identifier is invalid");
            }
        }
        if !self.paypal_order_id.is_empty()
            && (self.paypal_order_id.len() > 64
                || !self
                    .paypal_order_id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric()))
        {
            bail!("PayPal order identifier is invalid");
        }
        Ok(())
    }
}

pub fn create_authorization(
    keys: &CryptoKeys,
    intent: &PaymentIntent,
    paypal_order_id: &str,
    capture_id: Option<String>,
    ttl_seconds: u64,
) -> Result<PaymentAuthorization> {
    let issued_at = now()?;
    let mut nonce_bytes = [0u8; 16];
    SystemRandom::new()
        .fill(&mut nonce_bytes)
        .map_err(|_| anyhow::anyhow!("secure nonce generation failed"))?;
    let mut auth = PaymentAuthorization {
        format: AUTH_FORMAT.into(),
        version: 1,
        algorithm: ML_DSA_ALG.into(),
        key_id: keys.key_id.clone(),
        merchant_id: intent.merchant_id.clone(),
        payment_id: intent.id.clone(),
        amount_minor: intent.amount_minor,
        currency: intent.currency.clone(),
        paypal_order_id: paypal_order_id.to_owned(),
        capture_id,
        issued_at,
        expires_at: issued_at.saturating_add(ttl_seconds.clamp(1, 900)),
        nonce: sha256_hex(&nonce_bytes)[..32].to_owned(),
        signature: String::new(),
    };
    auth.verify_structure()?;
    auth.signature = b64(keys.sign(&auth.signing_bytes()?)?);
    Ok(auth)
}

pub struct SecurityStore {
    conn: std::sync::Mutex<rusqlite::Connection>,
}

impl SecurityStore {
    pub fn open_default() -> Result<Self> {
        Self::open(crate::payments::default_db_path()?)
    }

    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let conn = rusqlite::Connection::open(path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        }
        conn.busy_timeout(std::time::Duration::from_secs(10))?;
        conn.execute_batch(
            "PRAGMA foreign_keys=ON;
             CREATE TABLE IF NOT EXISTS payment_evidence (
               payment_id TEXT PRIMARY KEY,
               sequence INTEGER NOT NULL UNIQUE,
               record_json TEXT NOT NULL,
               chain_hash TEXT NOT NULL,
               created_at INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS security_events (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               created_at INTEGER NOT NULL,
               kind TEXT NOT NULL,
               severity TEXT NOT NULL,
               payment_id TEXT,
               detail TEXT NOT NULL,
               prev_hash TEXT NOT NULL,
               entry_hash TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS authorization_nonces (
               nonce TEXT PRIMARY KEY,
               payment_id TEXT NOT NULL,
               expires_at INTEGER NOT NULL,
               used_at INTEGER NOT NULL
             );
             PRAGMA user_version=2;",
        )?;
        Ok(Self {
            conn: std::sync::Mutex::new(conn),
        })
    }

    pub fn log_event(
        &self,
        kind: &str,
        severity: &str,
        payment_id: Option<&str>,
        detail: &str,
    ) -> Result<()> {
        if !["info", "verified", "warning", "rejected"].contains(&severity) {
            bail!("invalid event severity");
        }
        if detail.len() > 2048 || kind.is_empty() || kind.len() > 64 {
            bail!("invalid security event");
        }
        let mut conn = self
            .conn
            .lock()
            .map_err(|_| anyhow::anyhow!("security store lock poisoned"))?;
        let tx = conn.transaction()?;
        let previous: Option<String> = tx
            .query_row(
                "SELECT entry_hash FROM security_events ORDER BY id DESC LIMIT 1",
                [],
                |r| r.get(0),
            )
            .optional()?;
        let prev = previous.unwrap_or_else(|| "0".repeat(64));
        let created = now()?;
        let material = format!(
            "{prev}\n{created}\n{kind}\n{severity}\n{}\n{detail}",
            payment_id.unwrap_or("")
        );
        let entry = sha256_hex(material.as_bytes());
        tx.execute(
            "INSERT INTO security_events
             (created_at, kind, severity, payment_id, detail, prev_hash, entry_hash)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![created, kind, severity, payment_id, detail, prev, entry],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn consume_nonce(&self, auth: &PaymentAuthorization, at: u64) -> Result<()> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| anyhow::anyhow!("security store lock poisoned"))?;
        let inserted = conn.execute(
            "INSERT OR IGNORE INTO authorization_nonces
             (nonce, payment_id, expires_at, used_at) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![auth.nonce, auth.payment_id, auth.expires_at, at],
        )?;
        if inserted != 1 {
            bail!("replayed authorization nonce");
        }
        Ok(())
    }

    pub fn append_evidence(&self, record: &EvidenceRecord, keys: &CryptoKeys) -> Result<()> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| anyhow::anyhow!("security store lock poisoned"))?;
        let prior: Option<(i64, String)> = conn
            .query_row(
                "SELECT sequence, chain_hash FROM payment_evidence ORDER BY sequence DESC LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let (sequence, prev) = match prior {
            Some((seq, hash)) => (seq + 1, hash),
            None => (1, "0".repeat(64)),
        };
        let mut final_record = record.clone();
        final_record.sequence = sequence;
        final_record.previous_hash = prev.clone();
        final_record.chain_hash = final_record.compute_chain_hash()?;
        // The chain hash covers `previous_hash`, so the signature must be
        // produced after the chain position is final. Otherwise an exported
        // record would fail independent verification.
        if final_record.key_id != keys.key_id {
            bail!("evidence key ID does not match the signing key");
        }
        final_record.ml_dsa_signature = b64(keys.sign(&final_record.signing_bytes()?)?);
        conn.execute(
            "INSERT INTO payment_evidence
             (payment_id, sequence, record_json, chain_hash, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                final_record.payment_id,
                sequence,
                serde_json::to_string(&final_record)?,
                final_record.chain_hash,
                final_record.created_at
            ],
        )?;
        Ok(())
    }

    pub fn evidence_for(&self, payment_id: &str) -> Result<Option<EvidenceRecord>> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| anyhow::anyhow!("security store lock poisoned"))?;
        let json: Option<String> = conn
            .query_row(
                "SELECT record_json FROM payment_evidence WHERE payment_id=?1",
                [payment_id],
                |r| r.get(0),
            )
            .optional()?;
        Ok(match json {
            Some(j) => Some(serde_json::from_str(&j)?),
            None => None,
        })
    }

    pub fn export_all_evidence(&self) -> Result<Vec<EvidenceRecord>> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| anyhow::anyhow!("security store lock poisoned"))?;
        let mut stmt =
            conn.prepare("SELECT record_json FROM payment_evidence ORDER BY sequence ASC")?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(serde_json::from_str(&row?)?);
        }
        Ok(out)
    }

    pub fn recent_events(&self, limit: usize) -> Result<Vec<SecurityEvent>> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| anyhow::anyhow!("security store lock poisoned"))?;
        let mut stmt = conn.prepare(
            "SELECT id, created_at, kind, severity, payment_id, detail, prev_hash, entry_hash
             FROM security_events ORDER BY id DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map([limit.clamp(1, 500) as i64], |r| {
            Ok(SecurityEvent {
                id: r.get(0)?,
                created_at: r.get(1)?,
                kind: r.get(2)?,
                severity: r.get(3)?,
                payment_id: r.get(4)?,
                detail: r.get(5)?,
                prev_hash: r.get(6)?,
                entry_hash: r.get(7)?,
            })
        })?;
        let mut events = Vec::new();
        for row in rows {
            events.push(row?);
        }
        Ok(events)
    }

    /// Recompute the audit hash chain from the database. Detects edits,
    /// deletions (via the broken prev-hash link) and reordering.
    pub fn verify_event_chain(&self) -> Result<usize> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| anyhow::anyhow!("security store lock poisoned"))?;
        let mut stmt = conn.prepare(
            "SELECT created_at, kind, severity, payment_id, detail, prev_hash, entry_hash
             FROM security_events ORDER BY id ASC",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, u64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, Option<String>>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, String>(5)?,
                r.get::<_, String>(6)?,
            ))
        })?;
        let mut previous = "0".repeat(64);
        let mut count = 0usize;
        for row in rows {
            let (created_at, kind, severity, payment_id, detail, prev_hash, entry_hash) = row?;
            if prev_hash != previous {
                bail!("audit chain is broken before entry {count}");
            }
            let material = format!(
                "{prev_hash}\n{created_at}\n{kind}\n{severity}\n{}\n{detail}",
                payment_id.unwrap_or_default()
            );
            if sha256_hex(material.as_bytes()) != entry_hash {
                bail!("audit entry {count} was modified");
            }
            previous = entry_hash;
            count += 1;
        }
        Ok(count)
    }

    pub fn counts(&self) -> Result<Counts> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| anyhow::anyhow!("security store lock poisoned"))?;
        let evidence: i64 =
            conn.query_row("SELECT COUNT(*) FROM payment_evidence", [], |r| r.get(0))?;
        let rejected: i64 = conn.query_row(
            "SELECT COUNT(*) FROM security_events WHERE severity='rejected'",
            [],
            |r| r.get(0),
        )?;
        let verified: i64 =
            conn.query_row("SELECT COUNT(*) FROM payment_evidence", [], |r| r.get(0))?;
        let events: i64 =
            conn.query_row("SELECT COUNT(*) FROM security_events", [], |r| r.get(0))?;
        Ok(Counts {
            evidence_records: evidence,
            verified_transactions: verified,
            rejected_events: rejected,
            security_events: events,
        })
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct SecurityEvent {
    pub id: i64,
    pub created_at: u64,
    pub kind: String,
    pub severity: String,
    pub payment_id: Option<String>,
    pub detail: String,
    pub prev_hash: String,
    pub entry_hash: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Counts {
    pub evidence_records: i64,
    pub verified_transactions: i64,
    pub rejected_events: i64,
    pub security_events: i64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EvidenceRecord {
    pub format: String,
    pub version: u8,
    pub sequence: i64,
    pub payment_id: String,
    pub merchant_id: String,
    pub amount_minor: u64,
    pub currency: String,
    pub paypal_order_id: String,
    pub paypal_capture_id: String,
    pub state: String,
    pub verification_result: String,
    pub signature_verified: bool,
    pub ml_kem_algorithm: String,
    pub ml_dsa_algorithm: String,
    pub aead_algorithm: String,
    pub kdf_algorithm: String,
    pub key_id: String,
    pub key_version: u32,
    pub webhook_event_id: String,
    pub webhook_payload_sha256: String,
    pub reconciled_at: u64,
    pub created_at: u64,
    pub previous_hash: String,
    pub chain_hash: String,
    pub ml_dsa_public_key: String,
    pub ml_dsa_signature: String,
}

impl EvidenceRecord {
    pub fn compute_chain_hash(&self) -> Result<String> {
        let material = format!(
            "{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}",
            self.format,
            self.version,
            self.sequence,
            self.payment_id,
            self.merchant_id,
            self.amount_minor,
            self.currency,
            self.paypal_order_id,
            self.paypal_capture_id,
            self.state,
            self.verification_result,
            self.signature_verified,
            self.key_id,
            self.key_version,
            self.webhook_event_id,
            self.webhook_payload_sha256,
            self.reconciled_at,
            self.previous_hash
        );
        Ok(sha256_hex(material.as_bytes()))
    }

    fn signing_bytes(&self) -> Result<Vec<u8>> {
        Ok(format!("{}\n{}", self.chain_hash, self.format).into_bytes())
    }
}

pub struct EvidenceInput<'a> {
    pub intent: &'a PaymentIntent,
    pub paypal_order_id: &'a str,
    pub capture_id: &'a str,
    pub event_id: &'a str,
    pub payload_sha256: &'a str,
    pub reconciled_at: u64,
    pub authorization: &'a PaymentAuthorization,
    pub authorization_verified: bool,
    pub keys: &'a CryptoKeys,
}

pub fn build_evidence(input: EvidenceInput<'_>) -> Result<EvidenceRecord> {
    // Structural validation only. A capture completed just before the intent's
    // approval window closed is still a valid transaction even if its webhook
    // is reconciled after that window; capture authorization is verified
    // separately with its own expiry.
    if input.intent.validate(input.intent.created_at).is_err() {
        bail!("payment intent is structurally invalid");
    }
    if !input.authorization_verified || input.authorization.payment_id != input.intent.id {
        bail!("evidence requires a verified payment authorization");
    }
    let created_at = now()?;
    let mut record = EvidenceRecord {
        format: EVIDENCE_FORMAT.into(),
        version: 1,
        sequence: 0,
        payment_id: input.intent.id.clone(),
        merchant_id: input.intent.merchant_id.clone(),
        amount_minor: input.intent.amount_minor,
        currency: input.intent.currency.clone(),
        paypal_order_id: input.paypal_order_id.into(),
        paypal_capture_id: input.capture_id.into(),
        state: "captured".into(),
        verification_result: "verified".into(),
        signature_verified: true,
        ml_kem_algorithm: ML_KEM_ALG.into(),
        ml_dsa_algorithm: ML_DSA_ALG.into(),
        aead_algorithm: AEAD_ALG.into(),
        kdf_algorithm: KDF_ALG.into(),
        key_id: input.keys.key_id.clone(),
        key_version: input.keys.key_version,
        webhook_event_id: input.event_id.into(),
        webhook_payload_sha256: input.payload_sha256.into(),
        reconciled_at: input.reconciled_at,
        created_at,
        previous_hash: String::new(),
        chain_hash: String::new(),
        ml_dsa_public_key: b64(input.keys.signing.public_key().as_ref()),
        ml_dsa_signature: String::new(),
    };
    record.chain_hash = record.compute_chain_hash()?;
    record.ml_dsa_signature = b64(input.keys.sign(&record.signing_bytes()?)?);
    Ok(record)
}

/// Independent verification: needs only the exported JSON and SHA-256/ML-DSA
/// public-key verification. It does not read the dashboard or local database.
pub fn verify_evidence(record: &EvidenceRecord) -> Result<()> {
    if record.format != EVIDENCE_FORMAT
        || record.version != 1
        || record.verification_result != "verified"
        || !record.signature_verified
    {
        bail!("unsupported or unverified evidence format");
    }
    let recomputed = record.compute_chain_hash()?;
    if recomputed != record.chain_hash {
        bail!("evidence integrity hash mismatch: record was modified");
    }
    let public = unb64(&record.ml_dsa_public_key, 4096)?;
    let signature = unb64(&record.ml_dsa_signature, 8192)?;
    UnparsedPublicKey::new(&ML_DSA_65, &public)
        .verify(&record.signing_bytes()?, &signature)
        .map_err(|_| anyhow::anyhow!("ML-DSA-65 evidence signature verification failed"))?;
    Ok(())
}

pub fn verify_evidence_chain(records: &[EvidenceRecord]) -> Result<()> {
    let mut previous = "0".repeat(64);
    for (index, record) in records.iter().enumerate() {
        verify_evidence(record)?;
        let expected_sequence =
            i64::try_from(index + 1).map_err(|_| anyhow::anyhow!("evidence chain is too long"))?;
        if record.sequence != expected_sequence {
            bail!("evidence sequence mismatch: expected {expected_sequence}");
        }
        if record.previous_hash != previous {
            bail!(
                "evidence hash chain is broken at sequence {}",
                record.sequence
            );
        }
        previous = record.chain_hash.clone();
    }
    Ok(())
}

/// Verify a payment authorization against the locally stored intent and order
/// binding, enforce expiry, and persist the nonce exactly once.
pub struct AuthorizationExpectation<'a> {
    pub intent: &'a PaymentIntent,
    pub paypal_order_id: &'a str,
    pub capture_id: Option<&'a str>,
    pub expected_key_id: &'a str,
    pub now: u64,
}

pub fn verify_authorization(
    keys: &CryptoKeys,
    auth: &PaymentAuthorization,
    store: &SecurityStore,
    expected: AuthorizationExpectation<'_>,
) -> Result<()> {
    auth.verify_structure()?;
    if auth.key_id != expected.expected_key_id || auth.key_id != keys.key_id {
        bail!("authorization is bound to an unknown or revoked key");
    }
    if key_revoked(&keys.dir, &keys.key_id) {
        bail!("authorization signing key has been revoked");
    }
    if auth.merchant_id != expected.intent.merchant_id
        || auth.payment_id != expected.intent.id
        || auth.amount_minor != expected.intent.amount_minor
        || auth.currency != expected.intent.currency
        || auth.paypal_order_id != expected.paypal_order_id
        || auth.capture_id.as_deref() != expected.capture_id
    {
        bail!("authorization does not match merchant, payment, amount, currency, order or capture");
    }
    if auth.expires_at <= expected.now {
        bail!("authorization has expired");
    }
    if auth.issued_at > expected.now.saturating_add(30) {
        bail!("authorization issue time is in the future");
    }
    let signature = unb64(&auth.signature, 8192)?;
    keys.verify(&auth.signing_bytes()?, &signature)?;
    store.consume_nonce(auth, expected.now)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Deterministic security lab
// ---------------------------------------------------------------------------

#[derive(Serialize, Clone, Debug)]
pub struct ScenarioResult {
    pub id: u32,
    pub scenario: String,
    pub expected: String,
    pub actual: String,
    pub passed: bool,
    pub error_class: String,
}

fn scenario(
    results: &mut Vec<ScenarioResult>,
    id: u32,
    name: &str,
    expected: &str,
    outcome: Result<()>,
    expected_ok: bool,
) {
    let (passed, actual, class) = match &outcome {
        Ok(()) if expected_ok => (
            true,
            "operation accepted as expected".to_string(),
            "none".into(),
        ),
        Ok(()) => (
            false,
            "operation was accepted".into(),
            "unexpected_accept".into(),
        ),
        Err(e) if !expected_ok => (
            true,
            format!("rejected: {e}"),
            "rejected_as_expected".into(),
        ),
        Err(e) => (
            false,
            format!("unexpected rejection: {e}"),
            "unexpected_rejection".into(),
        ),
    };
    results.push(ScenarioResult {
        id,
        scenario: name.into(),
        expected: expected.into(),
        actual,
        passed,
        error_class: class,
    });
}

#[allow(clippy::redundant_closure_call)]
pub fn run_security_lab() -> Result<Vec<ScenarioResult>> {
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root = std::env::temp_dir().join(format!("qs-lab-{}-{stamp}", std::process::id()));
    fs::create_dir_all(&root)?;
    let keys = CryptoKeys::open_or_create(root.join("keys"), "lab-key-1")?;
    let db = root.join("lab.sqlite3");
    let security = SecurityStore::open(&db)?;
    let book = SqlitePaymentBook::open_existing_for_tests(&db)?;
    let current = now()?;
    let intent = PaymentIntent {
        id: "pay_lab_valid".into(),
        merchant_id: "merchant_lab".into(),
        amount_minor: 2599,
        currency: "USD".into(),
        description: "Deterministic security lab payment".into(),
        created_at: current.saturating_sub(10),
        expires_at: current + 600,
    };
    book.create(intent.clone(), "idem_lab_valid", current)?;
    book.transition(&intent.id, PaymentState::Pending)?;
    book.bind_paypal_order(&intent.id, "ORDERLAB001")?;

    let auth = create_authorization(&keys, &intent, "ORDERLAB001", None, 300)?;
    let aad = format!("{}/ORDERLAB001", intent.id);
    let sealed = keys.seal(aad.as_bytes(), br#"{"card_token":"sandbox-nonsecret"}"#)?;
    let mut results = Vec::new();

    scenario(
        &mut results,
        1,
        "Valid payment authorization, sealing and evidence verification",
        "all cryptographic and state checks succeed",
        (|| {
            verify_authorization(
                &keys,
                &auth,
                &security,
                AuthorizationExpectation {
                    intent: &intent,
                    paypal_order_id: "ORDERLAB001",
                    capture_id: None,
                    expected_key_id: &keys.key_id,
                    now: current,
                },
            )?;
            if keys.open(aad.as_bytes(), &sealed)? != br#"{"card_token":"sandbox-nonsecret"}"# {
                bail!("plaintext mismatch");
            }
            let evidence = build_evidence(EvidenceInput {
                intent: &intent,
                paypal_order_id: "ORDERLAB001",
                capture_id: "CAPTURELAB001",
                event_id: "WH_LAB_VALID",
                payload_sha256: &sha256_hex(b"verified-lab-event"),
                reconciled_at: current,
                authorization: &auth,
                authorization_verified: true,
                keys: &keys,
            })?;
            verify_evidence(&evidence)?;
            Ok(())
        })(),
        true,
    );

    scenario(
        &mut results,
        2,
        "Modified authorization amount",
        "signature/binding verification rejects",
        (|| {
            let mut modified = auth.clone();
            modified.nonce = sha256_hex(b"other-nonce")[..32].to_owned();
            modified.amount_minor += 1;
            let sig = unb64(&modified.signature, 8192)?;
            keys.verify(&modified.signing_bytes()?, &sig)
        })(),
        false,
    );

    scenario(
        &mut results,
        3,
        "Modified encrypted payment data",
        "AEAD authentication rejects",
        (|| {
            let mut modified = sealed.clone();
            let mut bytes = unb64(&modified.ciphertext, 2_000_000)?;
            bytes[0] ^= 1;
            modified.ciphertext = b64(bytes);
            keys.open(aad.as_bytes(), &modified).map(|_| ())
        })(),
        false,
    );

    scenario(
        &mut results,
        4,
        "Invalid ML-DSA-65 signature",
        "signature verification rejects",
        (|| {
            let mut bad = auth.clone();
            let mut bytes = unb64(&bad.signature, 8192)?;
            bytes[0] ^= 1;
            bad.signature = b64(bytes);
            keys.verify(&bad.signing_bytes()?, &unb64(&bad.signature, 8192)?)
        })(),
        false,
    );

    scenario(
        &mut results,
        5,
        "Replayed authorization nonce",
        "persistent replay store rejects second use",
        (|| {
            let nonce_auth = create_authorization(&keys, &intent, "ORDERLAB001", None, 300)?;
            verify_authorization(
                &keys,
                &nonce_auth,
                &security,
                AuthorizationExpectation {
                    intent: &intent,
                    paypal_order_id: "ORDERLAB001",
                    capture_id: None,
                    expected_key_id: &keys.key_id,
                    now: current,
                },
            )?;
            verify_authorization(
                &keys,
                &nonce_auth,
                &security,
                AuthorizationExpectation {
                    intent: &intent,
                    paypal_order_id: "ORDERLAB001",
                    capture_id: None,
                    expected_key_id: &keys.key_id,
                    now: current,
                },
            )
        })(),
        false,
    );

    scenario(
        &mut results,
        6,
        "Duplicate verified webhook",
        "event ID is deduplicated without state corruption",
        (|| {
            let duplicate = PaymentIntent {
                id: "pay_lab_dup".into(),
                merchant_id: "merchant_lab".into(),
                amount_minor: 500,
                currency: "USD".into(),
                description: "duplicate webhook".into(),
                created_at: current.saturating_sub(5),
                expires_at: current + 300,
            };
            book.create(duplicate.clone(), "idem_lab_dup", current)?;
            book.transition(&duplicate.id, PaymentState::Pending)?;
            book.bind_paypal_order(&duplicate.id, "ORDERLAB002")?;
            let hash = sha256_hex(b"same-webhook-body");
            if !book.record_verified_capture(
                "WH_LAB_DUP",
                "PAYMENT.CAPTURE.COMPLETED",
                &hash,
                current,
                &duplicate.id,
                "CAPLAB002",
            )? {
                bail!("first event was not recorded");
            }
            if book.record_verified_capture(
                "WH_LAB_DUP",
                "PAYMENT.CAPTURE.COMPLETED",
                &hash,
                current,
                &duplicate.id,
                "CAPLAB002",
            )? {
                bail!("duplicate event was treated as new");
            }
            Ok(())
        })(),
        true,
    );

    scenario(
        &mut results,
        7,
        "Reused webhook event ID with different content",
        "different payload hash is rejected",
        (|| {
            book.record_verified_capture(
                "WH_LAB_DUP",
                "PAYMENT.CAPTURE.COMPLETED",
                &sha256_hex(b"altered-body"),
                current,
                &intent.id,
                "CAPLAB002",
            )
            .map(|_| ())
        })(),
        false,
    );

    scenario(
        &mut results,
        8,
        "Incorrect amount or currency",
        "authorization binding rejects",
        (|| {
            let mut wrong = intent.clone();
            wrong.amount_minor = 2600;
            wrong.currency = "EUR".into();
            verify_authorization(
                &keys,
                &auth,
                &security,
                AuthorizationExpectation {
                    intent: &wrong,
                    paypal_order_id: "ORDERLAB001",
                    capture_id: None,
                    expected_key_id: &keys.key_id,
                    now: current,
                },
            )
        })(),
        false,
    );

    scenario(
        &mut results,
        9,
        "Invalid PayPal order binding",
        "order binding mismatch is rejected",
        (|| {
            verify_authorization(
                &keys,
                &auth,
                &security,
                AuthorizationExpectation {
                    intent: &intent,
                    paypal_order_id: "ORDERLAB999",
                    capture_id: None,
                    expected_key_id: &keys.key_id,
                    now: current,
                },
            )
        })(),
        false,
    );

    scenario(
        &mut results,
        10,
        "Revoked or unknown key",
        "a revoked signing key is rejected before signature use",
        (|| {
            let rotating = CryptoKeys::open_or_create(root.join("keys"), "lab-revoked-key")?;
            let revoked_auth = create_authorization(&rotating, &intent, "ORDERLAB001", None, 300)?;
            revoke_key(&rotating.dir, &rotating.key_id)?;
            verify_authorization(
                &rotating,
                &revoked_auth,
                &security,
                AuthorizationExpectation {
                    intent: &intent,
                    paypal_order_id: "ORDERLAB001",
                    capture_id: None,
                    expected_key_id: &rotating.key_id,
                    now: current,
                },
            )
        })(),
        false,
    );

    scenario(
        &mut results,
        11,
        "Expired transaction authorization",
        "expired authorization is rejected",
        (|| {
            let expired = create_authorization(&keys, &intent, "ORDERLAB001", None, 1)?;
            verify_authorization(
                &keys,
                &expired,
                &security,
                AuthorizationExpectation {
                    intent: &intent,
                    paypal_order_id: "ORDERLAB001",
                    capture_id: None,
                    expected_key_id: &keys.key_id,
                    now: current + 5,
                },
            )
        })(),
        false,
    );

    scenario(
        &mut results,
        12,
        "Modified exported transaction evidence",
        "independent verifier detects tampering",
        (|| {
            let mut evidence = build_evidence(EvidenceInput {
                intent: &intent,
                paypal_order_id: "ORDERLAB001",
                capture_id: "CAPTURELAB001",
                event_id: "WH_LAB_VALID",
                payload_sha256: &sha256_hex(b"verified-lab-event"),
                reconciled_at: current,
                authorization: &auth,
                authorization_verified: true,
                keys: &keys,
            })?;
            evidence.amount_minor += 100;
            verify_evidence(&evidence)
        })(),
        false,
    );

    let _ = fs::remove_dir_all(&root);
    Ok(results)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (
        PathBuf,
        CryptoKeys,
        SecurityStore,
        SqlitePaymentBook,
        PaymentIntent,
    ) {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("qs-psec-{}-{stamp}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let keys = CryptoKeys::open_or_create(root.join("keys"), "test-key").unwrap();
        let db = root.join("test.sqlite3");
        let store = SecurityStore::open(&db).unwrap();
        let book = SqlitePaymentBook::open_existing_for_tests(&db).unwrap();
        let current = now().unwrap();
        let intent = PaymentIntent {
            id: "pay_test_secure".into(),
            merchant_id: "merchant_test".into(),
            amount_minor: 1999,
            currency: "USD".into(),
            description: "test".into(),
            created_at: current - 10,
            expires_at: current + 300,
        };
        (root, keys, store, book, intent)
    }

    #[test]
    fn ml_kem_hybrid_envelope_round_trip_and_tamper_detection() {
        let (root, keys, _, _, _) = fixture();
        let envelope = keys.seal(b"pay_1/order_1", b"payment metadata").unwrap();
        assert_eq!(
            keys.open(b"pay_1/order_1", &envelope).unwrap(),
            b"payment metadata"
        );
        let mut modified = envelope.clone();
        let mut bytes = B64.decode(&modified.ciphertext).unwrap();
        bytes[0] ^= 1;
        modified.ciphertext = b64(bytes);
        assert!(keys.open(b"pay_1/order_1", &modified).is_err());
        assert!(keys.open(b"pay_2/order_1", &envelope).is_err());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn ml_dsa_authorization_signature_and_replay() {
        let (root, keys, store, _, intent) = fixture();
        let current = now().unwrap();
        let auth = create_authorization(&keys, &intent, "ORDER1", None, 120).unwrap();
        verify_authorization(
            &keys,
            &auth,
            &store,
            AuthorizationExpectation {
                intent: &intent,
                paypal_order_id: "ORDER1",
                capture_id: None,
                expected_key_id: &keys.key_id,
                now: current,
            },
        )
        .unwrap();
        assert!(verify_authorization(
            &keys,
            &auth,
            &store,
            AuthorizationExpectation {
                intent: &intent,
                paypal_order_id: "ORDER1",
                capture_id: None,
                expected_key_id: &keys.key_id,
                now: current,
            }
        )
        .is_err());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn evidence_tampering_is_detected_independently() {
        let (root, keys, store, _, intent) = fixture();
        let current = now().unwrap();
        let auth =
            create_authorization(&keys, &intent, "ORDER1", Some("CAP1".into()), 120).unwrap();
        let mut evidence = build_evidence(EvidenceInput {
            intent: &intent,
            paypal_order_id: "ORDER1",
            capture_id: "CAP1",
            event_id: "WH1",
            payload_sha256: &sha256_hex(b"payload"),
            reconciled_at: current,
            authorization: &auth,
            authorization_verified: true,
            keys: &keys,
        })
        .unwrap();
        store.append_evidence(&evidence, &keys).unwrap();
        verify_evidence(&evidence).unwrap();
        evidence.currency = "EUR".into();
        assert!(verify_evidence(&evidence).is_err());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn evidence_chain_rejects_sequence_gaps_even_with_valid_signature() {
        let (root, keys, _, _, intent) = fixture();
        let current = now().unwrap();
        let auth =
            create_authorization(&keys, &intent, "ORDER1", Some("CAP1".into()), 120).unwrap();
        let mut evidence = build_evidence(EvidenceInput {
            intent: &intent,
            paypal_order_id: "ORDER1",
            capture_id: "CAP1",
            event_id: "WH1",
            payload_sha256: &sha256_hex(b"payload"),
            reconciled_at: current,
            authorization: &auth,
            authorization_verified: true,
            keys: &keys,
        })
        .unwrap();
        evidence.sequence = 2;
        evidence.chain_hash = evidence.compute_chain_hash().unwrap();
        evidence.ml_dsa_signature = b64(keys.sign(&evidence.signing_bytes().unwrap()).unwrap());
        assert!(verify_evidence(&evidence).is_ok());
        assert!(verify_evidence_chain(&[evidence]).is_err());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn evidence_survives_intent_expiry_after_authoritative_capture() {
        let (root, keys, _, _, mut intent) = fixture();
        let current = now().unwrap();
        intent.created_at = current - 600;
        intent.expires_at = current - 300;
        let auth =
            create_authorization(&keys, &intent, "ORDER1", Some("CAP1".into()), 120).unwrap();
        let evidence = build_evidence(EvidenceInput {
            intent: &intent,
            paypal_order_id: "ORDER1",
            capture_id: "CAP1",
            event_id: "WH1",
            payload_sha256: &sha256_hex(b"payload"),
            reconciled_at: current,
            authorization: &auth,
            authorization_verified: true,
            keys: &keys,
        })
        .unwrap();
        verify_evidence(&evidence).unwrap();
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn audit_chain_detects_modified_event() {
        let (root, _keys, store, _book, _intent) = fixture();
        store
            .log_event("test.first", "info", None, "first entry")
            .unwrap();
        store
            .log_event("test.second", "warning", None, "second entry")
            .unwrap();
        assert_eq!(store.verify_event_chain().unwrap(), 2);
        store
            .conn
            .lock()
            .unwrap()
            .execute(
                "UPDATE security_events SET detail='tampered' WHERE id=(SELECT MIN(id) FROM security_events)",
                [],
            )
            .unwrap();
        assert!(store.verify_event_chain().is_err());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn deterministic_security_lab_passes_all_scenarios() {
        let results = run_security_lab().unwrap();
        assert_eq!(results.len(), 12);
        for result in results {
            assert!(
                result.passed,
                "scenario {} failed: {}",
                result.id, result.actual
            );
        }
    }
}
