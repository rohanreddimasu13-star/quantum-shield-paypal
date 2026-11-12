//! Deterministic attack execution against the existing payment defenses.
//!
//! This module contains no PayPal client, no provider HTTP call and no way to
//! capture, refund or transfer money. Attacks only mutate disposable synthetic
//! inputs and observe the existing verification functions.

use anyhow::{bail, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::Serialize;
use serde_json::{json, Value};

use crate::payment_api::validate_order_matches;
use crate::payment_security::{
    build_evidence, create_authorization, revoke_key, sha256_hex, verify_authorization,
    verify_evidence, verify_evidence_chain, AuthorizationExpectation, CryptoKeys, EvidenceInput,
};
use crate::payments::{PaymentIntent, PaymentState};

use super::plan::AttackKind;
use super::synthetic::{Fixture, SYNTHETIC_CAPTURE_ID, SYNTHETIC_ORDER_ID, SYNTHETIC_PAYMENT_ID};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Observation {
    Rejected { control: String, message: String },
    Accepted { message: String },
    Skipped { reason: String },
}

#[derive(Debug, Clone, Serialize)]
pub struct InvariantCheck {
    pub name: String,
    pub passed: bool,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AttackExecution {
    pub observation: Observation,
    pub invariants: Vec<InvariantCheck>,
    pub notes: Vec<String>,
}

impl AttackExecution {
    pub fn accepted(message: impl Into<String>) -> Self {
        Self {
            observation: Observation::Accepted {
                message: message.into(),
            },
            invariants: Vec::new(),
            notes: Vec::new(),
        }
    }

    pub fn rejected(control: &str, message: impl Into<String>) -> Self {
        Self {
            observation: Observation::Rejected {
                control: control.into(),
                message: message.into(),
            },
            invariants: Vec::new(),
            notes: Vec::new(),
        }
    }

    pub fn skipped(reason: impl Into<String>) -> Self {
        Self {
            observation: Observation::Skipped {
                reason: reason.into(),
            },
            invariants: Vec::new(),
            notes: Vec::new(),
        }
    }

    pub fn with_invariants(mut self, invariants: Vec<InvariantCheck>) -> Self {
        self.invariants = invariants;
        self
    }

    pub fn with_note(mut self, note: impl Into<String>) -> Self {
        self.notes.push(note.into());
        self
    }
}

pub fn execute(kind: AttackKind) -> Result<AttackExecution> {
    if !kind.meta().offline {
        return Ok(AttackExecution::skipped(
            "requires PayPal's live signature-verification API and credentials; \
             not evaluated in this offline harness",
        ));
    }
    match kind {
        AttackKind::AuthSignatureTamper => auth_signature_tamper(),
        AttackKind::AuthBindingAmount => auth_binding_amount(),
        AttackKind::AuthBindingOrder => auth_binding_order(),
        AttackKind::AuthBindingMerchant => auth_binding_merchant(),
        AttackKind::AuthExpired => auth_expired(),
        AttackKind::AuthFutureIssued => auth_future_issued(),
        AttackKind::AuthNonceReplay => auth_nonce_replay(),
        AttackKind::AuthUnknownKey => auth_unknown_key(),
        AttackKind::AuthRevokedKey => auth_revoked_key(),
        AttackKind::EnvelopeCiphertextTamper => envelope_ciphertext_tamper(),
        AttackKind::EnvelopeAadSwap => envelope_aad_swap(),
        AttackKind::WebhookEventReplay => webhook_event_replay(),
        AttackKind::WebhookContentCollision => webhook_content_collision(),
        AttackKind::OrderReferenceMismatch => order_reference_mismatch(),
        AttackKind::OrderAmountMismatch => order_amount_mismatch(),
        AttackKind::PaymentStateSkip => payment_state_skip(),
        AttackKind::IdempotencyKeyReuse => idempotency_key_reuse(),
        AttackKind::RefundOverCapture => refund_over_capture(),
        AttackKind::EvidenceHashTamper => evidence_hash_tamper(),
        AttackKind::EvidenceSignatureTamper => evidence_signature_tamper(),
        AttackKind::AuditChainTamper => audit_chain_tamper(),
        AttackKind::EvidenceChainTamper => evidence_chain_tamper(),
        AttackKind::PayPalWebhookSignature => Ok(AttackExecution::skipped(
            "requires PayPal's live signature-verification API and credentials; \
             not evaluated in this offline harness",
        )),
    }
}

fn expectation<'a>(
    intent: &'a PaymentIntent,
    order_id: &'a str,
    key_id: &'a str,
    now: u64,
) -> AuthorizationExpectation<'a> {
    AuthorizationExpectation {
        intent,
        paypal_order_id: order_id,
        capture_id: None,
        expected_key_id: key_id,
        now,
    }
}

fn invariant(name: &str, passed: bool, detail: impl Into<String>) -> InvariantCheck {
    InvariantCheck {
        name: name.into(),
        passed,
        detail: detail.into(),
    }
}

/// A rejected attack must not have moved the payment or created a capture.
fn payment_untouched(fixture: &Fixture) -> Vec<InvariantCheck> {
    let state_ok = matches!(
        fixture.book.state(&fixture.intent.id),
        Ok(PaymentState::Pending)
    );
    let capture_absent = matches!(fixture.book.capture_for_order(SYNTHETIC_ORDER_ID), Ok(None));
    vec![
        invariant(
            "payment_state_unchanged",
            state_ok,
            "payment must remain pending",
        ),
        invariant(
            "no_capture_recorded",
            capture_absent,
            "no capture may exist after a rejected attack",
        ),
    ]
}

/// Classify a rejection by the exact control that produced it. If the message
/// does not match, the control is recorded as UNCLASSIFIED so the judge treats
/// it as a wrong-control result rather than a successful block.
fn reject_expected(kind: AttackKind, needle: &str, error: anyhow::Error) -> AttackExecution {
    let message = format!("{error:#}");
    if message
        .to_ascii_lowercase()
        .contains(&needle.to_ascii_lowercase())
    {
        AttackExecution::rejected(kind.meta().control, message)
    } else {
        AttackExecution::rejected("UNCLASSIFIED", message)
    }
}

// ---------------------------------------------------------------------------
// Authorization attacks
// ---------------------------------------------------------------------------

fn auth_signature_tamper() -> Result<AttackExecution> {
    let fixture = Fixture::new("authsig")?;

    // Positive control: an untampered authorization verifies.
    let valid = fixture.auth()?;
    verify_authorization(
        &fixture.keys,
        &valid,
        &fixture.security,
        expectation(
            &fixture.intent,
            SYNTHETIC_ORDER_ID,
            &fixture.keys.key_id,
            fixture.now,
        ),
    )?;

    let mut tampered = fixture.auth()?;
    let mut signature = B64.decode(&tampered.signature)?;
    if signature.is_empty() {
        bail!("authorization signature fixture is empty");
    }
    signature[0] ^= 0x01;
    tampered.signature = B64.encode(signature);

    let invariants = payment_untouched(&fixture);
    match verify_authorization(
        &fixture.keys,
        &tampered,
        &fixture.security,
        expectation(
            &fixture.intent,
            SYNTHETIC_ORDER_ID,
            &fixture.keys.key_id,
            fixture.now,
        ),
    ) {
        Ok(()) => Ok(
            AttackExecution::accepted("tampered ML-DSA-65 signature was accepted")
                .with_invariants(invariants),
        ),
        Err(error) => Ok(
            reject_expected(AttackKind::AuthSignatureTamper, "signature", error)
                .with_invariants(invariants)
                .with_note("positive control verified before the tampered signature"),
        ),
    }
}

fn auth_binding_amount() -> Result<AttackExecution> {
    let fixture = Fixture::new("authbindamount")?;
    let mut other_intent = fixture.intent.clone();
    other_intent.amount_minor += 1;
    let auth = create_authorization(&fixture.keys, &other_intent, SYNTHETIC_ORDER_ID, None, 300)?;

    // The authorization is genuinely valid for the intent it was signed for.
    verify_authorization(
        &fixture.keys,
        &auth,
        &fixture.security,
        expectation(
            &other_intent,
            SYNTHETIC_ORDER_ID,
            &fixture.keys.key_id,
            fixture.now,
        ),
    )?;

    let invariants = payment_untouched(&fixture);
    match verify_authorization(
        &fixture.keys,
        &auth,
        &fixture.security,
        expectation(
            &fixture.intent,
            SYNTHETIC_ORDER_ID,
            &fixture.keys.key_id,
            fixture.now,
        ),
    ) {
        Ok(()) => Ok(AttackExecution::accepted(
            "authorization for a different amount was accepted",
        )
        .with_invariants(invariants)),
        Err(error) => Ok(reject_expected(
            AttackKind::AuthBindingAmount,
            "does not match merchant",
            error,
        )
        .with_invariants(invariants)
        .with_note("the same authorization verified successfully against its own intent")),
    }
}

fn auth_binding_order() -> Result<AttackExecution> {
    let fixture = Fixture::new("authbindorder")?;
    let other_order = "ORDERXRT999";
    let auth = create_authorization(&fixture.keys, &fixture.intent, other_order, None, 300)?;

    verify_authorization(
        &fixture.keys,
        &auth,
        &fixture.security,
        expectation(
            &fixture.intent,
            other_order,
            &fixture.keys.key_id,
            fixture.now,
        ),
    )?;

    let invariants = payment_untouched(&fixture);
    match verify_authorization(
        &fixture.keys,
        &auth,
        &fixture.security,
        expectation(
            &fixture.intent,
            SYNTHETIC_ORDER_ID,
            &fixture.keys.key_id,
            fixture.now,
        ),
    ) {
        Ok(()) => Ok(
            AttackExecution::accepted("authorization for a different order was accepted")
                .with_invariants(invariants),
        ),
        Err(error) => Ok(reject_expected(
            AttackKind::AuthBindingOrder,
            "does not match merchant",
            error,
        )
        .with_invariants(invariants)
        .with_note("the same authorization verified successfully against its own order")),
    }
}

fn auth_binding_merchant() -> Result<AttackExecution> {
    let fixture = Fixture::new("authbindmerchant")?;
    let mut other_intent = fixture.intent.clone();
    other_intent.merchant_id = "merchant_redteam_other".into();
    let auth = create_authorization(&fixture.keys, &other_intent, SYNTHETIC_ORDER_ID, None, 300)?;

    verify_authorization(
        &fixture.keys,
        &auth,
        &fixture.security,
        expectation(
            &other_intent,
            SYNTHETIC_ORDER_ID,
            &fixture.keys.key_id,
            fixture.now,
        ),
    )?;

    let invariants = payment_untouched(&fixture);
    match verify_authorization(
        &fixture.keys,
        &auth,
        &fixture.security,
        expectation(
            &fixture.intent,
            SYNTHETIC_ORDER_ID,
            &fixture.keys.key_id,
            fixture.now,
        ),
    ) {
        Ok(()) => Ok(AttackExecution::accepted(
            "authorization for a different merchant was accepted",
        )
        .with_invariants(invariants)),
        Err(error) => Ok(reject_expected(
            AttackKind::AuthBindingMerchant,
            "does not match merchant",
            error,
        )
        .with_invariants(invariants)
        .with_note("the same authorization verified successfully against its own merchant")),
    }
}

fn auth_expired() -> Result<AttackExecution> {
    let fixture = Fixture::new("authexpired")?;
    let mut auth = fixture.auth()?;
    let issued_at = fixture.now.saturating_sub(120);
    auth.issued_at = issued_at;
    auth.expires_at = issued_at.saturating_add(60);
    auth.signature = B64.encode(fixture.keys.sign(&auth.signing_bytes()?)?);

    let invariants = payment_untouched(&fixture);
    match verify_authorization(
        &fixture.keys,
        &auth,
        &fixture.security,
        expectation(
            &fixture.intent,
            SYNTHETIC_ORDER_ID,
            &fixture.keys.key_id,
            fixture.now,
        ),
    ) {
        Ok(()) => Ok(
            AttackExecution::accepted("expired authorization was accepted")
                .with_invariants(invariants),
        ),
        Err(error) => Ok(reject_expected(AttackKind::AuthExpired, "expired", error)
            .with_invariants(invariants)
            .with_note("authorization was re-signed so only expiry could reject it")),
    }
}

fn auth_future_issued() -> Result<AttackExecution> {
    let fixture = Fixture::new("authfuture")?;
    let mut auth = fixture.auth()?;
    auth.issued_at = fixture.now.saturating_add(3_600);
    auth.expires_at = auth.issued_at.saturating_add(300);
    auth.signature = B64.encode(fixture.keys.sign(&auth.signing_bytes()?)?);

    let invariants = payment_untouched(&fixture);
    match verify_authorization(
        &fixture.keys,
        &auth,
        &fixture.security,
        expectation(
            &fixture.intent,
            SYNTHETIC_ORDER_ID,
            &fixture.keys.key_id,
            fixture.now,
        ),
    ) {
        Ok(()) => Ok(
            AttackExecution::accepted("future-dated authorization was accepted")
                .with_invariants(invariants),
        ),
        Err(error) => Ok(
            reject_expected(AttackKind::AuthFutureIssued, "future", error)
                .with_invariants(invariants)
                .with_note("authorization was re-signed so only issue time could reject it"),
        ),
    }
}

fn auth_nonce_replay() -> Result<AttackExecution> {
    let fixture = Fixture::new("authnonce")?;
    let auth = fixture.auth()?;
    verify_authorization(
        &fixture.keys,
        &auth,
        &fixture.security,
        expectation(
            &fixture.intent,
            SYNTHETIC_ORDER_ID,
            &fixture.keys.key_id,
            fixture.now,
        ),
    )?;

    let invariants = payment_untouched(&fixture);
    match verify_authorization(
        &fixture.keys,
        &auth,
        &fixture.security,
        expectation(
            &fixture.intent,
            SYNTHETIC_ORDER_ID,
            &fixture.keys.key_id,
            fixture.now,
        ),
    ) {
        Ok(()) => Ok(
            AttackExecution::accepted("replayed authorization nonce was accepted")
                .with_invariants(invariants),
        ),
        Err(error) => Ok(reject_expected(AttackKind::AuthNonceReplay, "nonce", error)
            .with_invariants(invariants)
            .with_note("first submission verified; second submission was the attack")),
    }
}

fn auth_unknown_key() -> Result<AttackExecution> {
    let fixture = Fixture::new("authunknownkey")?;
    let other_keys =
        CryptoKeys::open_or_create(fixture.root.join("keys-unknown"), "redteam-key-2")?;
    let auth = create_authorization(&other_keys, &fixture.intent, SYNTHETIC_ORDER_ID, None, 300)?;

    verify_authorization(
        &other_keys,
        &auth,
        &fixture.security,
        expectation(
            &fixture.intent,
            SYNTHETIC_ORDER_ID,
            &other_keys.key_id,
            fixture.now,
        ),
    )?;

    let invariants = payment_untouched(&fixture);
    match verify_authorization(
        &fixture.keys,
        &auth,
        &fixture.security,
        expectation(
            &fixture.intent,
            SYNTHETIC_ORDER_ID,
            &fixture.keys.key_id,
            fixture.now,
        ),
    ) {
        Ok(()) => Ok(
            AttackExecution::accepted("authorization from an unknown key was accepted")
                .with_invariants(invariants),
        ),
        Err(error) => {
            Ok(
                reject_expected(AttackKind::AuthUnknownKey, "unknown or revoked key", error)
                    .with_invariants(invariants)
                    .with_note("the same authorization verified against its own key first"),
            )
        }
    }
}

fn auth_revoked_key() -> Result<AttackExecution> {
    let fixture = Fixture::new("authrevokedkey")?;
    let other_keys =
        CryptoKeys::open_or_create(fixture.root.join("keys-revoked"), "redteam-key-revoked")?;
    let auth = create_authorization(&other_keys, &fixture.intent, SYNTHETIC_ORDER_ID, None, 300)?;

    verify_authorization(
        &other_keys,
        &auth,
        &fixture.security,
        expectation(
            &fixture.intent,
            SYNTHETIC_ORDER_ID,
            &other_keys.key_id,
            fixture.now,
        ),
    )?;
    revoke_key(&other_keys.dir, &other_keys.key_id)?;

    let invariants = payment_untouched(&fixture);
    match verify_authorization(
        &other_keys,
        &auth,
        &fixture.security,
        expectation(
            &fixture.intent,
            SYNTHETIC_ORDER_ID,
            &other_keys.key_id,
            fixture.now,
        ),
    ) {
        Ok(()) => Ok(
            AttackExecution::accepted("authorization from a revoked key was accepted")
                .with_invariants(invariants),
        ),
        Err(error) => Ok(
            reject_expected(AttackKind::AuthRevokedKey, "revoked", error)
                .with_invariants(invariants)
                .with_note("key verified before revocation; the same key was then revoked"),
        ),
    }
}

// ---------------------------------------------------------------------------
// Envelope attacks
// ---------------------------------------------------------------------------

fn envelope_ciphertext_tamper() -> Result<AttackExecution> {
    let fixture = Fixture::new("envelopeaead")?;
    let aad = format!("{}/{}", fixture.intent.id, SYNTHETIC_ORDER_ID);
    let plaintext = br#"{"card_token":"sandbox-nonsecret"}"#;
    let sealed = fixture.keys.seal(aad.as_bytes(), plaintext)?;
    let opened = fixture.keys.open(aad.as_bytes(), &sealed)?;
    if opened != plaintext.to_vec() {
        bail!("positive envelope round-trip returned different plaintext");
    }

    let mut modified = sealed.clone();
    let mut ciphertext = B64.decode(&modified.ciphertext)?;
    if ciphertext.is_empty() {
        bail!("sealed ciphertext fixture is empty");
    }
    ciphertext[0] ^= 0x01;
    modified.ciphertext = B64.encode(ciphertext);

    match fixture.keys.open(aad.as_bytes(), &modified) {
        Ok(_) => Ok(
            AttackExecution::accepted("modified encrypted envelope was accepted")
                .with_note("positive envelope round-trip succeeded before tampering"),
        ),
        Err(error) => Ok(reject_expected(
            AttackKind::EnvelopeCiphertextTamper,
            "authentication failed",
            error,
        )
        .with_note("positive envelope round-trip succeeded before tampering")),
    }
}

fn envelope_aad_swap() -> Result<AttackExecution> {
    let fixture = Fixture::new("envelopeaad")?;
    let aad = format!("{}/{}", fixture.intent.id, SYNTHETIC_ORDER_ID);
    let other_aad = format!("{}/ORDERXRT999", fixture.intent.id);
    let sealed = fixture
        .keys
        .seal(aad.as_bytes(), b"synthetic payment data")?;
    fixture.keys.open(aad.as_bytes(), &sealed)?;

    match fixture.keys.open(other_aad.as_bytes(), &sealed) {
        Ok(_) => Ok(
            AttackExecution::accepted("envelope opened under the wrong context")
                .with_note("positive envelope round-trip succeeded before context swap"),
        ),
        Err(error) => {
            Ok(
                reject_expected(AttackKind::EnvelopeAadSwap, "context does not match", error)
                    .with_note("positive envelope round-trip succeeded before context swap"),
            )
        }
    }
}

// ---------------------------------------------------------------------------
// Webhook / order attacks
// ---------------------------------------------------------------------------

fn webhook_event_replay() -> Result<AttackExecution> {
    let fixture = Fixture::new("webhookreplay")?;
    let payload_hash = sha256_hex(b"synthetic verified capture payload");
    let first = fixture.book.record_verified_capture(
        "WH_RT_REPLAY",
        "PAYMENT.CAPTURE.COMPLETED",
        &payload_hash,
        fixture.now,
        &fixture.intent.id,
        SYNTHETIC_CAPTURE_ID,
    )?;
    if !first {
        bail!("positive control did not record the first verified webhook");
    }

    let capture = fixture.book.capture_details(SYNTHETIC_CAPTURE_ID)?;
    let invariants = vec![
        invariant(
            "payment_captured_once",
            matches!(
                fixture.book.state(&fixture.intent.id),
                Ok(PaymentState::Captured)
            ),
            "payment must be captured exactly once",
        ),
        invariant(
            "single_capture_record",
            capture
                .as_ref()
                .map(|record| record.payment_id == SYNTHETIC_PAYMENT_ID)
                .unwrap_or(false),
            "exactly one capture record must exist",
        ),
        invariant(
            "no_refund_created",
            capture
                .as_ref()
                .map(|record| record.refunded_minor == 0)
                .unwrap_or(false),
            "replayed webhook must not create a refund",
        ),
    ];

    match fixture.book.record_verified_capture(
        "WH_RT_REPLAY",
        "PAYMENT.CAPTURE.COMPLETED",
        &payload_hash,
        fixture.now,
        &fixture.intent.id,
        SYNTHETIC_CAPTURE_ID,
    ) {
        Ok(false) => Ok(AttackExecution::rejected(
            "DEF-WH-REPLAY",
            "duplicate webhook acknowledged without a second state change",
        )
        .with_invariants(invariants)),
        Ok(true) => Ok(
            AttackExecution::accepted("replayed webhook created a second state change")
                .with_invariants(invariants),
        ),
        Err(error) => Ok(
            reject_expected(AttackKind::WebhookEventReplay, "duplicate", error)
                .with_invariants(invariants),
        ),
    }
}

fn webhook_content_collision() -> Result<AttackExecution> {
    let fixture = Fixture::new("webhookcontent")?;
    let first_hash = sha256_hex(b"first synthetic webhook content");
    let second_hash = sha256_hex(b"different synthetic webhook content");
    let first = fixture.book.record_verified_capture(
        "WH_RT_CONTENT",
        "PAYMENT.CAPTURE.COMPLETED",
        &first_hash,
        fixture.now,
        &fixture.intent.id,
        SYNTHETIC_CAPTURE_ID,
    )?;
    if !first {
        bail!("positive control did not record the first verified webhook");
    }

    let invariants = vec![
        invariant(
            "payment_still_captured",
            matches!(
                fixture.book.state(&fixture.intent.id),
                Ok(PaymentState::Captured)
            ),
            "payment state must not be changed by the colliding event",
        ),
        invariant(
            "capture_still_owned_by_payment",
            fixture
                .book
                .capture_details(SYNTHETIC_CAPTURE_ID)?
                .map(|record| record.payment_id == SYNTHETIC_PAYMENT_ID)
                .unwrap_or(false),
            "capture must still belong to the original payment",
        ),
    ];

    match fixture.book.record_verified_capture(
        "WH_RT_CONTENT",
        "PAYMENT.CAPTURE.COMPLETED",
        &second_hash,
        fixture.now,
        &fixture.intent.id,
        SYNTHETIC_CAPTURE_ID,
    ) {
        Ok(_) => Ok(AttackExecution::accepted(
            "webhook event ID was reused with different content",
        )
        .with_invariants(invariants)),
        Err(error) => Ok(reject_expected(
            AttackKind::WebhookContentCollision,
            "different content",
            error,
        )
        .with_invariants(invariants)),
    }
}

fn synthetic_order(reference: &str, value: &str, currency: &str, capture_id: &str) -> Value {
    json!({
        "purchase_units": [{
            "reference_id": reference,
            "custom_id": reference,
            "amount": {"currency_code": currency, "value": value},
            "payments": {
                "captures": [{
                    "id": capture_id,
                    "status": "COMPLETED",
                    "amount": {"currency_code": currency, "value": value}
                }]
            }
        }]
    })
}

fn order_reference_mismatch() -> Result<AttackExecution> {
    let fixture = Fixture::new("orderreference")?;
    let good = synthetic_order(
        &fixture.intent.id,
        "25.99",
        &fixture.intent.currency,
        SYNTHETIC_CAPTURE_ID,
    );
    validate_order_matches(&good, &fixture.intent, SYNTHETIC_CAPTURE_ID)?;

    let bad = synthetic_order(
        "pay_redteam_other",
        "25.99",
        &fixture.intent.currency,
        SYNTHETIC_CAPTURE_ID,
    );
    match validate_order_matches(&bad, &fixture.intent, SYNTHETIC_CAPTURE_ID) {
        Ok(()) => Ok(
            AttackExecution::accepted("PayPal order for another payment was accepted")
                .with_note("positive order matched before the reference was changed"),
        ),
        Err(error) => Ok(reject_expected(
            AttackKind::OrderReferenceMismatch,
            "reference does not match",
            error,
        )
        .with_note("positive order matched before the reference was changed")),
    }
}

fn order_amount_mismatch() -> Result<AttackExecution> {
    let fixture = Fixture::new("orderamount")?;
    let good = synthetic_order(
        &fixture.intent.id,
        "25.99",
        &fixture.intent.currency,
        SYNTHETIC_CAPTURE_ID,
    );
    validate_order_matches(&good, &fixture.intent, SYNTHETIC_CAPTURE_ID)?;

    let bad = synthetic_order(
        &fixture.intent.id,
        "0.01",
        &fixture.intent.currency,
        SYNTHETIC_CAPTURE_ID,
    );
    match validate_order_matches(&bad, &fixture.intent, SYNTHETIC_CAPTURE_ID) {
        Ok(()) => Ok(AttackExecution::accepted(
            "PayPal order with a different amount was accepted",
        )
        .with_note("positive order matched before the amount was changed")),
        Err(error) => Ok(reject_expected(
            AttackKind::OrderAmountMismatch,
            "amount or currency does not match",
            error,
        )
        .with_note("positive order matched before the amount was changed")),
    }
}

fn payment_state_skip() -> Result<AttackExecution> {
    let fixture = Fixture::new("stateskip")?;
    let invariants = vec![invariant(
        "payment_state_unchanged",
        matches!(
            fixture.book.state(&fixture.intent.id),
            Ok(PaymentState::Pending)
        ),
        "payment must remain pending",
    )];
    match fixture
        .book
        .transition(&fixture.intent.id, PaymentState::Captured)
    {
        Ok(_) => Ok(
            AttackExecution::accepted("pending payment skipped directly to captured")
                .with_invariants(invariants),
        ),
        Err(error) => Ok(reject_expected(
            AttackKind::PaymentStateSkip,
            "invalid payment state transition",
            error,
        )
        .with_invariants(invariants)),
    }
}

fn idempotency_key_reuse() -> Result<AttackExecution> {
    let fixture = Fixture::new("idempotency")?;
    let mut other_intent = fixture.intent.clone();
    other_intent.id = "pay_redteam_other".into();
    other_intent.amount_minor += 1;
    other_intent.description = "Different synthetic payment".into();

    let invariants = vec![
        invariant(
            "single_payment_stored",
            fixture.book.list_payments()?.len() == 1,
            "reused idempotency key must not create a second payment",
        ),
        invariant(
            "original_payment_unchanged",
            matches!(
                fixture.book.state(&fixture.intent.id),
                Ok(PaymentState::Pending)
            ),
            "original payment must remain pending",
        ),
    ];

    match fixture
        .book
        .create(other_intent, "idem_redteam_valid", fixture.now)
    {
        Ok(_) => Ok(AttackExecution::accepted(
            "idempotency key was reused for a different payment",
        )
        .with_invariants(invariants)),
        Err(error) => Ok(reject_expected(
            AttackKind::IdempotencyKeyReuse,
            "idempotency key already belongs",
            error,
        )
        .with_invariants(invariants)),
    }
}

fn refund_over_capture() -> Result<AttackExecution> {
    let fixture = Fixture::new("refund")?;
    let payload_hash = sha256_hex(b"authoritative synthetic capture");
    let recorded = fixture.book.record_authoritative_capture(
        &fixture.intent.id,
        SYNTHETIC_CAPTURE_ID,
        &payload_hash,
        fixture.now,
    )?;
    if !recorded {
        bail!("positive control did not record the authoritative capture");
    }
    let first_refund = fixture.book.record_refund(
        "REFUNDXRT001",
        SYNTHETIC_CAPTURE_ID,
        &fixture.intent.id,
        "COMPLETED",
        2_000,
        "USD",
        fixture.now,
    )?;
    if first_refund.2 != 2_000 {
        bail!("positive control did not record the first refund");
    }

    let capture = fixture.book.capture_details(SYNTHETIC_CAPTURE_ID)?;
    let invariants = vec![
        invariant(
            "refund_total_capped",
            capture
                .as_ref()
                .map(|record| record.refunded_minor == 2_000)
                .unwrap_or(false),
            "refunded total must remain at the accepted amount",
        ),
        invariant(
            "over_refund_not_persisted",
            fixture.book.refund_details("REFUNDXRT002")?.is_none(),
            "rejected refund must not be persisted",
        ),
    ];

    match fixture.book.record_refund(
        "REFUNDXRT002",
        SYNTHETIC_CAPTURE_ID,
        &fixture.intent.id,
        "COMPLETED",
        1_000,
        "USD",
        fixture.now,
    ) {
        Ok(_) => Ok(
            AttackExecution::accepted("refund exceeded the remaining captured amount")
                .with_invariants(invariants),
        ),
        Err(error) => Ok(reject_expected(
            AttackKind::RefundOverCapture,
            "exceeds the remaining",
            error,
        )
        .with_invariants(invariants)
        .with_note("a legitimate partial refund was accepted first")),
    }
}

// ---------------------------------------------------------------------------
// Evidence / audit attacks
// ---------------------------------------------------------------------------

fn valid_evidence(fixture: &Fixture) -> Result<crate::payment_security::EvidenceRecord> {
    let auth = fixture.auth()?;
    build_evidence(EvidenceInput {
        intent: &fixture.intent,
        paypal_order_id: SYNTHETIC_ORDER_ID,
        capture_id: SYNTHETIC_CAPTURE_ID,
        event_id: "WH_RT_EVIDENCE",
        payload_sha256: &sha256_hex(b"synthetic evidence payload"),
        reconciled_at: fixture.now,
        authorization: &auth,
        authorization_verified: true,
        keys: &fixture.keys,
    })
}

fn evidence_hash_tamper() -> Result<AttackExecution> {
    let fixture = Fixture::new("evidencehash")?;
    let evidence = valid_evidence(&fixture)?;
    verify_evidence(&evidence)?;

    let mut tampered = evidence;
    tampered.amount_minor += 1;
    match verify_evidence(&tampered) {
        Ok(()) => Ok(
            AttackExecution::accepted("modified evidence body passed verification")
                .with_note("positive evidence verified before the body was modified"),
        ),
        Err(error) => Ok(reject_expected(
            AttackKind::EvidenceHashTamper,
            "integrity hash mismatch",
            error,
        )
        .with_note("positive evidence verified before the body was modified")),
    }
}

fn evidence_signature_tamper() -> Result<AttackExecution> {
    let fixture = Fixture::new("evidencesig")?;
    let evidence = valid_evidence(&fixture)?;
    verify_evidence(&evidence)?;

    let mut tampered = evidence;
    let mut signature = B64.decode(&tampered.ml_dsa_signature)?;
    if signature.is_empty() {
        bail!("evidence signature fixture is empty");
    }
    signature[0] ^= 0x01;
    tampered.ml_dsa_signature = B64.encode(signature);

    match verify_evidence(&tampered) {
        Ok(()) => Ok(
            AttackExecution::accepted("tampered evidence signature passed verification")
                .with_note("positive evidence verified before the signature was modified"),
        ),
        Err(error) => Ok(reject_expected(
            AttackKind::EvidenceSignatureTamper,
            "signature verification failed",
            error,
        )
        .with_note("positive evidence verified before the signature was modified")),
    }
}

fn audit_chain_tamper() -> Result<AttackExecution> {
    let fixture = Fixture::new("auditchain")?;
    fixture.security.log_event(
        "redteam.first",
        "info",
        Some(&fixture.intent.id),
        "first synthetic audit event",
    )?;
    fixture.security.log_event(
        "redteam.second",
        "info",
        Some(&fixture.intent.id),
        "second synthetic audit event",
    )?;
    let count = fixture.security.verify_event_chain()?;
    if count != 2 {
        bail!("positive control did not produce two audit entries");
    }

    let connection = rusqlite::Connection::open(&fixture.db_path)?;
    let changed = connection.execute(
        "UPDATE security_events SET detail='tampered by synthetic red team' WHERE id=1",
        [],
    )?;
    if changed != 1 {
        bail!("could not tamper the synthetic audit entry");
    }

    match fixture.security.verify_event_chain() {
        Ok(_) => Ok(
            AttackExecution::accepted("modified audit entry passed chain verification")
                .with_note("positive audit chain verified before the entry was modified"),
        ),
        Err(error) => Ok(
            reject_expected(AttackKind::AuditChainTamper, "modified", error)
                .with_note("positive audit chain verified before the entry was modified"),
        ),
    }
}

fn evidence_chain_tamper() -> Result<AttackExecution> {
    let fixture = Fixture::new("evidencechain")?;
    let auth = fixture.auth()?;
    let first = build_evidence(EvidenceInput {
        intent: &fixture.intent,
        paypal_order_id: SYNTHETIC_ORDER_ID,
        capture_id: SYNTHETIC_CAPTURE_ID,
        event_id: "WH_RT_CHAIN1",
        payload_sha256: &sha256_hex(b"chain payload one"),
        reconciled_at: fixture.now,
        authorization: &auth,
        authorization_verified: true,
        keys: &fixture.keys,
    })?;

    let mut second_intent = fixture.intent.clone();
    second_intent.id = "pay_redteam_two".into();
    let second_auth =
        create_authorization(&fixture.keys, &second_intent, SYNTHETIC_ORDER_ID, None, 300)?;
    let second = build_evidence(EvidenceInput {
        intent: &second_intent,
        paypal_order_id: SYNTHETIC_ORDER_ID,
        capture_id: "CAPTURXRT002",
        event_id: "WH_RT_CHAIN2",
        payload_sha256: &sha256_hex(b"chain payload two"),
        reconciled_at: fixture.now,
        authorization: &second_auth,
        authorization_verified: true,
        keys: &fixture.keys,
    })?;

    fixture.security.append_evidence(&first, &fixture.keys)?;
    fixture.security.append_evidence(&second, &fixture.keys)?;
    let mut records = fixture.security.export_all_evidence()?;
    if records.len() != 2 {
        bail!("positive control did not produce two evidence records");
    }
    verify_evidence_chain(&records)?;

    records.swap(0, 1);
    match verify_evidence_chain(&records) {
        Ok(()) => Ok(
            AttackExecution::accepted("reordered evidence chain passed verification")
                .with_note("positive evidence chain verified before records were reordered"),
        ),
        Err(error) => {
            Ok(
                reject_expected(AttackKind::EvidenceChainTamper, "sequence mismatch", error)
                    .with_note("positive evidence chain verified before records were reordered"),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::payment_redteam::plan::catalog;

    #[test]
    fn every_offline_attack_executes_without_a_bypass() {
        for kind in catalog() {
            if !kind.meta().offline {
                continue;
            }
            let execution = execute(*kind).unwrap_or_else(|error| {
                panic!("{} failed to execute: {error:#}", kind.meta().title)
            });
            match execution.observation {
                Observation::Rejected { control, .. } => {
                    assert_eq!(
                        control,
                        kind.meta().control,
                        "{} was rejected by the wrong control",
                        kind.meta().title
                    );
                }
                Observation::Accepted { message } => {
                    panic!("{} was accepted: {message}", kind.meta().title)
                }
                Observation::Skipped { reason } => {
                    panic!("{} was skipped: {reason}", kind.meta().title)
                }
            }
            assert!(
                execution.invariants.iter().all(|check| check.passed),
                "{} violated an invariant: {:?}",
                kind.meta().title,
                execution.invariants
            );
        }
    }

    #[test]
    fn online_only_attack_is_skipped_not_claimed() {
        let execution = execute(AttackKind::PayPalWebhookSignature).unwrap();
        assert!(matches!(execution.observation, Observation::Skipped { .. }));
    }
}
