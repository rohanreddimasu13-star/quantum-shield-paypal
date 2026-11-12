//! Strict, versioned attack plan.
//!
//! A plan may be produced deterministically or by a local model. It contains
//! only *attack selections*: the control under test, its weight and whether it
//! is critical are derived here, in trusted code, and can never be supplied by
//! the model or by a plan file.

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const PLAN_SCHEMA_VERSION: u32 = 1;
pub const MAX_PLAN_ATTACKS: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum RedTeamProvider {
    Deterministic,
    Ollama,
}

impl std::fmt::Display for RedTeamProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Deterministic => "deterministic",
            Self::Ollama => "ollama",
        })
    }
}

/// Every attack the harness knows how to execute offline.
///
/// `PayPalWebhookSignature` is deliberately present but never executed: real
/// PayPal signature verification needs PayPal's API and credentials, so it is
/// reported as `not_evaluated` instead of being claimed as blocked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttackKind {
    AuthSignatureTamper,
    AuthBindingAmount,
    AuthBindingOrder,
    AuthBindingMerchant,
    AuthExpired,
    AuthFutureIssued,
    AuthNonceReplay,
    AuthUnknownKey,
    AuthRevokedKey,
    EnvelopeCiphertextTamper,
    EnvelopeAadSwap,
    WebhookEventReplay,
    WebhookContentCollision,
    OrderReferenceMismatch,
    OrderAmountMismatch,
    PaymentStateSkip,
    IdempotencyKeyReuse,
    RefundOverCapture,
    EvidenceHashTamper,
    EvidenceSignatureTamper,
    AuditChainTamper,
    EvidenceChainTamper,
    #[serde(rename = "paypal_webhook_signature")]
    PayPalWebhookSignature,
}

pub struct KindMeta {
    pub control: &'static str,
    pub title: &'static str,
    pub weight: u32,
    pub critical: bool,
    pub offline: bool,
}

impl AttackKind {
    pub fn meta(self) -> KindMeta {
        use AttackKind::*;
        let (control, title, weight, critical, offline) = match self {
            AuthSignatureTamper => (
                "DEF-AUTH-SIG",
                "Tampered ML-DSA-65 authorization signature",
                5,
                true,
                true,
            ),
            AuthBindingAmount => (
                "DEF-AUTH-BIND",
                "Validly signed authorization for a different amount",
                5,
                true,
                true,
            ),
            AuthBindingOrder => (
                "DEF-AUTH-BIND",
                "Validly signed authorization for a different PayPal order",
                4,
                false,
                true,
            ),
            AuthBindingMerchant => (
                "DEF-AUTH-BIND",
                "Validly signed authorization for a different merchant",
                3,
                false,
                true,
            ),
            AuthExpired => (
                "DEF-AUTH-EXPIRY",
                "Expired payment authorization",
                3,
                false,
                true,
            ),
            AuthFutureIssued => (
                "DEF-AUTH-FUTURE",
                "Authorization issued in the future",
                2,
                false,
                true,
            ),
            AuthNonceReplay => (
                "DEF-AUTH-NONCE",
                "Replayed authorization nonce",
                5,
                true,
                true,
            ),
            AuthUnknownKey => (
                "DEF-AUTH-KEY",
                "Authorization signed by an unknown key",
                4,
                true,
                true,
            ),
            AuthRevokedKey => (
                "DEF-KEY-REVOKED",
                "Authorization signed by a revoked key",
                4,
                true,
                true,
            ),
            EnvelopeCiphertextTamper => (
                "DEF-ENV-AEAD",
                "Modified encrypted payment envelope",
                5,
                true,
                true,
            ),
            EnvelopeAadSwap => (
                "DEF-ENV-AAD",
                "Payment envelope opened under the wrong context",
                4,
                false,
                true,
            ),
            WebhookEventReplay => (
                "DEF-WH-REPLAY",
                "Replayed verified capture webhook",
                4,
                true,
                true,
            ),
            WebhookContentCollision => (
                "DEF-WH-CONTENT",
                "Webhook event ID reused with different content",
                3,
                false,
                true,
            ),
            OrderReferenceMismatch => (
                "DEF-WH-ORDER",
                "PayPal order reference for another payment",
                4,
                true,
                true,
            ),
            OrderAmountMismatch => (
                "DEF-WH-ORDER",
                "PayPal order amount or currency mismatch",
                4,
                true,
                true,
            ),
            PaymentStateSkip => (
                "DEF-STATE",
                "Illegal payment state transition",
                3,
                false,
                true,
            ),
            IdempotencyKeyReuse => (
                "DEF-IDEMP",
                "Idempotency key reused for a different payment",
                3,
                false,
                true,
            ),
            RefundOverCapture => (
                "DEF-REFUND",
                "Cumulative refunds exceed the captured amount",
                5,
                true,
                true,
            ),
            EvidenceHashTamper => (
                "DEF-EVIDENCE-HASH",
                "Modified transaction evidence body",
                4,
                true,
                true,
            ),
            EvidenceSignatureTamper => (
                "DEF-EVIDENCE-SIG",
                "Tampered evidence ML-DSA-65 signature",
                5,
                true,
                true,
            ),
            AuditChainTamper => ("DEF-AUDIT-CHAIN", "Tampered audit-log entry", 4, true, true),
            EvidenceChainTamper => (
                "DEF-EVIDENCE-CHAIN",
                "Reordered evidence hash chain",
                4,
                true,
                true,
            ),
            PayPalWebhookSignature => (
                "DEF-WH-SIG",
                "Real PayPal webhook signature verification",
                5,
                true,
                false,
            ),
        };
        KindMeta {
            control,
            title,
            weight,
            critical,
            offline,
        }
    }
}

/// The fixed catalog, in stable order.
pub fn catalog() -> &'static [AttackKind] {
    use AttackKind::*;
    &[
        AuthSignatureTamper,
        AuthBindingAmount,
        AuthBindingOrder,
        AuthBindingMerchant,
        AuthExpired,
        AuthFutureIssued,
        AuthNonceReplay,
        AuthUnknownKey,
        AuthRevokedKey,
        EnvelopeCiphertextTamper,
        EnvelopeAadSwap,
        WebhookEventReplay,
        WebhookContentCollision,
        OrderReferenceMismatch,
        OrderAmountMismatch,
        PaymentStateSkip,
        IdempotencyKeyReuse,
        RefundOverCapture,
        EvidenceHashTamper,
        EvidenceSignatureTamper,
        AuditChainTamper,
        EvidenceChainTamper,
        PayPalWebhookSignature,
    ]
}

pub fn is_known_kind(kind: AttackKind) -> bool {
    catalog().contains(&kind)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttackSelection {
    pub kind: AttackKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttackPlan {
    pub schema_version: u32,
    pub seed: u64,
    pub source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    pub attacks: Vec<AttackSelection>,
}

#[derive(Debug, Clone)]
pub struct PlannedAttack {
    pub id: String,
    pub kind: AttackKind,
    pub name: String,
    pub control: &'static str,
    pub weight: u32,
    pub critical: bool,
    pub offline: bool,
}

impl AttackPlan {
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != PLAN_SCHEMA_VERSION {
            bail!(
                "unsupported red-team plan schema version {} (expected {})",
                self.schema_version,
                PLAN_SCHEMA_VERSION
            );
        }
        if self.attacks.is_empty() {
            bail!("red-team plan contains no attacks");
        }
        if self.attacks.len() > MAX_PLAN_ATTACKS {
            bail!(
                "red-team plan exceeds the {} attack limit",
                MAX_PLAN_ATTACKS
            );
        }
        if self.source.is_empty()
            || self.source.len() > 64
            || self.source.chars().any(char::is_control)
        {
            bail!("red-team plan source label is invalid or too long");
        }
        if let Some(model) = &self.model {
            if model.is_empty() || model.len() > 128 || model.chars().any(char::is_control) {
                bail!("red-team plan model name is invalid or too long");
            }
        }
        let mut seen = BTreeSet::new();
        for attack in &self.attacks {
            if !is_known_kind(attack.kind) {
                bail!("red-team plan contains an unknown attack kind");
            }
            if !seen.insert(attack.kind) {
                bail!("red-team plan contains a duplicate attack kind");
            }
            if let Some(name) = &attack.name {
                if name.len() > 120 || name.chars().any(char::is_control) {
                    bail!("red-team attack name is invalid or too long");
                }
            }
        }
        Ok(())
    }

    pub fn expand(&self) -> Vec<PlannedAttack> {
        self.attacks
            .iter()
            .enumerate()
            .map(|(index, selection)| {
                let meta = selection.kind.meta();
                PlannedAttack {
                    id: format!("RT-{:02}", index + 1),
                    kind: selection.kind,
                    name: selection
                        .name
                        .clone()
                        .unwrap_or_else(|| meta.title.to_owned()),
                    control: meta.control,
                    weight: meta.weight,
                    critical: meta.critical,
                    offline: meta.offline,
                }
            })
            .collect()
    }
}

/// Deterministic plan: a seeded shuffle of the whole catalog, optionally
/// truncated to `max_attacks`.
pub fn deterministic_plan(seed: u64, max_attacks: Option<usize>) -> AttackPlan {
    let mut kinds = catalog().to_vec();
    shuffle(&mut kinds, seed);
    if let Some(limit) = max_attacks {
        kinds.truncate(limit.clamp(1, MAX_PLAN_ATTACKS));
    }
    AttackPlan {
        schema_version: PLAN_SCHEMA_VERSION,
        seed,
        source: "deterministic".into(),
        model: None,
        attacks: kinds
            .into_iter()
            .map(|kind| AttackSelection { kind, name: None })
            .collect(),
    }
}

/// Plan built from model-proposed kinds. The model cannot add controls,
/// weights, outcomes or free-form fields.
pub fn plan_from_kinds(
    seed: u64,
    model: &str,
    kinds: Vec<AttackKind>,
    max_attacks: Option<usize>,
) -> Result<AttackPlan> {
    let mut seen = BTreeSet::new();
    let mut attacks = Vec::new();
    for kind in kinds {
        if !is_known_kind(kind) {
            bail!("model proposed an unknown attack kind");
        }
        if seen.insert(kind) {
            attacks.push(AttackSelection { kind, name: None });
        }
    }
    if let Some(limit) = max_attacks {
        attacks.truncate(limit.clamp(1, MAX_PLAN_ATTACKS));
    }
    if attacks.is_empty() {
        bail!("model proposed no usable attacks");
    }
    let plan = AttackPlan {
        schema_version: PLAN_SCHEMA_VERSION,
        seed,
        source: "ollama".into(),
        model: Some(model.to_owned()),
        attacks,
    };
    plan.validate()?;
    Ok(plan)
}

fn shuffle(kinds: &mut [AttackKind], seed: u64) {
    let mut state = seed ^ 0x9e37_79b9_7f4a_7c15;
    for index in (1..kinds.len()).rev() {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        let pick = (state >> 33) as usize % (index + 1);
        kinds.swap(index, pick);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_has_unique_kinds_and_controls() {
        let mut kinds = BTreeSet::new();
        for kind in catalog() {
            assert!(kinds.insert(*kind), "duplicate attack kind in catalog");
            assert!(!kind.meta().control.is_empty());
            assert!(kind.meta().weight >= 1);
        }
        assert_eq!(kinds.len(), catalog().len());
    }

    #[test]
    fn deterministic_plan_is_stable_for_a_seed() {
        let a = deterministic_plan(42, None);
        let b = deterministic_plan(42, None);
        assert_eq!(
            a.attacks.iter().map(|x| x.kind).collect::<Vec<_>>(),
            b.attacks.iter().map(|x| x.kind).collect::<Vec<_>>()
        );
        a.validate().unwrap();
    }

    #[test]
    fn deterministic_plan_respects_attack_limit() {
        let plan = deterministic_plan(7, Some(3));
        assert_eq!(plan.attacks.len(), 3);
        plan.validate().unwrap();
    }

    #[test]
    fn plan_rejects_unknown_fields() {
        let json = r#"{"schema_version":1,"seed":1,"source":"deterministic","attacks":[{"kind":"auth_expired","control":"DEF-STATE"}],"extra":true}"#;
        assert!(serde_json::from_str::<AttackPlan>(json).is_err());
    }

    #[test]
    fn plan_rejects_duplicate_attacks() {
        let plan = AttackPlan {
            schema_version: PLAN_SCHEMA_VERSION,
            seed: 1,
            source: "test".into(),
            model: None,
            attacks: vec![
                AttackSelection {
                    kind: AttackKind::AuthExpired,
                    name: None,
                },
                AttackSelection {
                    kind: AttackKind::AuthExpired,
                    name: None,
                },
            ],
        };
        assert!(plan.validate().is_err());
    }
}
