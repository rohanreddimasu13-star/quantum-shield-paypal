//! Verdict derivation.
//!
//! The judge never trusts a model. It only accepts an attack as blocked when
//! the deterministic executor observed the *planned* control rejecting the
//! attempt **and** every post-attack invariant still holds.

use serde::Serialize;

use super::execute::{AttackExecution, InvariantCheck, Observation};
use super::plan::PlannedAttack;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// Correct control rejected the attack and no forbidden mutation occurred.
    VerifiedRejected,
    /// The attack succeeded: this is a bypass.
    UnexpectedAccept,
    /// Rejected, but by a different control than the one under test.
    UnexpectedReject,
    /// Rejected, but a forbidden state change or record was still created.
    InvariantViolation,
    /// Could not be evaluated offline (for example real PayPal signatures).
    NotEvaluated,
    /// The harness itself could not build or run the attack.
    InvalidAttack,
}

impl Verdict {
    pub fn is_evaluated(self) -> bool {
        !matches!(self, Self::NotEvaluated | Self::InvalidAttack)
    }

    pub fn is_blocked(self) -> bool {
        matches!(self, Self::VerifiedRejected)
    }

    pub fn is_bypass(self) -> bool {
        matches!(self, Self::UnexpectedAccept | Self::InvariantViolation)
    }
}

impl std::fmt::Display for Verdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::VerifiedRejected => "verified_rejected",
            Self::UnexpectedAccept => "unexpected_accept",
            Self::UnexpectedReject => "unexpected_reject",
            Self::InvariantViolation => "invariant_violation",
            Self::NotEvaluated => "not_evaluated",
            Self::InvalidAttack => "invalid_attack",
        })
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct AttackResult {
    pub id: String,
    pub kind: super::plan::AttackKind,
    pub name: String,
    pub control: String,
    pub weight: u32,
    pub critical: bool,
    pub verdict: Verdict,
    pub evaluated: bool,
    pub blocked: bool,
    pub observed_control: Option<String>,
    pub detail: String,
    pub invariants: Vec<InvariantCheck>,
    pub notes: Vec<String>,
}

pub fn judge(planned: &PlannedAttack, execution: AttackExecution) -> AttackResult {
    let invariants_ok = execution.invariants.iter().all(|check| check.passed);
    let (verdict, observed_control, detail) = match &execution.observation {
        Observation::Skipped { reason } => (Verdict::NotEvaluated, None, reason.clone()),
        Observation::Accepted { message } => (Verdict::UnexpectedAccept, None, message.clone()),
        Observation::Rejected { control, message } => {
            let observed = Some(control.clone());
            if !invariants_ok {
                (
                    Verdict::InvariantViolation,
                    observed,
                    format!(
                        "attack was rejected, but a forbidden state change was observed: {message}"
                    ),
                )
            } else if control != planned.control {
                (
                    Verdict::UnexpectedReject,
                    observed,
                    format!(
                        "attack was rejected by {control}, not the planned control {}: {message}",
                        planned.control
                    ),
                )
            } else {
                (Verdict::VerifiedRejected, observed, message.clone())
            }
        }
    };

    AttackResult {
        id: planned.id.clone(),
        kind: planned.kind,
        name: planned.name.clone(),
        control: planned.control.into(),
        weight: planned.weight,
        critical: planned.critical,
        verdict,
        evaluated: verdict.is_evaluated(),
        blocked: verdict.is_blocked(),
        observed_control,
        detail,
        invariants: execution.invariants,
        notes: execution.notes,
    }
}

pub fn invalid(planned: &PlannedAttack, error: impl Into<String>) -> AttackResult {
    AttackResult {
        id: planned.id.clone(),
        kind: planned.kind,
        name: planned.name.clone(),
        control: planned.control.into(),
        weight: planned.weight,
        critical: planned.critical,
        verdict: Verdict::InvalidAttack,
        evaluated: false,
        blocked: false,
        observed_control: None,
        detail: error.into(),
        invariants: Vec::new(),
        notes: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::payment_redteam::plan::AttackKind;

    fn planned() -> PlannedAttack {
        PlannedAttack {
            id: "RT-01".into(),
            kind: AttackKind::AuthExpired,
            name: "Expired authorization".into(),
            control: "DEF-AUTH-EXPIRY",
            weight: 3,
            critical: false,
            offline: true,
        }
    }

    #[test]
    fn matching_rejection_with_clean_invariants_is_blocked() {
        let execution = AttackExecution::rejected("DEF-AUTH-EXPIRY", "authorization has expired")
            .with_invariants(vec![InvariantCheck {
                name: "payment_state_unchanged".into(),
                passed: true,
                detail: "pending".into(),
            }]);
        let result = judge(&planned(), execution);
        assert_eq!(result.verdict, Verdict::VerifiedRejected);
        assert!(result.blocked);
    }

    #[test]
    fn wrong_control_is_not_counted_as_blocked() {
        let execution = AttackExecution::rejected("DEF-AUTH-SIG", "signature failed");
        let result = judge(&planned(), execution);
        assert_eq!(result.verdict, Verdict::UnexpectedReject);
        assert!(!result.blocked);
    }

    #[test]
    fn forbidden_mutation_is_a_bypass() {
        let execution = AttackExecution::rejected("DEF-AUTH-EXPIRY", "authorization has expired")
            .with_invariants(vec![InvariantCheck {
                name: "payment_state_unchanged".into(),
                passed: false,
                detail: "payment was captured".into(),
            }]);
        let result = judge(&planned(), execution);
        assert_eq!(result.verdict, Verdict::InvariantViolation);
        assert!(result.verdict.is_bypass());
        assert!(!result.blocked);
    }

    #[test]
    fn accepted_attack_is_a_bypass() {
        let execution = AttackExecution::accepted("attack succeeded");
        let result = judge(&planned(), execution);
        assert_eq!(result.verdict, Verdict::UnexpectedAccept);
        assert!(result.verdict.is_bypass());
    }
}
