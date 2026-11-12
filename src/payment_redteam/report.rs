//! Scoring and reporting for the offline payment red team.
//!
//! The score is weighted over the **whole** catalog, not only the attacks that
//! happened to run, so a truncated or partially evaluated run can never report
//! a misleading 100%.

use anyhow::{Context, Result};
use serde::Serialize;
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use super::judge::AttackResult;
use super::plan::{catalog, AttackPlan};

pub const REPORT_SCHEMA_VERSION: u32 = 1;
pub const MINIMUM_COVERAGE_PERCENT: f64 = 80.0;

#[derive(Debug, Clone, Serialize)]
pub struct RedTeamReport {
    pub schema_version: u32,
    pub generated_at_unix: u64,
    pub provider: String,
    pub model: Option<String>,
    pub seed: u64,
    pub plan_source: String,
    pub execution_mode: String,
    pub catalog_size: usize,
    pub total_attacks: usize,
    pub evaluated: usize,
    pub verified_rejected: usize,
    pub bypasses: usize,
    pub critical_bypasses: usize,
    pub wrong_control: usize,
    pub invariant_violations: usize,
    pub not_evaluated: usize,
    pub invalid: usize,
    pub evaluated_score: f64,
    pub defense_score: f64,
    pub coverage_percent: f64,
    pub grade: String,
    pub verdict: String,
    pub results: Vec<AttackResult>,
    pub limitations: Vec<String>,
}

impl RedTeamReport {
    pub fn passed(&self) -> bool {
        self.verdict == "PASS"
    }
}

pub fn build(plan: &AttackPlan, results: Vec<AttackResult>) -> RedTeamReport {
    let catalog_weight: u32 = catalog().iter().map(|kind| kind.meta().weight).sum();
    let evaluated: Vec<&AttackResult> = results.iter().filter(|result| result.evaluated).collect();
    let blocked: Vec<&AttackResult> = results.iter().filter(|result| result.blocked).collect();

    let evaluated_weight: u32 = evaluated.iter().map(|result| result.weight).sum();
    let blocked_weight: u32 = blocked.iter().map(|result| result.weight).sum();
    let bypasses = results
        .iter()
        .filter(|result| result.verdict.is_bypass())
        .count();
    let critical_bypasses = results
        .iter()
        .filter(|result| result.verdict.is_bypass() && result.critical)
        .count();
    let wrong_control = results
        .iter()
        .filter(|result| result.verdict == super::judge::Verdict::UnexpectedReject)
        .count();
    let invariant_violations = results
        .iter()
        .filter(|result| result.verdict == super::judge::Verdict::InvariantViolation)
        .count();
    let not_evaluated = results
        .iter()
        .filter(|result| result.verdict == super::judge::Verdict::NotEvaluated)
        .count();
    let invalid = results
        .iter()
        .filter(|result| result.verdict == super::judge::Verdict::InvalidAttack)
        .count();

    let evaluated_score = ratio(blocked_weight, evaluated_weight);
    let defense_score = ratio(blocked_weight, catalog_weight);
    let coverage_percent = ratio(evaluated.len() as u32, catalog().len() as u32);

    let verdict = if bypasses > 0 || critical_bypasses > 0 || invariant_violations > 0 {
        "FAIL"
    } else if evaluated.is_empty() {
        "NOTHING_EVALUATED"
    } else if coverage_percent < MINIMUM_COVERAGE_PERCENT {
        "INSUFFICIENT_COVERAGE"
    } else if wrong_control > 0 || invalid > 0 || blocked.len() != evaluated.len() {
        "FAIL"
    } else {
        "PASS"
    };

    let grade = if critical_bypasses > 0 || !verdict_is_passing(verdict) {
        "F".to_owned()
    } else if defense_score >= 90.0 {
        "A".to_owned()
    } else if defense_score >= 80.0 {
        "B".to_owned()
    } else if defense_score >= 70.0 {
        "C".to_owned()
    } else if defense_score >= 60.0 {
        "D".to_owned()
    } else {
        "F".to_owned()
    };

    RedTeamReport {
        schema_version: REPORT_SCHEMA_VERSION,
        generated_at_unix: unix_now(),
        provider: plan.source.clone(),
        model: plan.model.clone(),
        seed: plan.seed,
        plan_source: plan.source.clone(),
        execution_mode: "offline_synthetic".into(),
        catalog_size: catalog().len(),
        total_attacks: results.len(),
        evaluated: evaluated.len(),
        verified_rejected: blocked.len(),
        bypasses,
        critical_bypasses,
        wrong_control,
        invariant_violations,
        not_evaluated,
        invalid,
        evaluated_score: round2(evaluated_score),
        defense_score: round2(defense_score),
        coverage_percent: round2(coverage_percent),
        grade,
        verdict: verdict.into(),
        results,
        limitations: limitations(),
    }
}

fn verdict_is_passing(verdict: &str) -> bool {
    verdict == "PASS"
}

fn ratio(numerator: u32, denominator: u32) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        f64::from(numerator) * 100.0 / f64::from(denominator)
    }
}

fn round2(value: f64) -> f64 {
    (value * 100.0).round() / 100.0
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs())
        .unwrap_or(0)
}

fn limitations() -> Vec<String> {
    vec![
        "Runs only against synthetic local fixtures; it never contacts PayPal and never captures, refunds or transfers money.".into(),
        "No PayPal client, credential or production payment datastore is present in the executor.".into(),
        "Real PayPal webhook signature verification (DEF-WH-SIG) requires PayPal's API and credentials and is reported as not_evaluated, not blocked.".into(),
        "An AI planner, when enabled, may only choose attack kinds from a fixed catalog. It never sees secrets and never decides the verdict.".into(),
        "The defense score is weighted over the full catalog and must not be read as a guarantee that the payment system is secure.".into(),
    ]
}

pub fn print_report(report: &RedTeamReport, json: bool) -> Result<()> {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(report).context("could not serialize red-team report")?
        );
    } else {
        print!("{}", render_human(report));
    }
    Ok(())
}

pub fn write_report_files(
    report: &RedTeamReport,
    directory: &Path,
) -> Result<Vec<std::path::PathBuf>> {
    fs::create_dir_all(directory)
        .with_context(|| format!("cannot create report directory {}", directory.display()))?;
    let stamp = report.generated_at_unix;
    let json_path = directory.join(format!("payment-redteam-{stamp}.json"));
    let text_path = directory.join(format!("payment-redteam-{stamp}.txt"));
    fs::write(
        &json_path,
        serde_json::to_string_pretty(report).context("could not serialize red-team report")?,
    )
    .with_context(|| format!("cannot write {}", json_path.display()))?;
    fs::write(&text_path, render_human(report))
        .with_context(|| format!("cannot write {}", text_path.display()))?;
    Ok(vec![json_path, text_path])
}

fn render_human(report: &RedTeamReport) -> String {
    let mut output = format!(
        "QUANTUM SHIELD - PAYMENT RED TEAM (OFFLINE SYNTHETIC)\n{}\n\
         Generated (Unix):       {}\n\
         Plan source:            {}{}\n\
         Seed:                   {}\n\
         Execution mode:         {}\n\
         Catalog / planned:      {} / {}\n\
         Evaluated:              {}\n\
         Verified rejected:      {}\n\
         Bypasses:               {} (critical: {})\n\
         Wrong-control rejects:  {}\n\
         Invariant violations:   {}\n\
         Not evaluated:          {}\n\
         Invalid attacks:        {}\n\
         Evaluated score:        {:.2}%\n\
         Coverage-weighted:      {:.2}%\n\
         Coverage:               {:.2}%\n\
         Grade:                  {}\n\
         Verdict:                {}\n\n",
        "=".repeat(78),
        report.generated_at_unix,
        report.plan_source,
        report
            .model
            .as_ref()
            .map(|model| format!(" ({model})"))
            .unwrap_or_default(),
        report.seed,
        report.execution_mode,
        report.catalog_size,
        report.total_attacks,
        report.evaluated,
        report.verified_rejected,
        report.bypasses,
        report.critical_bypasses,
        report.wrong_control,
        report.invariant_violations,
        report.not_evaluated,
        report.invalid,
        report.evaluated_score,
        report.defense_score,
        report.coverage_percent,
        report.grade,
        report.verdict
    );

    for result in &report.results {
        let marker = match result.verdict {
            super::judge::Verdict::VerifiedRejected => "BLOCKED",
            super::judge::Verdict::UnexpectedAccept => "BYPASS",
            super::judge::Verdict::UnexpectedReject => "WRONG-CONTROL",
            super::judge::Verdict::InvariantViolation => "INVARIANT-VIOLATION",
            super::judge::Verdict::NotEvaluated => "NOT-EVALUATED",
            super::judge::Verdict::InvalidAttack => "INVALID",
        };
        output.push_str(&format!(
            "[{marker}] {} {} - {} (control {})\n    {}\n",
            result.id, result.name, result.verdict, result.control, result.detail
        ));
        for check in &result.invariants {
            output.push_str(&format!(
                "    invariant {}: {}\n",
                check.name,
                if check.passed { "ok" } else { "FAILED" }
            ));
        }
        for note in &result.notes {
            output.push_str(&format!("    note: {note}\n"));
        }
    }

    output.push_str("\nLIMITATIONS\n");
    for limitation in &report.limitations {
        output.push_str(&format!("- {limitation}\n"));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::payment_redteam::judge::{invalid, judge, Verdict};
    use crate::payment_redteam::plan::{AttackKind, AttackPlan, AttackSelection};

    fn plan() -> AttackPlan {
        AttackPlan {
            schema_version: 1,
            seed: 0,
            source: "deterministic".into(),
            model: None,
            attacks: vec![AttackSelection {
                kind: AttackKind::AuthExpired,
                name: None,
            }],
        }
    }

    fn result(verdict: Verdict) -> AttackResult {
        AttackResult {
            id: "RT-01".into(),
            kind: AttackKind::AuthExpired,
            name: "Expired authorization".into(),
            control: "DEF-AUTH-EXPIRY".into(),
            weight: 3,
            critical: false,
            verdict,
            evaluated: verdict.is_evaluated(),
            blocked: verdict.is_blocked(),
            observed_control: None,
            detail: String::new(),
            invariants: Vec::new(),
            notes: Vec::new(),
        }
    }

    #[test]
    fn partial_run_never_scores_one_hundred() {
        let report = build(&plan(), vec![result(Verdict::VerifiedRejected)]);
        assert!(report.defense_score < 100.0);
        assert_eq!(report.verdict, "INSUFFICIENT_COVERAGE");
    }

    #[test]
    fn bypass_forces_failure_and_f_grade() {
        let mut bypass = result(Verdict::UnexpectedAccept);
        bypass.critical = true;
        let report = build(&plan(), vec![bypass]);
        assert_eq!(report.verdict, "FAIL");
        assert_eq!(report.grade, "F");
        assert_eq!(report.critical_bypasses, 1);
    }

    #[test]
    fn judge_wrapper_marks_invalid_as_not_evaluated() {
        let planned = plan().expand().pop().unwrap();
        let result = invalid(&planned, "fixture failed");
        assert_eq!(result.verdict, Verdict::InvalidAttack);
        assert!(!result.evaluated);
    }

    #[test]
    fn human_render_mentions_limitations() {
        let report = build(&plan(), vec![result(Verdict::VerifiedRejected)]);
        let rendered = render_human(&report);
        assert!(rendered.contains("LIMITATIONS"));
        assert!(rendered.contains("not_evaluated"));
    }

    #[test]
    fn judge_accepts_only_the_planned_control() {
        let planned = plan().expand().pop().unwrap();
        let execution =
            crate::payment_redteam::execute::AttackExecution::rejected("DEF-AUTH-SIG", "signature");
        assert_eq!(
            judge(&planned, execution).verdict,
            Verdict::UnexpectedReject
        );
        let execution = crate::payment_redteam::execute::AttackExecution::rejected(
            "DEF-AUTH-EXPIRY",
            "expired",
        );
        assert_eq!(
            judge(&planned, execution).verdict,
            Verdict::VerifiedRejected
        );
    }
}
