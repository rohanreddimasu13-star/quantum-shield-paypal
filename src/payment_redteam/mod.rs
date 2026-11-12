//! Offline adversarial payment red team.
//!
//! The AI, when enabled, is only an attack-plan proposal source. Every verdict
//! is produced by Quantum Shield's deterministic payment code. The executor has
//! no PayPal client and performs no capture, refund, transfer or provider call.

mod ai;
mod execute;
mod judge;
mod plan;
mod report;
mod synthetic;

use anyhow::{bail, Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

pub use judge::{AttackResult, Verdict};
pub use plan::{AttackKind, AttackPlan, AttackSelection, PlannedAttack, RedTeamProvider};
pub use report::RedTeamReport;

use execute::AttackExecution;

const MAX_PLAN_BYTES: u64 = 1024 * 1024;

pub struct RedTeamOptions {
    pub provider: RedTeamProvider,
    pub model: String,
    pub ai_url: String,
    pub seed: u64,
    pub max_attacks: Option<usize>,
    pub plan_in: Option<PathBuf>,
    pub plan_out: Option<PathBuf>,
    pub report_dir: Option<PathBuf>,
    pub json: bool,
}

pub async fn run(options: RedTeamOptions) -> Result<RedTeamReport> {
    assert_safe_environment()?;

    let plan = if let Some(path) = options.plan_in.as_deref() {
        load_plan(path)?
    } else if options.provider == RedTeamProvider::Ollama {
        ai::plan_from_ollama(
            &options.ai_url,
            &options.model,
            options.seed,
            options.max_attacks,
        )
        .await?
    } else {
        plan::deterministic_plan(options.seed, options.max_attacks)
    };
    plan.validate()?;

    if let Some(path) = options.plan_out.as_deref() {
        write_plan(path, &plan)?;
    }

    let results = execute_plan(&plan);
    let report = report::build(&plan, results);
    if let Some(directory) = options.report_dir.as_deref() {
        let written = report::write_report_files(&report, directory)?;
        if !options.json {
            for path in written {
                println!("red-team report written to {}", path.display());
            }
        }
    }
    Ok(report)
}

pub fn print_report(report: &RedTeamReport, json: bool) -> Result<()> {
    report::print_report(report, json)
}

fn execute_plan(plan: &AttackPlan) -> Vec<AttackResult> {
    plan.expand()
        .iter()
        .map(|attack| {
            if !attack.offline {
                return judge::judge(
                    attack,
                    AttackExecution::skipped(
                        "requires PayPal's live signature-verification API and credentials; \
                         not evaluated in this offline harness",
                    ),
                );
            }
            match execute::execute(attack.kind) {
                Ok(execution) => judge::judge(attack, execution),
                Err(error) => judge::invalid(attack, format!("{error:#}")),
            }
        })
        .collect()
}

/// Refuse to run at all when the environment is pointed at live PayPal.
/// The red team never uses a PayPal client, but this failure-closed guard makes
/// accidental reuse in a live shell impossible.
fn assert_safe_environment() -> Result<()> {
    let value = std::env::var("PAYPAL_ENVIRONMENT").ok();
    safe_environment_value(value.as_deref())
}

fn safe_environment_value(value: Option<&str>) -> Result<()> {
    if value
        .map(|value| value.trim().eq_ignore_ascii_case("live"))
        .unwrap_or(false)
    {
        bail!(
            "refusing to run: PAYPAL_ENVIRONMENT=live. \
             Payment red-team fixtures are synthetic and must never be mixed with live PayPal."
        );
    }
    Ok(())
}

fn load_plan(path: &Path) -> Result<AttackPlan> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("cannot inspect plan file {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("plan file must be a regular file");
    }
    if metadata.len() > MAX_PLAN_BYTES {
        bail!("plan file exceeds the 1 MiB limit");
    }
    let bytes = fs::read(path).with_context(|| format!("cannot read {}", path.display()))?;
    let plan: AttackPlan = serde_json::from_slice(&bytes).context("invalid red-team plan JSON")?;
    plan.validate()?;
    Ok(plan)
}

fn write_plan(path: &Path, plan: &AttackPlan) -> Result<()> {
    let rendered =
        serde_json::to_string_pretty(plan).context("could not serialize red-team plan")?;
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .with_context(|| format!("cannot create {}", parent.display()))?;
        }
    }
    fs::write(path, rendered).with_context(|| format!("cannot write {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_deterministic_run_passes_without_bypasses() {
        let plan = plan::deterministic_plan(42, None);
        let results = execute_plan(&plan);
        let report = report::build(&plan, results);
        assert_eq!(
            report.bypasses,
            0,
            "unexpected bypasses: {:?}",
            report
                .results
                .iter()
                .filter(|result| result.verdict.is_bypass())
                .map(|result| (&result.name, &result.detail))
                .collect::<Vec<_>>()
        );
        assert_eq!(
            report.wrong_control,
            0,
            "wrong-control rejections: {:?}",
            report
                .results
                .iter()
                .filter(|result| result.verdict == Verdict::UnexpectedReject)
                .map(|result| (&result.name, &result.detail))
                .collect::<Vec<_>>()
        );
        assert_eq!(report.invalid, 0);
        assert_eq!(report.verdict, "PASS");
        assert!(report.coverage_percent >= report::MINIMUM_COVERAGE_PERCENT);
        assert!(report.defense_score < 100.0);
    }

    #[test]
    fn plan_round_trips_through_json() {
        let plan = plan::deterministic_plan(9, Some(4));
        let rendered = serde_json::to_string(&plan).unwrap();
        let parsed: AttackPlan = serde_json::from_str(&rendered).unwrap();
        parsed.validate().unwrap();
        assert_eq!(parsed.attacks.len(), 4);
    }

    #[test]
    fn live_paypal_environment_is_refused() {
        assert!(safe_environment_value(Some("live")).is_err());
        assert!(safe_environment_value(Some("LIVE")).is_err());
        assert!(safe_environment_value(Some("sandbox")).is_ok());
        assert!(safe_environment_value(None).is_ok());
    }
}
