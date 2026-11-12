//! Optional local-model attack planner.
//!
//! The model is an *attacker proposal source only*. It receives a fixed catalog
//! and schema, never credentials or keys, and its output is parsed into the same
//! strict `AttackSelection` type used by the deterministic planner. It cannot
//! add controls, weights, expected outcomes or success claims.

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use serde_json::json;
use std::time::Duration;
use url::Url;

use super::plan::{catalog, plan_from_kinds, AttackKind, AttackPlan};
use super::synthetic::SYNTHETIC_PAYMENT_ID;

const MAX_AI_BODY_BYTES: usize = 1024 * 1024;
const AI_TIMEOUT_SECONDS: u64 = 120;

#[derive(Deserialize)]
struct OllamaResponse {
    response: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AiPlanResponse {
    attacks: Vec<AiAttack>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AiAttack {
    kind: AttackKind,
    #[serde(default)]
    rationale: Option<String>,
}

pub async fn plan_from_ollama(
    ai_url: &str,
    model: &str,
    seed: u64,
    max_attacks: Option<usize>,
) -> Result<AttackPlan> {
    let endpoint = generate_endpoint(ai_url)?;
    if model.is_empty() || model.len() > 128 || model.chars().any(char::is_control) {
        bail!("invalid local model name");
    }

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(AI_TIMEOUT_SECONDS))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("could not build the local Ollama client")?;
    let prompt = build_prompt(max_attacks);
    let response = client
        .post(endpoint.clone())
        .json(&json!({
            "model": model,
            "prompt": prompt,
            "stream": false,
            "format": "json",
            "options": {"temperature": 0, "num_predict": 512}
        }))
        .send()
        .await
        .with_context(|| {
            format!(
                "could not reach the local Ollama planner at {endpoint}; \
                 start it with `ollama serve` or use --provider deterministic"
            )
        })?;
    if !response.status().is_success() {
        bail!(
            "local Ollama planner returned HTTP {}; use --provider deterministic if it is unavailable",
            response.status()
        );
    }
    let body = response
        .bytes()
        .await
        .context("could not read the local Ollama response")?;
    if body.len() > MAX_AI_BODY_BYTES {
        bail!("local Ollama response exceeds the 1 MiB limit");
    }
    let envelope: OllamaResponse =
        serde_json::from_slice(&body).context("invalid Ollama response envelope")?;
    if envelope.response.len() > MAX_AI_BODY_BYTES {
        bail!("model plan exceeds the 1 MiB limit");
    }
    let parsed: AiPlanResponse = serde_json::from_str(&envelope.response)
        .context("model did not return a valid attack plan; no attacks were executed")?;
    if parsed.attacks.len() > 64 {
        bail!("model proposed more attacks than the hard limit");
    }

    let kinds: Vec<AttackKind> = parsed
        .attacks
        .into_iter()
        .map(|attack| {
            if let Some(rationale) = &attack.rationale {
                if rationale.len() > 500 || rationale.chars().any(char::is_control) {
                    bail!("model rationale is invalid or too long");
                }
            }
            Ok(attack.kind)
        })
        .collect::<Result<_>>()?;

    plan_from_kinds(seed, model, kinds, max_attacks)
}

fn generate_endpoint(ai_url: &str) -> Result<Url> {
    let parsed = Url::parse(ai_url).context("invalid --ai-url")?;
    if parsed.scheme() != "http" && parsed.scheme() != "https" {
        bail!("--ai-url must use http or https");
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        bail!("--ai-url must not contain credentials");
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        bail!("--ai-url must not contain a query or fragment");
    }
    let host = parsed.host_str().context("--ai-url has no host")?;
    if !matches!(host, "localhost" | "127.0.0.1" | "::1" | "[::1]") {
        bail!("--ai-url must point at loopback (localhost, 127.0.0.1 or ::1)");
    }
    let endpoint = format!("{}/api/generate", parsed.as_str().trim_end_matches('/'));
    Url::parse(&endpoint).context("could not build the local Ollama endpoint")
}

fn build_prompt(max_attacks: Option<usize>) -> String {
    let limit = max_attacks.unwrap_or(12).clamp(1, 32);
    let kinds: Vec<String> = catalog()
        .iter()
        .map(|kind| {
            let name = serde_json::to_value(kind)
                .ok()
                .and_then(|value| value.as_str().map(str::to_owned))
                .unwrap_or_default();
            format!("- {name}")
        })
        .collect();
    format!(
        "You are an adversarial payment-security test planner.\n\
         You may ONLY choose attack kinds from the fixed list below.\n\
         Return one JSON object and nothing else, with exactly this shape:\n\
         {{\"attacks\":[{{\"kind\":\"<kind>\",\"rationale\":\"<short reason>\"}}]}}\n\
         Choose at most {limit} kinds. Do not repeat a kind.\n\
         Do not invent fields. Do not include control IDs, expected outcomes, scores, commands, credentials or secrets.\n\
         Deterministic Rust code executes every chosen attack against synthetic local fixtures and decides the result.\n\
         Synthetic payment identifier for context only: {SYNTHETIC_PAYMENT_ID}\n\
         Allowed kinds:\n{}\n",
        kinds.join("\n")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_urls_are_accepted_and_public_urls_are_rejected() {
        assert!(generate_endpoint("http://127.0.0.1:11434").is_ok());
        assert!(generate_endpoint("http://localhost:11434/").is_ok());
        assert!(generate_endpoint("http://[::1]:11434").is_ok());
        assert!(generate_endpoint("https://api.openai.com").is_err());
        assert!(generate_endpoint("http://10.0.0.5:11434").is_err());
        assert!(generate_endpoint("http://user:pass@127.0.0.1:11434").is_err());
        assert!(generate_endpoint("file:///etc/passwd").is_err());
    }

    #[test]
    fn model_output_must_be_strict_json_with_known_kinds() {
        let good = r#"{"attacks":[{"kind":"auth_expired"}]}"#;
        assert!(serde_json::from_str::<AiPlanResponse>(good).is_ok());
        let extra_field = r#"{"attacks":[{"kind":"auth_expired","control":"DEF-STATE"}]}"#;
        assert!(serde_json::from_str::<AiPlanResponse>(extra_field).is_err());
        let unknown_kind = r#"{"attacks":[{"kind":"steal_card"}]}"#;
        assert!(serde_json::from_str::<AiPlanResponse>(unknown_kind).is_err());
    }

    #[test]
    fn prompt_contains_the_catalog_but_no_secret_names() {
        let prompt = build_prompt(Some(4));
        assert!(prompt.contains("auth_signature_tamper"));
        assert!(prompt.contains("paypal_webhook_signature"));
        assert!(!prompt.contains("PAYPAL_CLIENT_SECRET"));
        assert!(!prompt.contains("PAYPAL_CLIENT_ID"));
        assert!(!prompt.contains("QS_API_TOKEN"));
    }

    #[test]
    fn ai_cannot_contribute_unknown_fields_to_a_plan() {
        let response: AiPlanResponse =
            serde_json::from_str(r#"{"attacks":[{"kind":"auth_expired"}]}"#).unwrap();
        let kinds = response.attacks.into_iter().map(|a| a.kind).collect();
        let plan = plan_from_kinds(1, "test-model", kinds, Some(4)).unwrap();
        assert_eq!(plan.attacks.len(), 1);
        assert_eq!(plan.source, "ollama");
    }

    #[test]
    fn endpoint_is_built_without_duplicating_slashes() {
        let endpoint = generate_endpoint("http://127.0.0.1:11434/").unwrap();
        assert_eq!(endpoint.as_str(), "http://127.0.0.1:11434/api/generate");
    }
}
