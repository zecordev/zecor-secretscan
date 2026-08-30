// SPDX-License-Identifier: Apache-2.0
//! SARIF 2.1.0 output, so findings drop straight into GitHub code scanning or any
//! CI that speaks SARIF. One run, one rule per finding kind, results as errors.

use crate::Finding;
use serde_json::{json, Value};
use std::collections::BTreeSet;

const SCHEMA: &str = "https://json.schemastore.org/sarif-2.1.0.json";

pub fn to_sarif(findings: &[Finding], tool_version: &str) -> Value {
    let rule_ids: BTreeSet<&str> = findings.iter().map(|f| f.rule.as_str()).collect();
    let rules: Vec<Value> = rule_ids
        .iter()
        .map(|id| {
            json!({
                "id": id,
                "name": id,
                "shortDescription": { "text": describe(id) },
                "defaultConfiguration": { "level": "error" },
            })
        })
        .collect();

    let results: Vec<Value> = findings
        .iter()
        .map(|f| {
            json!({
                "ruleId": f.rule,
                "level": "error",
                "message": { "text": format!("{} (masked: {})", describe(&f.rule), f.hint) },
                "partialFingerprints": { "zecor/v1": f.fingerprint() },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": f.file },
                        "region": { "startLine": f.line.max(1) }
                    }
                }],
            })
        })
        .collect();

    json!({
        "$schema": SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "zecor-secretscan",
                    "informationUri": "https://zecor.dev",
                    "version": tool_version,
                    "rules": rules,
                }
            },
            "results": results,
        }]
    })
}

fn describe(rule: &str) -> &'static str {
    match rule {
        "aws-access-key-id" => "AWS access key id",
        "aws-secret-access-key" => "AWS secret access key",
        "github-token" => "GitHub token",
        "github-pat-fine" => "GitHub fine-grained PAT",
        "gitlab-pat" => "GitLab personal access token",
        "slack-token" => "Slack token",
        "slack-webhook" => "Slack incoming webhook URL",
        "google-api-key" => "Google API key",
        "gcp-sa-key" => "GCP service-account key material",
        "openai-key" => "OpenAI API key",
        "anthropic-key" => "Anthropic API key",
        "huggingface-token" => "Hugging Face access token",
        "stripe-secret-key" => "Stripe live secret key",
        "twilio-key" => "Twilio API key",
        "sendgrid-key" => "SendGrid API key",
        "npm-token" => "npm access token",
        "pypi-token" => "PyPI upload token",
        "jwt" => "JSON Web Token",
        "db-connection-uri" => "database connection URI with inline credentials",
        "private-key-block" => "PEM private key block",
        "generic-assignment" => "hardcoded credential assignment",
        "high-entropy-token" => "high-entropy token",
        r if r.starts_with("injection-") => "prompt-injection phrasing",
        _ => "potential secret",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shape_is_sarif_210() {
        let f = vec![Finding {
            rule: "github-token".into(),
            file: "a.py".into(),
            line: 3,
            hint: "ghp_\u{2026}zz".into(),
        }];
        let s = to_sarif(&f, "0.1.0");
        assert_eq!(s["version"], "2.1.0");
        assert_eq!(s["runs"][0]["results"][0]["ruleId"], "github-token");
        assert_eq!(
            s["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"],
            3
        );
        assert_eq!(
            s["runs"][0]["tool"]["driver"]["rules"][0]["id"],
            "github-token"
        );
    }
}
