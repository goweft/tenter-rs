use crate::finding::{Severity, ScanResult, VERSION};
use serde_json::{json, Value};
use std::collections::HashMap;

pub fn format(result: &ScanResult) -> String {
    let mut rules: HashMap<&str, Value> = HashMap::new();
    let mut sarif_results: Vec<Value> = Vec::new();

    for f in &result.findings {
        rules.entry(&f.rule_id).or_insert_with(|| {
            json!({
                "id": f.rule_id,
                "shortDescription": { "text": f.message },
            })
        });

        let level = match f.severity {
            Severity::Critical | Severity::High => "error",
            Severity::Medium => "warning",
            _ => "note",
        };

        let msg_text = if f.detail.is_empty() {
            f.message.clone()
        } else {
            format!("{}. {}", f.message, f.detail)
        };

        sarif_results.push(json!({
            "ruleId": f.rule_id,
            "level": level,
            "message": { "text": msg_text },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": { "uri": f.file_path }
                }
            }]
        }));
    }

    let mut rules_list: Vec<Value> = rules.into_values().collect();
    // stable ordering for deterministic output
    rules_list.sort_by(|a, b| {
        a["id"].as_str().unwrap_or("").cmp(b["id"].as_str().unwrap_or(""))
    });

    let sarif = json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "tenter",
                    "version": VERSION,
                    "informationUri": "https://github.com/goweft/tenter-rs",
                    "rules": rules_list,
                }
            },
            "results": sarif_results,
        }]
    });

    serde_json::to_string_pretty(&sarif).unwrap_or_else(|_| "{}".to_owned())
}
