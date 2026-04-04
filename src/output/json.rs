use crate::finding::{ScanResult, VERSION};
use serde_json::{json, Value};

pub fn format(result: &ScanResult) -> String {
    let findings: Vec<Value> = result
        .findings
        .iter()
        .map(|f| {
            let mut obj = json!({
                "rule_id": f.rule_id,
                "severity": f.severity.to_string(),
                "file_path": f.file_path,
                "message": f.message,
            });
            if !f.detail.is_empty() {
                obj["detail"] = json!(f.detail);
            }
            obj
        })
        .collect();

    let doc = json!({
        "version": VERSION,
        "package_type": result.package_type,
        "package_path": result.package_path,
        "total_files": result.total_files,
        "total_size_bytes": result.total_size_bytes,
        "findings_count": result.findings.len(),
        "max_severity": result.max_severity().map(|s| s.to_string()),
        "findings": findings,
    });

    serde_json::to_string_pretty(&doc).unwrap_or_else(|_| "{}".to_owned())
}
