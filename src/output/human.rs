use crate::finding::{Finding, Severity, ScanResult};

const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
const GREEN: &str = "\x1b[92m";

pub fn format(result: &ScanResult, color: bool) -> String {
    let mut out = String::new();

    let c = |code: &str, text: &str| -> String {
        if color { format!("{code}{text}{RESET}") } else { text.to_owned() }
    };

    out.push('\n');
    out.push_str(&c(BOLD, "═══ tenter scan results ═══"));
    out.push('\n');
    out.push_str(&format!(
        "  Package type: {}\n  Path: {}\n  Files: {}\n  Size: {:.1} KB ({:.2} MB)\n",
        result.package_type,
        result.package_path,
        result.total_files,
        result.total_size_bytes as f64 / 1024.0,
        result.total_size_bytes as f64 / (1024.0 * 1024.0),
    ));
    out.push('\n');

    if result.findings.is_empty() {
        out.push_str(&c(GREEN, "  ✓ No issues found. Safe to publish."));
        out.push('\n');
        return out;
    }

    for sev in &[
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ] {
        let group: Vec<&Finding> =
            result.findings.iter().filter(|f| &f.severity == sev).collect();
        if group.is_empty() { continue; }

        out.push_str(&c(sev.ansi_color(), &format!("  ┌─ {sev} ({})", group.len())));
        out.push('\n');

        for f in &group {
            out.push_str(&c(
                sev.ansi_color(),
                &format!("  │ {} [{}] {}", sev.icon(), f.rule_id, f.file_path),
            ));
            out.push('\n');
            out.push_str(&format!("  │   {}\n", f.message));
            if !f.detail.is_empty() {
                out.push_str(&c(DIM, &format!("  │   {}", f.detail)));
                out.push('\n');
            }
        }
        out.push_str(&format!("  └{}\n\n", "─".repeat(60)));
    }

    let total = result.findings.len();
    let crit = result.count_at(Severity::Critical);
    let high = result.count_at(Severity::High);

    if crit > 0 || high > 0 {
        out.push_str(&c(
            "\x1b[91m",
            &format!(
                "  ✖ BLOCKED: {total} finding(s) — {crit} critical, {high} high. DO NOT PUBLISH."
            ),
        ));
    } else {
        out.push_str(&c(
            "\x1b[93m",
            &format!("  ⚠ {total} finding(s). Review before publishing."),
        ));
    }
    out.push('\n');
    out
}
