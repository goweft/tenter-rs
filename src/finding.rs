use serde::{Deserialize, Serialize};
use std::fmt;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

// ─── Severity ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// Returns true if this severity is at or above the given threshold.
    pub fn at_least(self, threshold: Severity) -> bool {
        self >= threshold
    }

    /// ANSI colour code for terminal output (mirrors Python \033[Xm codes exactly).
    pub fn ansi_color(self) -> &'static str {
        match self {
            Severity::Critical | Severity::High => "\x1b[91m",
            Severity::Medium => "\x1b[93m",
            Severity::Low => "\x1b[96m",
            Severity::Info => "\x1b[90m",
        }
    }

    /// Icon used in human output.
    pub fn icon(self) -> &'static str {
        match self {
            Severity::Critical | Severity::High => "✖",
            Severity::Medium => "⚠",
            _ => "ℹ",
        }
    }

    /// Process exit code contribution.
    #[allow(dead_code)]
    pub fn exit_code(self) -> i32 {
        match self {
            Severity::Critical | Severity::High => 2,
            Severity::Medium => 1,
            _ => 0,
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Critical => write!(f, "CRITICAL"),
            Severity::High => write!(f, "HIGH"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::Low => write!(f, "LOW"),
            Severity::Info => write!(f, "INFO"),
        }
    }
}

impl std::str::FromStr for Severity {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "critical" => Ok(Severity::Critical),
            "high" => Ok(Severity::High),
            "medium" => Ok(Severity::Medium),
            "low" => Ok(Severity::Low),
            "info" => Ok(Severity::Info),
            other => Err(format!("unknown severity: {other}")),
        }
    }
}

// ─── Finding ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub rule_id: String,
    pub severity: Severity,
    pub file_path: String,
    pub message: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub detail: String,
}

impl Finding {
    pub fn new(
        rule_id: impl Into<String>,
        severity: Severity,
        file_path: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            rule_id: rule_id.into(),
            severity,
            file_path: file_path.into(),
            message: message.into(),
            detail: String::new(),
        }
    }

    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = detail.into();
        self
    }
}

// ─── ScanResult ──────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct ScanResult {
    pub package_type: String,
    pub package_path: String,
    pub total_files: usize,
    pub total_size_bytes: u64,
    pub findings: Vec<Finding>,
}

impl ScanResult {
    pub fn new(
        package_type: impl Into<String>,
        package_path: impl Into<String>,
    ) -> Self {
        Self {
            package_type: package_type.into(),
            package_path: package_path.into(),
            total_files: 0,
            total_size_bytes: 0,
            findings: Vec::new(),
        }
    }

    pub fn push(&mut self, f: Finding) {
        self.findings.push(f);
    }

    pub fn max_severity(&self) -> Option<Severity> {
        self.findings.iter().map(|f| f.severity).max()
    }

    /// Exit code based on highest severity finding.
    #[allow(dead_code)]
    pub fn exit_code(&self) -> i32 {
        self.max_severity().map(|s| s.exit_code()).unwrap_or(0)
    }

    /// Whether any finding is at or above the given threshold.
    pub fn has_finding_at_or_above(&self, threshold: Severity) -> bool {
        self.findings.iter().any(|f| f.severity.at_least(threshold))
    }

    /// Count findings by severity.
    pub fn count_at(&self, sev: Severity) -> usize {
        self.findings.iter().filter(|f| f.severity == sev).count()
    }

    /// Check if a file_path already has a specific rule finding
    /// (used to avoid duplicate MAP-001/DBG-001 on the same file).
    pub fn has_finding_for(&self, rule_id: &str, file_path: &str) -> bool {
        self.findings
            .iter()
            .any(|f| f.rule_id == rule_id && f.file_path == file_path)
    }
}
