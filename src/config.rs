use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::{Path, PathBuf};

pub const DEFAULT_SINGLE_FILE_WARN: u64 = 10 * 1024 * 1024;  // 10 MB
pub const DEFAULT_SINGLE_FILE_CRIT: u64 = 50 * 1024 * 1024;  // 50 MB
pub const DEFAULT_TOTAL_WARN: u64 = 50 * 1024 * 1024;        // 50 MB
pub const DEFAULT_TOTAL_CRIT: u64 = 200 * 1024 * 1024;       // 200 MB

/// Mirrors .tenter.json schema exactly.
/// Unknown keys are silently ignored for forward-compatibility.
#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct Config {
    pub allowlist: Vec<String>,
    pub size_limit_single_file_bytes: u64,
    pub size_limit_total_bytes: u64,
    pub extra_sensitive_patterns: Vec<String>,
    pub extra_debug_patterns: Vec<String>,

    // content_scan_timeout_secs from v1 is accepted but ignored:
    // Rust's regex crate is linear-time (DFA/NFA), ReDoS is impossible.
    #[serde(default)]
    #[allow(dead_code)]
    pub content_scan_timeout_secs: Option<f64>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            allowlist: Vec::new(),
            size_limit_single_file_bytes: DEFAULT_SINGLE_FILE_CRIT,
            size_limit_total_bytes: DEFAULT_TOTAL_CRIT,
            extra_sensitive_patterns: Vec::new(),
            extra_debug_patterns: Vec::new(),
            content_scan_timeout_secs: None,
        }
    }
}

impl Config {
    pub fn default_json() -> String {
        serde_json::json!({
            "$schema": "https://github.com/goweft/tenter-rs/blob/main/schema.json",
            "allowlist": [],
            "size_limit_single_file_bytes": DEFAULT_SINGLE_FILE_CRIT,
            "size_limit_total_bytes": DEFAULT_TOTAL_CRIT,
            "extra_sensitive_patterns": [],
            "extra_debug_patterns": []
        })
        .to_string()
    }
}

/// Load config from explicit path or by searching upward from cwd.
pub fn load_config(explicit: Option<&Path>) -> Result<Config> {
    let path = if let Some(p) = explicit {
        if !p.exists() {
            anyhow::bail!("config file not found: {}", p.display());
        }
        Some(p.to_path_buf())
    } else {
        find_config_file()
    };

    match path {
        None => Ok(Config::default()),
        Some(p) => {
            let text = std::fs::read_to_string(&p)
                .with_context(|| format!("failed to read config: {}", p.display()))?;
            let cfg: Config = serde_json::from_str(&text)
                .with_context(|| format!("failed to parse config: {}", p.display()))?;
            Ok(cfg)
        }
    }
}

fn find_config_file() -> Option<PathBuf> {
    let candidates = [".tenter.json", ".publishguardrc"];
    let cwd = std::env::current_dir().ok()?;
    for name in &candidates {
        let p = cwd.join(name);
        if p.exists() {
            return Some(p);
        }
    }
    None
}
