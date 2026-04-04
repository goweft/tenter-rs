use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use crate::config::Config;
use crate::finding::{Finding, Severity, ScanResult};
use globset::GlobSet;
use crate::glob::{glob_matches, single_glob_matches};
use crate::rules::{
    self, INTERNAL_PATTERNS, SENSITIVE_FILE_PATTERNS,
    SOURCE_MAP_EXTENSIONS, SOURCE_MAP_URL_EXTENSIONS,
};

const MB: u64 = 1024 * 1024;
const HEAD_TAIL_BYTES: u64 = MB;           // 1 MB head + 1 MB tail for >50MB files
const SOURCEMAP_TAIL_BYTES: usize = 4096;  // only check tail for sourceMappingURL

pub fn check_file(
    result: &mut ScanResult,
    rel_path: &str,
    size: u64,
    full_path: Option<&Path>,
    cfg: &Config,
    debug_gs: &GlobSet,
    sensitive_gs: &GlobSet,
    internal_gs: &GlobSet,
    _allowlist_gs: &GlobSet,
) {
    // ── MAP-001: source map file by extension ──────────────────────────────
    let lower = rel_path.to_ascii_lowercase();
    if SOURCE_MAP_EXTENSIONS.iter().any(|ext| lower.ends_with(ext)) {
        result.push(
            Finding::new(
                "MAP-001",
                Severity::Critical,
                rel_path,
                "Source map file detected in package",
            )
            .with_detail(
                "Source maps expose original source code. This is the exact \
                 vulnerability class that leaked Claude Code's 512K-line codebase.",
            ),
        );
    }

    // ── MAP-002: sourceMappingURL reference in JS/CSS ──────────────────────
    let is_js_css = SOURCE_MAP_URL_EXTENSIONS.iter().any(|ext| lower.ends_with(ext));
    if is_js_css && size < 100 * MB {
        if let Some(path) = full_path {
            if let Ok(bytes) = read_tail(path, SOURCEMAP_TAIL_BYTES) {
                let re = rules::source_map_url_pattern();
                if let Some(cap) = re.captures(&bytes) {
                    let url = String::from_utf8_lossy(&cap[1]);
                    let sev = if url.starts_with("http") || url.starts_with("//") {
                        Severity::Critical
                    } else {
                        Severity::High
                    };
                    let url_short = &url[..url.len().min(200)];
                    result.push(
                        Finding::new(
                            "MAP-002",
                            sev,
                            rel_path,
                            "sourceMappingURL reference found",
                        )
                        .with_detail(format!("Points to: {url_short}")),
                    );
                }
            }
        }
    }

    // ── DBG-001: debug artifacts ───────────────────────────────────────────
    if glob_matches(debug_gs, rel_path) && !result.has_finding_for("MAP-001", rel_path) {
        result.push(Finding::new(
            "DBG-001",
            Severity::High,
            rel_path,
            "Debug artifact detected in package",
        ));
    }

    // ── SEC-001: sensitive files ───────────────────────────────────────────
    if glob_matches(sensitive_gs, rel_path) {
        let matched = SENSITIVE_FILE_PATTERNS
            .iter()
            .find(|&&p| single_glob_matches(p, rel_path))
            .copied()
            .unwrap_or("(pattern)");
        result.push(
            Finding::new(
                "SEC-001",
                Severity::Critical,
                rel_path,
                "Sensitive file detected in package",
            )
            .with_detail(format!("Matched pattern: {matched}")),
        );
    }

    // ── INT-001: internal/development artifacts ────────────────────────────
    if glob_matches(internal_gs, rel_path) {
        let matched = INTERNAL_PATTERNS
            .iter()
            .find(|&&p| single_glob_matches(p, rel_path))
            .copied()
            .unwrap_or("(pattern)");
        result.push(
            Finding::new(
                "INT-001",
                Severity::Medium,
                rel_path,
                "Internal/development artifact detected in package",
            )
            .with_detail(format!("Matched pattern: {matched}")),
        );
    }

    // ── SIZE-001 / SIZE-002: individual file size ──────────────────────────
    if size > cfg.size_limit_single_file_bytes {
        result.push(
            Finding::new(
                "SIZE-001",
                Severity::Critical,
                rel_path,
                format!("Anomalously large file: {:.1} MB", size as f64 / MB as f64),
            )
            .with_detail(format!(
                "Exceeds {:.0} MB threshold. \
                 The Claude Code source map that leaked was 59.8 MB.",
                cfg.size_limit_single_file_bytes as f64 / MB as f64
            )),
        );
    } else if size > crate::config::DEFAULT_SINGLE_FILE_WARN {
        result.push(Finding::new(
            "SIZE-002",
            Severity::Medium,
            rel_path,
            format!("Large file: {:.1} MB", size as f64 / MB as f64),
        ));
    }

    // ── SEC-002: secret patterns in file content ───────────────────────────
    // Rust's regex crate is DFA/NFA — linear time, ReDoS architecturally impossible.
    // No timeout needed (unlike Python v1's SEC-003 mechanism).
    if let Some(path) = full_path {
        if let Ok(content) = read_content_window(path, size) {
            // Built-in patterns
            for sp in rules::secret_patterns() {
                let re = sp.regex.get_or_init(|| {
                    rules::compile_pattern(sp.raw)
                        .unwrap_or_else(|e| panic!("bad builtin pattern {:?}: {e}", sp.raw))
                });
                if re.is_match(&content) {
                    result.push(
                        Finding::new(
                            "SEC-002",
                            Severity::Critical,
                            rel_path,
                            format!("Potential secret detected: {}", sp.description),
                        )
                        .with_detail("Value redacted."),
                    );
                }
            }

            // User-supplied extra_sensitive_patterns from config
            for raw in &cfg.extra_sensitive_patterns {
                if let Ok(re) = rules::compile_pattern(raw) {
                    if re.is_match(&content) {
                        result.push(
                            Finding::new(
                                "SEC-002",
                                Severity::Critical,
                                rel_path,
                                "Potential secret detected: custom pattern",
                            )
                            .with_detail(format!("Pattern: {raw} — Value redacted.")),
                        );
                    }
                }
            }
        }
    }
}

pub fn check_total_size(result: &mut ScanResult, total_bytes: u64, cfg: &Config) {
    if total_bytes > cfg.size_limit_total_bytes {
        result.push(Finding::new(
            "SIZE-003",
            Severity::High,
            "(total package)",
            format!(
                "Package size {:.1} MB exceeds threshold",
                total_bytes as f64 / MB as f64
            ),
        ));
    } else if total_bytes > crate::config::DEFAULT_TOTAL_WARN {
        result.push(Finding::new(
            "SIZE-004",
            Severity::Medium,
            "(total package)",
            format!("Package is large: {:.1} MB", total_bytes as f64 / MB as f64),
        ));
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn read_content_window(path: &Path, size: u64) -> std::io::Result<Vec<u8>> {
    if size <= 50 * MB {
        std::fs::read(path)
    } else {
        let mut f = std::fs::File::open(path)?;
        let mut head = vec![0u8; HEAD_TAIL_BYTES as usize];
        let n = f.read(&mut head)?;
        head.truncate(n);

        let tail_start = size.saturating_sub(HEAD_TAIL_BYTES);
        f.seek(SeekFrom::Start(tail_start))?;
        let mut tail = Vec::new();
        f.read_to_end(&mut tail)?;

        head.extend_from_slice(&tail);
        Ok(head)
    }
}

fn read_tail(path: &Path, n: usize) -> std::io::Result<Vec<u8>> {
    let mut f = std::fs::File::open(path)?;
    let size = f.metadata()?.len();
    let start = size.saturating_sub(n as u64);
    f.seek(SeekFrom::Start(start))?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf)?;
    Ok(buf)
}
