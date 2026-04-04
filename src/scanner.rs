use std::path::{Path, PathBuf};
use walkdir::WalkDir;

use crate::check::{check_file, check_total_size};
use crate::config::Config;
use crate::finding::{Finding, Severity, ScanResult};
use globset::GlobSet;
use crate::glob::{build_globset, build_globset_owned, glob_matches};
use crate::rules::{DEBUG_PATTERNS, INTERNAL_PATTERNS, SENSITIVE_FILE_PATTERNS};

pub struct Scanner {
    pub cfg: Config,
    debug_gs: GlobSet,
    sensitive_gs: GlobSet,
    internal_gs: GlobSet,
}

impl Scanner {
    pub fn new(cfg: Config) -> Self {
        let debug_gs = build_globset(DEBUG_PATTERNS);
        let sensitive_gs = build_globset(SENSITIVE_FILE_PATTERNS);
        let internal_gs = build_globset(INTERNAL_PATTERNS);
        Self { cfg, debug_gs, sensitive_gs, internal_gs }
    }

    fn allowlist_gs(&self) -> GlobSet {
        build_globset_owned(&self.cfg.allowlist)
    }

    fn is_allowlisted(&self, gs: &GlobSet, rel_path: &str) -> bool {
        glob_matches(gs, rel_path)
    }

    // ── Public scan entrypoints ──────────────────────────────────────────

    pub fn scan_directory(&self, path: &Path, package_type: &str) -> ScanResult {
        let mut result = ScanResult::new(package_type, path.display().to_string());
        let allowlist = self.allowlist_gs();

        let mut files: Vec<(String, u64, PathBuf)> = Vec::new();
        let mut total_size = 0u64;

        for entry in WalkDir::new(path)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            let rel = entry
                .path()
                .strip_prefix(path)
                .unwrap_or(entry.path())
                .to_string_lossy()
                .replace('\\', "/");
            let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
            total_size += size;
            files.push((rel, size, entry.path().to_path_buf()));
        }

        result.total_files = files.len();
        result.total_size_bytes = total_size;
        check_total_size(&mut result, total_size, &self.cfg);

        for (rel, size, full) in &files {
            if self.is_allowlisted(&allowlist, rel) {
                continue;
            }
            check_file(
                &mut result, rel, *size, Some(full),
                &self.cfg, &self.debug_gs, &self.sensitive_gs,
                &self.internal_gs, &allowlist,
            );
        }
        result
    }

    pub fn scan_tarball(&self, path: &Path, package_type: &str) -> ScanResult {
        let mut result = ScanResult::new(package_type, path.display().to_string());
        let allowlist = self.allowlist_gs();

        let dir = match tempfile::tempdir() {
            Ok(d) => d,
            Err(e) => {
                result.push(Finding::new("PKG-001", Severity::High,
                    path.display().to_string(),
                    format!("Failed to create temp dir: {e}")));
                return result;
            }
        };

        // First pass: collect metadata + extract
        let file = match std::fs::File::open(path) {
            Ok(f) => f,
            Err(e) => {
                result.push(Finding::new("PKG-001", Severity::High,
                    path.display().to_string(),
                    format!("Failed to open archive: {e}")));
                return result;
            }
        };

        let decoder = flate2::read::GzDecoder::new(file);
        let mut archive = tar::Archive::new(decoder);
        let mut file_infos: Vec<(String, u64, PathBuf)> = Vec::new();
        let mut total_size = 0u64;

        let entries = match archive.entries() {
            Ok(e) => e,
            Err(e) => {
                result.push(Finding::new("PKG-001", Severity::High,
                    path.display().to_string(),
                    format!("Failed to read tarball: {e}")));
                return result;
            }
        };

        for mut entry in entries.flatten() {
            if !entry.header().entry_type().is_file() { continue; }
            let entry_path = match entry.path() { Ok(p) => p.to_path_buf(), Err(_) => continue };
            let size = entry.header().size().unwrap_or(0);

            // Strip leading package/ or package-version/ prefix (npm tarball convention)
            let raw = entry_path.to_string_lossy().replace('\\', "/");
            let rel = match raw.find('/') {
                Some(i) => raw[i + 1..].to_string(),
                None => raw.to_string(),
            };

            // Path traversal protection
            let dest = dir.path().join(&rel);
            if !dest.starts_with(dir.path()) {
                result.push(
                    Finding::new("PKG-001", Severity::Critical, &rel, "Tar path traversal detected")
                        .with_detail(format!("Entry attempts escape: {rel}")),
                );
                continue;
            }

            if let Some(parent) = dest.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let _ = entry.unpack(&dest);

            total_size += size;
            file_infos.push((rel, size, dest));
        }

        result.total_files = file_infos.len();
        result.total_size_bytes = total_size;
        check_total_size(&mut result, total_size, &self.cfg);

        for (rel, size, full) in &file_infos {
            if self.is_allowlisted(&allowlist, rel) { continue; }
            let full_opt = if full.exists() { Some(full.as_path()) } else { None };
            check_file(
                &mut result, rel, *size, full_opt,
                &self.cfg, &self.debug_gs, &self.sensitive_gs,
                &self.internal_gs, &allowlist,
            );
        }
        result
    }

    pub fn scan_zip(&self, path: &Path, package_type: &str) -> ScanResult {
        let mut result = ScanResult::new(package_type, path.display().to_string());
        let allowlist = self.allowlist_gs();

        let file = match std::fs::File::open(path) {
            Ok(f) => f,
            Err(e) => {
                result.push(Finding::new("PKG-002", Severity::High,
                    path.display().to_string(), format!("Failed to open zip: {e}")));
                return result;
            }
        };

        let mut archive = match zip::ZipArchive::new(file) {
            Ok(a) => a,
            Err(e) => {
                result.push(Finding::new("PKG-002", Severity::High,
                    path.display().to_string(), format!("Failed to read zip: {e}")));
                return result;
            }
        };

        let dir = match tempfile::tempdir() {
            Ok(d) => d,
            Err(e) => {
                result.push(Finding::new("PKG-002", Severity::High,
                    path.display().to_string(), format!("Failed to create temp dir: {e}")));
                return result;
            }
        };

        let mut total_size = 0u64;
        let mut file_infos: Vec<(String, u64, PathBuf)> = Vec::new();

        for i in 0..archive.len() {
            let mut zf = match archive.by_index(i) { Ok(f) => f, Err(_) => continue };
            if zf.is_dir() { continue; }

            let rel = zf.name().replace('\\', "/");
            let size = zf.size();

            // Path traversal check
            let dest = dir.path().join(&rel);
            if !dest.starts_with(dir.path()) {
                result.push(
                    Finding::new("PKG-003", Severity::Critical, &rel, "Zip path traversal detected")
                        .with_detail(format!("Entry attempts escape: {rel}")),
                );
                continue;
            }

            if let Some(parent) = dest.parent() { let _ = std::fs::create_dir_all(parent); }
            if let Ok(mut out) = std::fs::File::create(&dest) {
                let _ = std::io::copy(&mut zf, &mut out);
            }

            total_size += size;
            file_infos.push((rel, size, dest));
        }

        result.total_files = file_infos.len();
        result.total_size_bytes = total_size;
        check_total_size(&mut result, total_size, &self.cfg);

        for (rel, size, full) in &file_infos {
            if self.is_allowlisted(&allowlist, rel) { continue; }
            let full_opt = if full.exists() { Some(full.as_path()) } else { None };
            check_file(
                &mut result, rel, *size, full_opt,
                &self.cfg, &self.debug_gs, &self.sensitive_gs,
                &self.internal_gs, &allowlist,
            );
        }
        result
    }

    pub fn scan_npm_dry_run(&self, project_dir: &Path) -> ScanResult {
        let mut result = ScanResult::new("npm", project_dir.display().to_string());

        let output = std::process::Command::new("npm")
            .args(["pack", "--dry-run", "--json"])
            .current_dir(project_dir)
            .output();

        let files: Vec<String> = match output {
            Err(_) => {
                result.push(Finding::new("NPM-001", Severity::Info, "",
                    "npm not found — falling back to directory scan"));
                return self.scan_directory(project_dir, "npm");
            }
            Ok(out) => {
                if out.status.success() {
                    parse_npm_dry_run_json(&String::from_utf8_lossy(&out.stdout))
                } else {
                    parse_npm_dry_run_text(
                        &String::from_utf8_lossy(&out.stdout),
                        &String::from_utf8_lossy(&out.stderr),
                    )
                }
            }
        };

        let allowlist = self.allowlist_gs();
        let mut total_size = 0u64;

        for rel in &files {
            if self.is_allowlisted(&allowlist, rel) { continue; }
            let full = project_dir.join(rel);
            let size = full.metadata().map(|m| m.len()).unwrap_or(0);
            total_size += size;
            let full_opt = if full.exists() { Some(full.as_path()) } else { None };
            check_file(
                &mut result, rel, size, full_opt,
                &self.cfg, &self.debug_gs, &self.sensitive_gs,
                &self.internal_gs, &allowlist,
            );
        }
        result.total_files = files.len();
        result.total_size_bytes = total_size;
        check_total_size(&mut result, total_size, &self.cfg);
        result
    }
}

// ─── npm dry-run parsers ──────────────────────────────────────────────────────

fn parse_npm_dry_run_json(output: &str) -> Vec<String> {
    if let Ok(val) = serde_json::from_str::<serde_json::Value>(output) {
        if let Some(arr) = val.as_array().and_then(|a| a.first()) {
            if let Some(files) = arr.get("files").and_then(|f| f.as_array()) {
                return files
                    .iter()
                    .filter_map(|f| f.get("path")?.as_str().map(str::to_owned))
                    .collect();
            }
        }
    }
    Vec::new()
}

fn parse_npm_dry_run_text(stdout: &str, stderr: &str) -> Vec<String> {
    let combined = format!("{stdout}{stderr}");
    let mut files = Vec::new();
    for line in combined.lines() {
        let trimmed = line.trim();
        if trimmed.contains("npm notice") {
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if parts.len() >= 4 {
                let candidate = parts[parts.len() - 1];
                if candidate.contains('/') || candidate.contains('.') {
                    files.push(candidate.to_owned());
                }
            }
        } else if !trimmed.is_empty() {
            files.push(trimmed.to_owned());
        }
    }
    files
}

/// Detect package type from path (mirrors Python detect_package_type).
pub fn detect_package_type(path: &Path) -> &'static str {
    if path.is_dir() {
        if path.join("package.json").exists() { return "npm"; }
        if path.join("pyproject.toml").exists() || path.join("setup.py").exists() { return "pip"; }
        if path.join("Cargo.toml").exists() { return "cargo"; }
        return "generic";
    }
    let name = path.file_name().unwrap_or_default().to_string_lossy().to_lowercase();
    if name.ends_with(".tgz") || name.ends_with(".tar.gz") { return "npm"; }
    if name.ends_with(".whl") { return "pip"; }
    if name.ends_with(".crate") { return "cargo"; }
    "generic"
}
