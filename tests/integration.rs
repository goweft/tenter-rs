#![allow(unused_variables)]
/// Integration tests — scenario parity with Python v1's test_tenter.py.
/// Runs the compiled binary against temp directories and archives,
/// verifying rule IDs and severities match exactly.
use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn binary() -> PathBuf {
    let mut p = std::env::current_exe().unwrap();
    p.pop(); // deps/
    p.pop(); // debug/ or release/
    p.push("tenter");
    // On Windows
    if cfg!(windows) { p.set_extension("exe"); }
    p
}

fn run(args: &[&str]) -> (i32, String) {
    let out = Command::new(binary())
        .args(args)
        .output()
        .expect("failed to run tenter binary");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out.status.code().unwrap_or(-1), combined)
}

fn make_dir(files: &[(&str, &[u8])]) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    for (rel, content) in files {
        let path = dir.path().join(rel);
        if let Some(p) = path.parent() { fs::create_dir_all(p).unwrap(); }
        fs::write(&path, content).unwrap();
    }
    dir
}

// ─── MAP-001 ─────────────────────────────────────────────────────────────────

#[test]
fn test_detects_map_file() {
    let dir = make_dir(&[
        ("dist/index.js", b"console.log('hello');"),
        ("dist/index.js.map", br#"{"version":3,"sources":["../src/index.ts"]}"#),
    ]);
    let (code, out) = run(&["scan", dir.path().to_str().unwrap(), "--format", "json", "--no-color"]);
    assert_eq!(code, 2);
    assert!(out.contains("MAP-001"), "expected MAP-001 in: {out}");
}

#[test]
fn test_detects_sourcemapping_url_external() {
    let dir = make_dir(&[(
        "dist/bundle.js",
        b"console.log('hello');\n//# sourceMappingURL=https://r2.example.com/src.zip",
    )]);
    let (code, out) = run(&["scan", dir.path().to_str().unwrap(), "--format", "json", "--no-color"]);
    assert!(out.contains("MAP-002"), "expected MAP-002 in: {out}");
    assert!(out.contains("CRITICAL"), "expected CRITICAL severity: {out}");
}

#[test]
fn test_detects_sourcemapping_url_local() {
    let dir = make_dir(&[(
        "dist/bundle.js",
        b"console.log('hello');\n//# sourceMappingURL=index.js.map",
    )]);
    let (_code, out) = run(&["scan", dir.path().to_str().unwrap(), "--format", "json", "--no-color"]);
    assert!(out.contains("MAP-002"), "expected MAP-002 in: {out}");
    assert!(out.contains("HIGH"), "expected HIGH severity: {out}");
}

#[test]
fn test_clean_js_no_map_findings() {
    let dir = make_dir(&[
        ("dist/index.js", b"console.log('hello');"),
        ("package.json", br#"{"name":"test","version":"1.0.0"}"#),
    ]);
    let (code, _out) = run(&["scan", dir.path().to_str().unwrap(), "--format", "json", "--no-color"]);
    assert_eq!(code, 0);
}

// ─── SEC-001 / SEC-002 ───────────────────────────────────────────────────────

#[test]
fn test_detects_env_file() {
    let dir = make_dir(&[(".env", b"DATABASE_URL=postgres://user:pass@localhost/db")]);
    let (_code, out) = run(&["scan", dir.path().to_str().unwrap(), "--format", "json", "--no-color"]);
    assert!(out.contains("SEC-001"), "expected SEC-001 in: {out}");
}

#[test]
fn test_detects_aws_key() {
    let dir = make_dir(&[("config.js", b"const key = \"AKIAIOSFODNN7EXAMPLE\";")]);
    let (_code, out) = run(&["scan", dir.path().to_str().unwrap(), "--format", "json", "--no-color"]);
    assert!(out.contains("SEC-002"), "expected SEC-002 in: {out}");
    assert!(out.contains("AWS Access Key"), "expected AWS label: {out}");
}

#[test]
fn test_detects_github_token() {
    let dir = make_dir(&[(
        "deploy.sh",
        b"export GITHUB_TOKEN=\"ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij\"",
    )]);
    let (_code, out) = run(&["scan", dir.path().to_str().unwrap(), "--format", "json", "--no-color"]);
    assert!(out.contains("SEC-002"), "expected SEC-002 in: {out}");
}

#[test]
fn test_detects_private_key() {
    let dir = make_dir(&[(
        "certs/server.key",
        b"-----BEGIN RSA PRIVATE KEY-----\nfakekey\n-----END RSA PRIVATE KEY-----",
    )]);
    let (_code, out) = run(&["scan", dir.path().to_str().unwrap(), "--format", "json", "--no-color"]);
    assert!(out.contains("SEC-002"), "expected SEC-002 in: {out}");
}

// ─── DBG-001 ─────────────────────────────────────────────────────────────────

#[test]
fn test_detects_pdb() {
    let dir = make_dir(&[("bin/app.pdb", &[0u8; 100])]);
    let (_code, out) = run(&["scan", dir.path().to_str().unwrap(), "--format", "json", "--no-color"]);
    assert!(out.contains("DBG-001"), "expected DBG-001 in: {out}");
}

#[test]
fn test_detects_src_zip() {
    let dir = make_dir(&[("dist/src.zip", b"PK\x03\x04fake")]);
    let (_code, out) = run(&["scan", dir.path().to_str().unwrap(), "--format", "json", "--no-color"]);
    assert!(out.contains("DBG-001"), "expected DBG-001 in: {out}");
}

// ─── INT-001 ─────────────────────────────────────────────────────────────────

#[test]
fn test_detects_claude_config() {
    let dir = make_dir(&[(".claude/config.json", br#"{"model":"opus"}"#)]);
    let (_code, out) = run(&["scan", dir.path().to_str().unwrap(), "--format", "json", "--no-color"]);
    assert!(out.contains("INT-001"), "expected INT-001 in: {out}");
}

#[test]
fn test_detects_claude_md() {
    let dir = make_dir(&[("CLAUDE.md", b"# Internal instructions")]);
    let (_code, out) = run(&["scan", dir.path().to_str().unwrap(), "--format", "json", "--no-color"]);
    assert!(out.contains("INT-001"), "expected INT-001 in: {out}");
}

#[test]
fn test_detects_coverage_dir() {
    let dir = make_dir(&[("coverage/lcov.info", b"TN:\nSF:src/index.ts")]);
    let (_code, out) = run(&["scan", dir.path().to_str().unwrap(), "--format", "json", "--no-color"]);
    assert!(out.contains("INT-001"), "expected INT-001 in: {out}");
}

// ─── SIZE-001 ────────────────────────────────────────────────────────────────

#[test]
fn test_detects_large_file() {
    let dir = make_dir(&[("dist/huge.js.map", vec![b'x'; 51 * 1024 * 1024].as_slice())]);
    let (_code, out) = run(&["scan", dir.path().to_str().unwrap(), "--format", "json", "--no-color"]);
    assert!(out.contains("SIZE-001"), "expected SIZE-001 in: {out}");
    assert!(out.contains("CRITICAL"), "expected CRITICAL: {out}");
}

// ─── Allowlist ───────────────────────────────────────────────────────────────

#[test]
fn test_allowlist_skips_file() {
    let dir = make_dir(&[("dist/index.js.map", br#"{"version":3}"#)]);
    // Write a config
    let cfg = r#"{"allowlist":["*.map"]}"#;
    fs::write(dir.path().join(".tenter.json"), cfg).unwrap();
    let (code, _out) = run(&[
        "scan", dir.path().to_str().unwrap(),
        "--config", dir.path().join(".tenter.json").to_str().unwrap(),
        "--format", "json", "--no-color",
    ]);
    assert_eq!(code, 0);
}

// ─── Output formats ──────────────────────────────────────────────────────────

#[test]
fn test_json_output_schema() {
    let dir = make_dir(&[("dist/index.js.map", br#"{"version":3}"#)]);
    let (_code, out) = run(&["scan", dir.path().to_str().unwrap(), "--format", "json", "--no-color"]);
    let v: serde_json::Value = serde_json::from_str(&out).expect("valid JSON");
    assert!(v["findings"].is_array());
    assert!(v["findings_count"].is_number());
    assert!(v["version"].is_string());
}

#[test]
fn test_sarif_output_schema() {
    let dir = make_dir(&[("dist/index.js.map", br#"{"version":3}"#)]);
    let (_code, out) = run(&["scan", dir.path().to_str().unwrap(), "--format", "sarif", "--no-color"]);
    let v: serde_json::Value = serde_json::from_str(&out).expect("valid JSON");
    assert_eq!(v["version"].as_str().unwrap(), "2.1.0");
    assert!(v["runs"][0]["results"].is_array());
}

#[test]
fn test_human_clean_output() {
    let dir = make_dir(&[("index.js", b"console.log('clean');")]);
    let (code, out) = run(&["scan", dir.path().to_str().unwrap(), "--no-color"]);
    assert_eq!(code, 0);
    assert!(out.contains("No issues found"), "expected clean message: {out}");
}

// ─── fail-on threshold ───────────────────────────────────────────────────────

#[test]
fn test_fail_on_threshold() {
    let dir = make_dir(&[("coverage/lcov.info", b"TN:")]);  // INT-001 = MEDIUM

    // Default --fail-on=high: MEDIUM should not fail
    let (code, _) = run(&["scan", dir.path().to_str().unwrap(), "--format", "json", "--no-color"]);
    assert_eq!(code, 0);

    // --fail-on=medium: should fail
    let (code, _) = run(&[
        "scan", dir.path().to_str().unwrap(),
        "--format", "json", "--no-color", "--fail-on", "medium",
    ]);
    assert_eq!(code, 2);
}
