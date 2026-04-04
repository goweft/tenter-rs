# tenter-rs — Project Context

## What This Is

tenter-rs is **tenter v2** — a Rust port of [tenter v1](https://github.com/goweft/tenter).
Pre-publish artifact integrity scanner compiled to a single static binary.
No Python runtime required.

**Repo:** github.com/goweft/tenter-rs
**Author:** goweft (goweft@proton.me)
**License:** MIT
**Status:** v2.0.0 shipped, 5-platform release binaries live on GitHub Releases

## Relationship to v1

- Identical scanning behaviour, same rule IDs, same `.tenter.json` schema, same CLI surface
- v1 lives at github.com/goweft/tenter (Python, zero pip deps)
- v2 replaces the `setup-python` GitHub Action step with a binary download (~1s vs 10-15s)
- SEC-003 timeout rule from v1 is NOT implemented — Rust regex crate is DFA/NFA,
  ReDoS is architecturally impossible

## Architecture

```
src/
├── main.rs        # CLI entry, clap derive, exit codes
├── finding.rs     # Severity, Finding, ScanResult
├── config.rs      # .tenter.json loading
├── rules.rs       # All static patterns (glob + regex, OnceLock compiled)
├── glob.rs        # Glob matching via globset, basename fallback
├── check.rs       # check_file() + check_total_size() — all rule evaluation
├── scanner.rs     # Scanner: scan_directory, scan_tarball, scan_zip, scan_npm_dry_run
└── output/
    ├── human.rs   # ANSI terminal output (matches v1 format_human exactly)
    ├── json.rs    # JSON output (matches v1 schema exactly)
    └── sarif.rs   # SARIF 2.1.0 output
tests/
└── integration.rs # 19 binary-level integration tests
```

## Key Crates

| Crate | Purpose |
|---|---|
| `regex` (unicode-case + unicode-perl) | Secret pattern matching, DFA/NFA, linear time |
| `globset` | Glob matching with ** semantics |
| `tar` + `flate2` (rust_backend) | .tgz / .crate reading, zero C deps |
| `zip` | .whl / .zip reading |
| `serde` + `serde_json` | Config parsing + JSON/SARIF output |
| `clap` (derive) | CLI argument parsing |
| `walkdir` | Recursive directory traversal |
| `is-terminal` | TTY detection for auto-color |
| `tempfile` | Temp dirs for archive extraction |

## Release Targets

- `x86_64-unknown-linux-musl` — fully static, zero glibc dependency
- `aarch64-unknown-linux-musl` — ARM64 static
- `x86_64-apple-darwin`
- `aarch64-apple-darwin`
- `x86_64-pc-windows-msvc`

## CI Pipeline

- `ci.yml` — build + test matrix across all 5 targets, self-scan step
- `release.yml` — triggered on `v*` tags, cross-compiles via `cross`, uploads to GitHub Releases
- Static check uses `file(1)` not `ldd` (ldd unreliable for cross-compiled aarch64 on x86_64 host)

## Development

```bash
# Build
cargo build

# Run tests
cargo test

# Run against a real target
cargo run -- scan /path/to/target --no-color

# Release build
cargo build --release
```

Git config for this repo uses `goweft <goweft@proton.me>` — set per-repo, not global.

## Design Rules

- No unsafe code in our crate
- No tokio/async — single-threaded sync is correct here
- No new crates without strong justification
- All rule IDs must match v1 exactly for config/tooling compatibility
- Integration tests are binary-level (spawn the compiled binary, check stdout/exit code)
