<p align="center"><img src="https://raw.githubusercontent.com/goweft/tenter/main/banner.svg" alt="tenter" width="100%"></p>

# tenter-rs

**tenter v2** — Pre-publish artifact integrity scanner. Memory-safe static binary. No Python required.

Identical scanning behaviour to [tenter v1](https://github.com/goweft/tenter) but compiled to a single static binary for use in GitHub Actions without `setup-python`.

## Why a Rust port?

| | v1 (Python) | v2 (Rust) |
|---|---|---|
| Runtime | Python 3.9+ required | None — static binary |
| GitHub Action setup | `setup-python` + 10-15s | Binary download, ~1s |
| ReDoS protection | Per-file timeout (SEC-003) | Architecturally impossible (DFA/NFA regex) |
| Binary size | N/A | ~3MB stripped musl |
| Platforms | Any Python platform | linux x86_64/arm64, macOS x86_64/arm64, Windows x86_64 |

## Installation

```bash
# Homebrew (coming soon)
brew install goweft/tap/tenter

# Direct download (linux x86_64)
curl -fsSL https://github.com/goweft/tenter-rs/releases/latest/download/tenter-linux-x86_64 \
  -o /usr/local/bin/tenter && chmod +x /usr/local/bin/tenter

# From source
cargo install --git https://github.com/goweft/tenter-rs
```

## Usage

```bash
# Scan a directory before publish
tenter scan ./dist

# Scan an npm tarball
tenter scan my-package-1.0.0.tgz

# Scan a Python wheel
tenter scan my_package-0.1.0-py3-none-any.whl

# npm pack --dry-run integration
tenter npm-check .

# JSON output for CI
tenter scan ./dist --format json

# SARIF output for GitHub code scanning
tenter scan ./dist --format sarif > results.sarif

# Create default .tenter.json config
tenter init
```

## GitHub Actions

```yaml
- name: Scan package before publish
  uses: goweft/tenter-rs@v2
  with:
    target: ./dist
    format: sarif
    fail-on: high
```

No `setup-python` step needed. The action downloads the correct platform binary and caches it.

## What It Catches

| Rule ID | Severity | What |
|---------|----------|------|
| **MAP-001** | CRITICAL | Source map files (`.map`, `.js.map`, `.css.map`, etc.) |
| **MAP-002** | CRITICAL/HIGH | `sourceMappingURL` references in JS/CSS |
| **DBG-001** | HIGH | Debug symbols (`.pdb`, `.dSYM`, `.debug`, `src.zip`) |
| **SEC-001** | CRITICAL | Sensitive files (`.env`, `.npmrc`, `.pypirc`, private keys) |
| **SEC-002** | CRITICAL | Embedded secrets (AWS keys, GitHub tokens, API keys, private keys) |
| **INT-001** | MEDIUM | Internal artifacts (`.claude/`, `CLAUDE.md`, `.cursor/`, `coverage/`) |
| **SIZE-001** | CRITICAL | Files > 50 MB |
| **SIZE-002** | MEDIUM | Files > 10 MB |
| **SIZE-003** | HIGH | Total package > 200 MB |
| **SIZE-004** | MEDIUM | Total package > 50 MB |

## Configuration

`.tenter.json` from tenter v1 works unchanged:

```json
{
  "allowlist": ["dist/*.map"],
  "size_limit_single_file_bytes": 52428800,
  "size_limit_total_bytes": 209715200,
  "extra_sensitive_patterns": [],
  "extra_debug_patterns": []
}
```

> `content_scan_timeout_secs` is accepted but ignored in v2 — the Rust regex engine is DFA/NFA and cannot hang regardless of input.

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No findings at or above `--fail-on` threshold |
| 2 | Findings detected — do not publish |

## Zero Runtime Dependencies

The release binary is statically linked against musl libc on Linux. No glibc, no Python, no shared libraries. Drop it anywhere and it works.

## Also by goweft

- **[tenter](https://github.com/goweft/tenter)** — Python v1 (zero pip dependencies)
- **[heddle](https://github.com/goweft/heddle)** — Policy-and-trust layer for MCP tool servers
- **[unshear](https://github.com/goweft/unshear)** — AI agent fork divergence detector

## License

MIT
