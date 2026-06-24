<p align="center"><img src="banner.svg" alt="tenter" width="100%"></p>

<p align="center">
  <a href="https://github.com/goweft/tenter-rs/actions/workflows/ci.yml"><img src="https://github.com/goweft/tenter-rs/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/goweft/tenter-rs/releases/latest"><img src="https://img.shields.io/github/v/release/goweft/tenter-rs?sort=semver" alt="Latest release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/goweft/tenter-rs" alt="License: MIT"></a>
  <img src="https://img.shields.io/badge/runtime-zero%20deps-success" alt="Zero runtime dependencies">
  <img src="https://img.shields.io/badge/binary-static%20%C2%B7%201.2–1.9%20MB-blue" alt="Static binary">
</p>

# tenter-rs

**Scan the exact bytes you're about to publish — npm tarball, Python wheel, `.crate`, or `npm pack` output — and block the release if it contains a source map, leaked secret, debug artifact, internal/AI-tool cruft, or a size anomaly.** One static binary, no runtime, runs in milliseconds.

tenter-rs is the **pre-publish gate that your secret scanner doesn't cover.** TruffleHog and gitleaks read your git history; tenter-rs reads the package that's about to go out the door — and also catches the things secret scanners ignore entirely: source maps that leak your original source, `.pdb`/`.dSYM` debug symbols, and the `.claude/` / `.cursor/` / `CLAUDE.md` cruft that AI coding tools leave behind.

> tenter-rs exists for the bug class behind the Claude Code npm source-map leak (2026-03-31): a stray `.map` file that ships your original source into a public package — it catches exactly that, before publish.

<p align="center"><img src="docs/demo.gif" alt="tenter-rs scanning a package and blocking the publish" width="100%"></p>

> The GIF above is generated from [`docs/demo.tape`](docs/demo.tape) — see [Recording the demo](#recording-the-demo).

---

## Quickstart (5 minutes)

```bash
# 1. Install the binary (Linux x86_64 — other platforms below).
#    Prepend sudo if /usr/local/bin isn't writable for your user.
curl -fsSL https://github.com/goweft/tenter-rs/releases/latest/download/tenter-linux-x86_64 \
  -o /usr/local/bin/tenter && chmod +x /usr/local/bin/tenter

# 2. Build a sample "dist" that has problems in it.
mkdir -p demo/dist && cd demo
printf '"use strict";\nconsole.log("hi");\n//# sourceMappingURL=app.js.map\n'                 > dist/app.js
printf '{"version":3,"sources":["../src/app.ts"],"sourcesContent":["secret source"]}\n'        > dist/app.js.map
printf 'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n' > dist/.env
printf 'export const version = "1.0.0";\n' > dist/index.js   # a clean file, so it's not all red

# 3. Scan what you're about to publish.
tenter scan dist
```

```text
═══ tenter scan results ═══
  Package type: generic
  Path: dist
  Files: 4
  Size: 0.3 KB (0.00 MB)

  ┌─ CRITICAL (4)
  │ ✖ [MAP-001] app.js.map
  │   Source map file detected in package
  │   Source maps expose original source code. This is the exact vulnerability class that leaked Claude Code's 512K-line codebase.
  │ ✖ [SEC-001] .env
  │   Sensitive file detected in package
  │   Matched pattern: .env
  │ ✖ [SEC-002] .env
  │   Potential secret detected: AWS Access Key ID
  │   Value redacted.
  │ ✖ [SEC-002] .env
  │   Potential secret detected: AWS Secret Key
  │   Value redacted.
  └────────────────────────────────────────────────────────────

  ┌─ HIGH (1)
  │ ✖ [MAP-002] app.js
  │   sourceMappingURL reference found
  │   Points to: app.js.map
  └────────────────────────────────────────────────────────────

  ✖ BLOCKED: 5 finding(s) — 4 critical, 1 high. DO NOT PUBLISH.
```

Exit code is **2** — drop `tenter scan` into your release script or `prepublishOnly` and a leak stops the publish. (Findings are grouped by severity; file order may vary by filesystem. The exact sample above is also reproducible with [`docs/seed-sample.sh`](docs/seed-sample.sh).)

Real npm/PyPI artifacts work the same way:

```bash
tenter scan my-package-1.0.0.tgz          # npm tarball
tenter scan my_package-0.1.0-py3-none-any.whl   # Python wheel
tenter npm-check .                        # runs `npm pack --dry-run` and scans the file list
```

---

## What it catches

| Rule ID | Severity | What |
|---------|----------|------|
| **MAP-001** | CRITICAL | Source map files (`.map`, `.js.map`, `.css.map`, `.ts.map`, …) |
| **MAP-002** | CRITICAL/HIGH | `sourceMappingURL` references in JS/CSS (CRITICAL if it points off-host) |
| **DBG-001** | HIGH | Debug symbols (`.pdb`, `.dSYM`, `.dwarf`, `.debug`, `src.zip`, …) |
| **SEC-001** | CRITICAL | Sensitive files (`.env`, `.npmrc`, `.pypirc`, private keys, `kubeconfig`, …) |
| **SEC-002** | CRITICAL | Embedded secrets — AWS, GitHub (PAT/OAuth/fine-grained), OpenAI, Anthropic, Slack, npm, PyPI tokens, private keys, bearer tokens, hardcoded passwords/API keys, plus your own regexes |
| **INT-001** | MEDIUM | Internal/AI-tool artifacts (`.claude/`, `CLAUDE.md`, `.cursor/`, `.idea/`, `coverage/`, `__pycache__/`, …) |
| **SIZE-001** | CRITICAL | Any single file > 50 MB |
| **SIZE-002** | MEDIUM | Any single file > 10 MB |
| **SIZE-003** | HIGH | Total package > 200 MB |
| **SIZE-004** | MEDIUM | Total package > 50 MB |

Thresholds and patterns are tunable via [`.tenter.json`](#configuration). Rule IDs are identical to [tenter v1](https://github.com/goweft/tenter), so existing configs and tooling work unchanged.

---

## How it compares

tenter-rs is **not** a general-purpose secret scanner, and this table is honest about that. The dedicated scanners detect far more secret types and verify them live; tenter-rs covers a different, complementary job — the integrity of the packaged artifact.

| | **tenter-rs** | TruffleHog | GitGuardian (ggshield) | gitleaks |
|---|---|---|---|---|
| **Runtime deps** | None — static binary, offline, no account | None to install (Go binary); live verify needs network | **Python + GitGuardian account/API key**; detection runs in their cloud | None (Go binary); `git` for history mode |
| **Binary / download size** | **~1.2–1.9 MB** static *(measured)* | ~27–68 MB compressed | tens of MB (Python); no static binary | ~8.2 MB compressed / ~21 MB binary |
| **Scan model** | Local regex on the **packaged artifact** / `npm pack` list; no network, no history walk | Local across git history + many sources; optional network verify | **Network round-trip per scan** (API quota) | Local regex over git history / dirs |
| **Secret detection** *(they win)* | Curated **14** built-in patterns + your regexes; no live verify | **800+** types + **live verification** | **500+** + validity checks | **222** rules; no live verify |
| **Source maps / debug / AI-tool cruft / size anomalies** | **Yes — first-class** | No | No | No |
| **Pre-publish artifact focus** | **Yes** — scans `.tgz` / `.whl` / `.crate` / `npm pack` output | No (history / filesystem) | Partial (`scan pypi` of an *already-published* package, secrets only) | No (history / dir / stdin) |
| **License** | **MIT** | AGPL-3.0 (network copyleft) | CLI MIT; engine proprietary SaaS | MIT (project feature-frozen) |

**The honest takeaway:** run TruffleHog or gitleaks across your source and history for broad, verified secret detection. Run tenter-rs on **what's actually about to ship**. They answer different questions and work well together — tenter-rs is the last gate before `npm publish` / `twine upload` / `cargo publish`, not a replacement for a full secret scanner.

<sub>Competitor facts gathered 2026-06 from official repos/docs (TruffleHog v3.95.6, gitleaks v8.30.1, current ggshield). Sizes are compressed download sizes where the tool ships a binary. tenter-rs sizes/speed are measured locally; no benchmark numbers are invented, and none of the tools publish a normal-mode throughput figure.</sub>

---

## Who should use this

- You publish **npm / PyPI / crates** and want a fast, dependency-free gate on exactly what ships.
- You run **CI** and want SARIF in GitHub code scanning **without** a `setup-python` step.
- You use **AI coding tools** (Claude Code, Cursor, Copilot) and want their cruft — `.claude/`, `CLAUDE.md`, `.cursor/`, stray source maps and debug stubs — to never land in a release.
- You need an **offline / air-gapped** scanner with no account, no API key, and no outbound network calls.

## When NOT to use this

- You need broad, **verified** secret detection across your **whole git history** → use TruffleHog or gitleaks (and keep tenter-rs for the pre-publish step).
- You want a **managed dashboard**, incident workflows, or org-wide monitoring → GitGuardian.
- The secret you're worried about is already in **old commits you pushed** → tenter-rs only sees the packaged artifact, not history.
- You need detection of secret *types* beyond the built-in 14 — though you can add your own with `extra_sensitive_patterns` in `.tenter.json`.

---

## Use it in CI (GitHub Action)

The action downloads the right platform binary (no `setup-python`), scans your target, and uploads SARIF to GitHub code scanning. Pin to the moving major tag `@v2` for patches, or to an exact tag for full reproducibility.

```yaml
name: pre-publish-scan
on: [pull_request]

permissions:
  contents: read
  security-events: write   # required for the SARIF upload

jobs:
  tenter:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Scan the package before publish
        uses: goweft/tenter-rs@v2          # or pin: goweft/tenter-rs@v2.1.0
        with:
          target: ./dist                   # directory, .tgz, .whl, or .crate
          format: sarif                     # human | json | sarif  (default: sarif)
          fail-on: high                     # critical | high | medium | low | info
```

The step exits non-zero when findings reach `fail-on`, failing the job; the SARIF still uploads (`if: always()`) so findings show up in the **Security → Code scanning** tab.

---

## Pre-commit hook

Adopt tenter-rs through the [pre-commit](https://pre-commit.com) framework. The hook downloads the matching static binary on first run — **no Rust toolchain required.** Add to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/goweft/tenter-rs
    rev: v2.1.0
    hooks:
      # Scans exactly what `npm pack` would publish — no node_modules noise.
      - id: tenter
      # For non-npm projects, scan a build dir instead (override the path):
      # - id: tenter-scan
      #   args: [scan, ./build, --no-color, --fail-on, critical]
```

Then `pre-commit install`. The default fails the commit only on **critical** findings — secrets, source maps, sensitive files — a deliberately stricter gate than the Action's `high`, so lower-severity noise doesn't block local commits; tune with `args` or your `.tenter.json`. For the authoritative pre-publish gate, use the GitHub Action above.

---

## Install (all platforms)

```bash
# Linux x86_64
curl -fsSL https://github.com/goweft/tenter-rs/releases/latest/download/tenter-linux-x86_64 \
  -o /usr/local/bin/tenter && chmod +x /usr/local/bin/tenter

# Linux arm64
curl -fsSL https://github.com/goweft/tenter-rs/releases/latest/download/tenter-linux-aarch64 \
  -o /usr/local/bin/tenter && chmod +x /usr/local/bin/tenter

# macOS Apple Silicon
curl -fsSL https://github.com/goweft/tenter-rs/releases/latest/download/tenter-darwin-aarch64 \
  -o /usr/local/bin/tenter && chmod +x /usr/local/bin/tenter

# macOS Intel
curl -fsSL https://github.com/goweft/tenter-rs/releases/latest/download/tenter-darwin-x86_64 \
  -o /usr/local/bin/tenter && chmod +x /usr/local/bin/tenter

# Windows x86_64: download tenter-windows-x86_64.exe from the latest release.

# From source (needs a Rust toolchain)
cargo install --git https://github.com/goweft/tenter-rs
```

---

## Usage

```bash
tenter scan ./dist                 # scan a directory
tenter scan pkg-1.0.0.tgz          # scan an npm tarball
tenter scan pkg-0.1.0-py3-none-any.whl   # scan a Python wheel
tenter npm-check .                 # npm pack --dry-run, then scan the file list
tenter scan ./dist --format json   # JSON for CI
tenter scan ./dist --format sarif > results.sarif   # SARIF for code scanning
tenter scan ./dist --fail-on critical   # only fail on CRITICAL
tenter init                        # write a default .tenter.json
```

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

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | No findings at or above `--fail-on` |
| 2 | Findings detected — do not publish |
| 1 | Error (bad config, unreadable archive, …) |

---

## Why a Rust port? (v1 → v2)

[tenter v1](https://github.com/goweft/tenter) is a zero-dependency Python tool with identical scanning behaviour. v2 keeps the rules and config but ships as a single static binary, so CI doesn't need `setup-python`.

| | v1 (Python) | v2 (Rust) |
|---|---|---|
| Runtime | Python 3.9+ required | None — static binary |
| GitHub Action setup | `setup-python` + 10–15 s | Binary download, ~1 s |
| ReDoS protection | Per-file timeout (SEC-003) | Architecturally impossible (DFA/NFA regex) |
| Binary size | N/A | ~1.2–1.9 MB static (measured) |
| Platforms | Any Python platform | linux x86_64/arm64, macOS x86_64/arm64, Windows x86_64 |

## Zero runtime dependencies

The Linux release binary is statically linked against musl libc — no glibc, no Python, no shared libraries, no network. Drop it anywhere and it runs.

## Recording the demo

[`docs/demo.gif`](docs/demo.gif) is generated with [vhs](https://github.com/charmbracelet/vhs):

```bash
# Install vhs (https://github.com/charmbracelet/vhs) and tenter, then:
vhs docs/demo.tape          # writes docs/demo.gif
```

The tape seeds a fresh sample via [`docs/seed-sample.sh`](docs/seed-sample.sh), so the recording is fully reproducible.

## Also by goweft

- **[tenter](https://github.com/goweft/tenter)** — Python v1 (zero pip dependencies)
- **[heddle](https://github.com/goweft/heddle)** — Policy-and-trust layer for MCP tool servers
- **[unshear](https://github.com/goweft/unshear)** — AI agent fork divergence detector

## License

MIT — see [LICENSE](LICENSE).
