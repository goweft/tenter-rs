# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.1.0] - 2026-06-24

Adoption / documentation release. **No detection-engine or rule changes** —
scanning behaviour is identical to v2.0.x and to [tenter v1](https://github.com/goweft/tenter).

### Added
- Rewritten README with a top-of-funnel value proposition, a 5-minute
  copy-paste quickstart with real example output, a "Who should / When NOT to
  use this" section, and an honest comparison table against TruffleHog,
  GitGuardian, and gitleaks (including where those tools are stronger).
- `.pre-commit-hooks.yaml` with `tenter` and `tenter-scan` hooks, plus a
  prebuilt-binary download wrapper (`hooks/tenter-precommit.sh`) — adopt via the
  [pre-commit](https://pre-commit.com) framework with no Rust toolchain.
- `docs/seed-sample.sh` and `docs/demo.tape` — a reproducible
  [vhs](https://github.com/charmbracelet/vhs) recording for `docs/demo.gif`.
- README badges (CI, latest release, license) and discoverability polish.

### Changed
- GitHub Action install step hardened: installs to `$RUNNER_TEMP` and adds it to
  `$GITHUB_PATH` (no write to `/usr/local/bin`, no `sudo`), and validates the
  downloaded binary by version.
- Documented binary size corrected to the measured **~1.2–1.9 MB** (previously
  stated "~3 MB").

## [2.0.4] - 2026-04-07

### Fixed
- `action.yml`: shorten the Marketplace description under the 125-character limit.
- Add `.tenter.json` allowlisting `target/**` and the test fixtures so the
  self-scan stays green.

## [2.0.3] - 2026-04-07

### Fixed
- CI static-binary check now matches both `statically linked` and
  `static-pie linked` (newer Rust toolchains emit the PIE form).

## [2.0.2] - 2026-04-07

### Fixed
- `action.yml` YAML/shell robustness around output-format handling and a safe
  exit-code default.

## [2.0.1] - 2026-04-07

### Fixed
- `action.yml`: distinct Marketplace name (`Tenter Scan (Rust)`), `latest`
  version auto-resolution via the Releases API, and safer shell quoting.
- Use `file(1)` instead of `ldd` for the static-binary check, which is reliable
  for cross-compiled aarch64 binaries on an x86_64 host.

## [2.0.0] - 2026-04-04

### Added
- Initial **tenter v2** release: a full Rust port of tenter v1 with identical
  scanning behaviour, rule IDs, `.tenter.json` schema, and CLI surface.
- Single static binary across five targets (linux x86_64/aarch64-musl, macOS
  x86_64/aarch64, Windows x86_64); no Python runtime.
- Composite GitHub Action that downloads the binary directly (no `setup-python`).
- Human, JSON, and SARIF output; SARIF upload to GitHub code scanning.

### Changed (vs v1)
- ReDoS protection is now architectural: the Rust `regex` crate is DFA/NFA
  (linear time), so v1's `SEC-003` per-file timeout is not implemented.

<sub>Entries for 2.0.1–2.0.4 are reconstructed from git history (same-day patch releases on 2026-04-07).</sub>

[2.1.0]: https://github.com/goweft/tenter-rs/compare/v2.0.4...v2.1.0
[2.0.4]: https://github.com/goweft/tenter-rs/compare/v2.0.3...v2.0.4
[2.0.3]: https://github.com/goweft/tenter-rs/compare/v2.0.2...v2.0.3
[2.0.2]: https://github.com/goweft/tenter-rs/compare/v2.0.1...v2.0.2
[2.0.1]: https://github.com/goweft/tenter-rs/compare/v2.0.0...v2.0.1
[2.0.0]: https://github.com/goweft/tenter-rs/releases/tag/v2.0.0
