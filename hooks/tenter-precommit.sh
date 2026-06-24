#!/usr/bin/env bash
# pre-commit wrapper for tenter-rs.
#
# Invoked by the pre-commit framework (see .pre-commit-hooks.yaml). Downloads the
# matching tenter-rs release binary on first run, caches it, then runs tenter
# with whatever arguments the hook passed (e.g. `npm-check .` or `scan ./dist`).
# No Rust toolchain required. Linux and macOS only.
set -euo pipefail

# Kept in lockstep with this hook's release tag so `rev:` and the downloaded
# binary always match. Override with TENTER_VERSION to test a different build.
TENTER_VERSION="${TENTER_VERSION:-2.1.0}"
TENTER_VERSION="${TENTER_VERSION#v}"

cache_dir="${XDG_CACHE_HOME:-$HOME/.cache}/tenter-rs"
bin="$cache_dir/tenter-${TENTER_VERSION}"

if [ ! -x "$bin" ]; then
  os="$(uname -s | tr '[:upper:]' '[:lower:]')"
  arch="$(uname -m)"
  case "$arch" in
    x86_64 | amd64)  arch="x86_64" ;;
    aarch64 | arm64) arch="aarch64" ;;
    *) echo "tenter pre-commit: unsupported architecture '$arch'" >&2; exit 1 ;;
  esac
  case "$os" in
    linux | darwin) asset="tenter-${os}-${arch}" ;;
    *) echo "tenter pre-commit: unsupported OS '$os' (Linux/macOS only — use the GitHub Action elsewhere)" >&2; exit 1 ;;
  esac

  url="https://github.com/goweft/tenter-rs/releases/download/v${TENTER_VERSION}/${asset}"
  echo "tenter pre-commit: downloading ${asset} (v${TENTER_VERSION})…" >&2
  mkdir -p "$cache_dir"
  tmp="$(mktemp "${cache_dir}/.dl.XXXXXX")"
  if ! curl -fsSL "$url" -o "$tmp"; then
    rm -f "$tmp"
    echo "tenter pre-commit: download failed from $url" >&2
    exit 1
  fi
  chmod +x "$tmp"
  mv -f "$tmp" "$bin"
fi

exec "$bin" "$@"
