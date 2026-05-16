#!/usr/bin/env bash
set -euo pipefail

: "${INPUT_INSTALL_MODE:=release}"
: "${INPUT_VERSION:=latest}"

install_bin=""

case "$INPUT_INSTALL_MODE" in
  release)
    if [[ "$INPUT_VERSION" == "latest" ]]; then
      curl -sSf https://raw.githubusercontent.com/brandonwise/agentwise/main/install.sh | sh
    else
      curl -sSf https://raw.githubusercontent.com/brandonwise/agentwise/main/install.sh | sh -s -- --version "$INPUT_VERSION"
    fi
    install_bin="$HOME/.local/bin"
    ;;
  source)
    if ! command -v cargo >/dev/null 2>&1; then
      echo "cargo is required when INPUT_INSTALL_MODE=source" >&2
      exit 1
    fi

    if [[ -z "${GITHUB_ACTION_PATH:-}" || ! -f "${GITHUB_ACTION_PATH}/Cargo.toml" ]]; then
      echo "GITHUB_ACTION_PATH must point to the agentwise checkout when INPUT_INSTALL_MODE=source" >&2
      exit 1
    fi

    install_root="${RUNNER_TEMP:-${TMPDIR:-/tmp}}/agentwise-action-root"
    rm -rf "$install_root"
    cargo install --locked --path "$GITHUB_ACTION_PATH" --root "$install_root" --force
    install_bin="$install_root/bin"
    ;;
  *)
    echo "Unsupported INPUT_INSTALL_MODE: $INPUT_INSTALL_MODE (expected 'release' or 'source')" >&2
    exit 1
    ;;
esac

if [[ -n "${GITHUB_PATH:-}" ]]; then
  printf '%s\n' "$install_bin" >> "$GITHUB_PATH"
else
  export PATH="$install_bin:$PATH"
fi

echo "Installed agentwise via ${INPUT_INSTALL_MODE} mode (${install_bin})"
