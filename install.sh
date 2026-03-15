#!/usr/bin/env sh
# agentwise installer
# Usage: curl -sSf https://raw.githubusercontent.com/brandonwise/agentwise/main/install.sh | sh

set -eu

REPO="brandonwise/agentwise"
BINARY="agentwise"
GITHUB_API="https://api.github.com/repos/${REPO}"
GITHUB_RELEASE_BASE="https://github.com/${REPO}/releases/download"

say() {
  printf '%s\n' "$*"
}

err() {
  printf 'agentwise install error: %s\n' "$*" >&2
}

die() {
  err "$1"
  exit 1
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "Missing required command: $1"
}

sha256_file() {
  file="$1"

  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$file" | awk '{print $1}'
    return
  fi

  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$file" | awk '{print $1}'
    return
  fi

  if command -v openssl >/dev/null 2>&1; then
    openssl dgst -sha256 "$file" | awk '{print $NF}'
    return
  fi

  die "No SHA256 tool found (need shasum, sha256sum, or openssl)."
}

detect_target() {
  os_raw=$(uname -s 2>/dev/null | tr '[:upper:]' '[:lower:]')
  arch_raw=$(uname -m 2>/dev/null)

  case "$os_raw" in
    linux)
      os="linux"
      ;;
    darwin)
      os="macos"
      ;;
    *)
      die "Unsupported OS '${os_raw}'. This installer supports Linux and macOS only."
      ;;
  esac

  case "$arch_raw" in
    x86_64|amd64)
      arch="amd64"
      ;;
    aarch64|arm64)
      arch="arm64"
      ;;
    *)
      die "Unsupported architecture '${arch_raw}'. Supported architectures: amd64, arm64."
      ;;
  esac

  TARGET="${os}-${arch}"
}

resolve_version() {
  if [ -n "${AGENTWISE_VERSION:-}" ]; then
    case "$AGENTWISE_VERSION" in
      v*)
        RELEASE_TAG="$AGENTWISE_VERSION"
        VERSION="${AGENTWISE_VERSION#v}"
        ;;
      *)
        RELEASE_TAG="v${AGENTWISE_VERSION}"
        VERSION="$AGENTWISE_VERSION"
        ;;
    esac
    return
  fi

  release_json=$(curl -fsSL "${GITHUB_API}/releases/latest") || die "Failed to fetch latest release metadata from GitHub."
  RELEASE_TAG=$(printf '%s' "$release_json" | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)

  [ -n "$RELEASE_TAG" ] || die "Could not determine the latest release tag."
  VERSION="${RELEASE_TAG#v}"
}

choose_install_dir() {
  INSTALL_DIR_CHOSEN="${INSTALL_DIR:-}"
  USE_SUDO=0

  if [ -z "$INSTALL_DIR_CHOSEN" ]; then
    if [ -w "/usr/local/bin" ]; then
      INSTALL_DIR_CHOSEN="/usr/local/bin"
    elif [ -d "/usr/local/bin" ] && command -v sudo >/dev/null 2>&1; then
      INSTALL_DIR_CHOSEN="/usr/local/bin"
      USE_SUDO=1
    else
      INSTALL_DIR_CHOSEN="${HOME}/.local/bin"
    fi
  fi

  if [ "$INSTALL_DIR_CHOSEN" != "/usr/local/bin" ] && [ -d "$INSTALL_DIR_CHOSEN" ] && [ ! -w "$INSTALL_DIR_CHOSEN" ] && command -v sudo >/dev/null 2>&1; then
    USE_SUDO=1
  fi
}

prepare_install_dir() {
  if [ "$USE_SUDO" -eq 1 ]; then
    sudo mkdir -p "$INSTALL_DIR_CHOSEN" || die "Failed to create install directory '${INSTALL_DIR_CHOSEN}'."
  else
    mkdir -p "$INSTALL_DIR_CHOSEN" || die "Failed to create install directory '${INSTALL_DIR_CHOSEN}'."
  fi
}

install_binary() {
  src="$1"
  dest="$2"

  if [ "$USE_SUDO" -eq 1 ]; then
    if command -v install >/dev/null 2>&1; then
      sudo install -m 0755 "$src" "$dest" || die "Failed to install binary to '${dest}'."
    else
      sudo cp "$src" "$dest" || die "Failed to copy binary to '${dest}'."
      sudo chmod 0755 "$dest" || die "Failed to set executable permissions on '${dest}'."
    fi
  else
    if command -v install >/dev/null 2>&1; then
      install -m 0755 "$src" "$dest" || die "Failed to install binary to '${dest}'."
    else
      cp "$src" "$dest" || die "Failed to copy binary to '${dest}'."
      chmod 0755 "$dest" || die "Failed to set executable permissions on '${dest}'."
    fi
  fi
}

main() {
  need_cmd curl
  need_cmd tar
  need_cmd mktemp

  detect_target
  resolve_version
  choose_install_dir

  ARCHIVE="${BINARY}-${VERSION}-${TARGET}.tar.gz"
  CHECKSUMS_FILE="agentwise-${VERSION}-checksums.txt"
  ARCHIVE_URL="${GITHUB_RELEASE_BASE}/${RELEASE_TAG}/${ARCHIVE}"
  CHECKSUMS_URL="${GITHUB_RELEASE_BASE}/${RELEASE_TAG}/${CHECKSUMS_FILE}"

  TMP_DIR=$(mktemp -d 2>/dev/null || mktemp -d -t agentwise-install)
  trap 'rm -rf "$TMP_DIR"' EXIT INT TERM

  say "Installing agentwise ${VERSION} (${TARGET})..."
  say "Downloading ${ARCHIVE}"
  curl -fsSL "$ARCHIVE_URL" -o "$TMP_DIR/$ARCHIVE" || die "Failed to download release archive from ${ARCHIVE_URL}."

  say "Downloading checksums"
  curl -fsSL "$CHECKSUMS_URL" -o "$TMP_DIR/$CHECKSUMS_FILE" || die "Failed to download checksums from ${CHECKSUMS_URL}."

  expected_sha=$(grep "[[:space:]]${ARCHIVE}$" "$TMP_DIR/$CHECKSUMS_FILE" | awk '{print $1}' | head -n 1 || true)
  [ -n "$expected_sha" ] || die "Could not find checksum for ${ARCHIVE} in ${CHECKSUMS_FILE}."

  actual_sha=$(sha256_file "$TMP_DIR/$ARCHIVE")
  [ "$actual_sha" = "$expected_sha" ] || die "Checksum verification failed for ${ARCHIVE}."

  say "Checksum verified"
  tar -xzf "$TMP_DIR/$ARCHIVE" -C "$TMP_DIR" || die "Failed to extract ${ARCHIVE}."

  BINARY_PATH="$TMP_DIR/$BINARY"
  if [ ! -f "$BINARY_PATH" ]; then
    BINARY_PATH=$(find "$TMP_DIR" -maxdepth 2 -type f -name "$BINARY" | head -n 1 || true)
  fi
  [ -n "${BINARY_PATH:-}" ] && [ -f "$BINARY_PATH" ] || die "Could not locate '${BINARY}' in extracted archive."

  prepare_install_dir
  install_binary "$BINARY_PATH" "$INSTALL_DIR_CHOSEN/$BINARY"

  say ""
  say "✅ Installed to $INSTALL_DIR_CHOSEN/$BINARY"

  case ":$PATH:" in
    *":$INSTALL_DIR_CHOSEN:"*) ;;
    *)
      if [ "$INSTALL_DIR_CHOSEN" = "${HOME}/.local/bin" ]; then
        say "Add ~/.local/bin to your PATH if needed:"
        say "  export PATH=\"$HOME/.local/bin:$PATH\""
      fi
      ;;
  esac

  say "Run: agentwise --version"
}

main "$@"
