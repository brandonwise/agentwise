#!/bin/sh
# agentwise installer
# Usage: curl -sSf https://raw.githubusercontent.com/brandonwise/agentwise/main/install.sh | sh

set -e

REPO="brandonwise/agentwise"
BINARY="agentwise"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"

# Detect OS and architecture
detect_platform() {
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    ARCH=$(uname -m)

    case "$OS" in
        linux) OS="unknown-linux-gnu" ;;
        darwin) OS="apple-darwin" ;;
        *) echo "Unsupported OS: $OS"; exit 1 ;;
    esac

    case "$ARCH" in
        x86_64|amd64) ARCH="x86_64" ;;
        aarch64|arm64) ARCH="aarch64" ;;
        *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
    esac

    PLATFORM="${ARCH}-${OS}"
}

# Get latest release tag
get_latest_version() {
    VERSION=$(curl -sSf "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')
    if [ -z "$VERSION" ]; then
        echo "Failed to get latest version"
        exit 1
    fi
}

main() {
    echo "Installing agentwise..."

    detect_platform
    get_latest_version

    URL="https://github.com/${REPO}/releases/download/${VERSION}/${BINARY}-${PLATFORM}.tar.gz"

    echo "  Platform: ${PLATFORM}"
    echo "  Version:  ${VERSION}"
    echo "  URL:      ${URL}"

    TMPDIR=$(mktemp -d)
    trap "rm -rf $TMPDIR" EXIT

    curl -sSfL "$URL" -o "$TMPDIR/agentwise.tar.gz"
    tar xzf "$TMPDIR/agentwise.tar.gz" -C "$TMPDIR"

    if [ -w "$INSTALL_DIR" ]; then
        mv "$TMPDIR/$BINARY" "$INSTALL_DIR/$BINARY"
    else
        sudo mv "$TMPDIR/$BINARY" "$INSTALL_DIR/$BINARY"
    fi

    chmod +x "$INSTALL_DIR/$BINARY"

    echo ""
    echo "✅ agentwise installed to $INSTALL_DIR/$BINARY"
    echo "   Run: agentwise scan ."
}

main
