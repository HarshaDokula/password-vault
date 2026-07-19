#!/usr/bin/env bash
set -euo pipefail

# Vault Password Manager — one-line installer
# Usage: curl -fsSL https://raw.githubusercontent.com/HarshaDokula/password-vault/main/install.sh | bash

REPO="HarshaDokula/password-vault"
VERSION="${VERSION:-latest}"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"

# ── Detect platform ──────────────────────────────────────────────
OS=$(uname -s)
ARCH=$(uname -m)

case "$OS" in
    Linux)  PLATFORM="linux" ;;
    Darwin) PLATFORM="macos" ;;
    *)
        echo "Unsupported OS: $OS"
        exit 1
        ;;
esac

case "$ARCH" in
    x86_64|amd64) ARCH="x86_64" ;;
    aarch64|arm64) ARCH="aarch64" ;;
    *)
        echo "Unsupported architecture: $ARCH"
        exit 1
        ;;
esac

# ── Resolve version ──────────────────────────────────────────────
if [ "$VERSION" = "latest" ]; then
    echo "🔍 Fetching latest release..."
    VERSION=$(curl -sL "https://api.github.com/repos/$REPO/releases/latest" | grep '"tag_name":' | sed -E 's/.*"tag_name": "([^"]+)".*/\1/')
    if [ -z "$VERSION" ]; then
        echo "Failed to determine latest version"
        exit 1
    fi
fi

ARTIFACT="vault-${PLATFORM}-${ARCH}.tar.gz"
URL="https://github.com/$REPO/releases/download/${VERSION}/${ARTIFACT}"

echo "📦 Installing vault ${VERSION} for ${PLATFORM}/${ARCH}..."

# ── Download and install ─────────────────────────────────────────
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

echo "⬇️  Downloading ${ARTIFACT}..."
curl -fsSL "$URL" -o "$TMP_DIR/$ARTIFACT"

echo "📂 Extracting..."
tar xzf "$TMP_DIR/$ARTIFACT" -C "$TMP_DIR"

echo "🚀 Installing to ${INSTALL_DIR}..."
if [ -w "$INSTALL_DIR" ]; then
    cp "$TMP_DIR/vault" "$INSTALL_DIR/vault"
else
    sudo cp "$TMP_DIR/vault" "$INSTALL_DIR/vault"
fi

chmod +x "$INSTALL_DIR/vault"

echo "✅ vault ${VERSION} installed to ${INSTALL_DIR}/vault"
echo ""
echo "Run 'vault' to get started."
