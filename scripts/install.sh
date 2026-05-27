#!/bin/sh
# secretscan installer — detects OS/arch, downloads from GitHub, verifies checksum.
#
# Usage:
#   curl -sSfL https://raw.githubusercontent.com/Nciibi/secretscan/main/scripts/install.sh | sh
#
set -e

REPO="Nciibi/secretscan"
INSTALL_DIR="/usr/local/bin"
BINARY="secretscan"

# Detect OS.
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
case "$OS" in
  linux*)  OS="linux" ;;
  darwin*) OS="darwin" ;;
  *)
    echo "❌ Unsupported OS: $OS"
    exit 1
    ;;
esac

# Detect architecture.
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *)
    echo "❌ Unsupported architecture: $ARCH"
    exit 1
    ;;
esac

echo "🔍 Detecting system: ${OS}/${ARCH}"

# Get the latest release tag.
LATEST=$(curl -sSf "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')
if [ -z "$LATEST" ]; then
  echo "❌ Could not determine latest release."
  exit 1
fi

VERSION="${LATEST#v}"
echo "📦 Latest version: ${LATEST}"

# Build the download URL.
ARCHIVE="secretscan_${VERSION}_${OS}_${ARCH}.tar.gz"
URL="https://github.com/${REPO}/releases/download/${LATEST}/${ARCHIVE}"
CHECKSUM_URL="https://github.com/${REPO}/releases/download/${LATEST}/checksums.txt"

# Download.
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

echo "⬇️  Downloading ${URL}..."
curl -sSfL -o "${TMPDIR}/${ARCHIVE}" "${URL}"
curl -sSfL -o "${TMPDIR}/checksums.txt" "${CHECKSUM_URL}"

# Verify checksum.
echo "🔐 Verifying checksum..."
cd "$TMPDIR"
EXPECTED=$(grep "${ARCHIVE}" checksums.txt | awk '{print $1}')
if [ -z "$EXPECTED" ]; then
  echo "⚠️  Checksum not found in checksums.txt, skipping verification."
else
  ACTUAL=$(sha256sum "${ARCHIVE}" | awk '{print $1}')
  if [ "$EXPECTED" != "$ACTUAL" ]; then
    echo "❌ Checksum mismatch!"
    echo "   Expected: ${EXPECTED}"
    echo "   Actual:   ${ACTUAL}"
    exit 1
  fi
  echo "✅ Checksum verified."
fi

# Extract and install.
tar -xzf "${ARCHIVE}"
echo "📁 Installing to ${INSTALL_DIR}/${BINARY}..."

if [ -w "$INSTALL_DIR" ]; then
  mv "${BINARY}" "${INSTALL_DIR}/${BINARY}"
else
  sudo mv "${BINARY}" "${INSTALL_DIR}/${BINARY}"
fi

chmod +x "${INSTALL_DIR}/${BINARY}"

echo ""
echo "✅ secretscan ${LATEST} installed successfully!"
echo "   Run: secretscan --help"
