#!/usr/bin/env bash
set -euo pipefail

# ──────────────────────────────────────────────────
# hermes-id — One-command setup
# ──────────────────────────────────────────────────
# Installs the hermes-id CLI tool and optionally
# registers the Hermes plugin.
# ──────────────────────────────────────────────────

HERMES_HOME="${HERMES_HOME:-$HOME/.hermes}"
VENV_DIR="${VENV_DIR:-$HERMES_HOME/venvs/hermes-id}"
REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }

info "hermes-id — Setup"
echo ""

# ── Check Python ──────────────────────────────────
PYTHON=""
for cmd in python3 python; do
    if command -v "$cmd" &>/dev/null; then
        PY_VER=$("$cmd" --version 2>&1 | grep -oP '\d+\.\d+')
        if awk "BEGIN {exit !($PY_VER >= 3.11)}"; then
            PYTHON="$cmd"
            break
        fi
    fi
done

if [ -z "$PYTHON" ]; then
    error "Python >= 3.11 is required."
    exit 1
fi
info "Using: $($PYTHON --version)"

# ── Install package ───────────────────────────────
info "Installing hermes-id package..."
cd "$REPO_DIR"

# Create or reuse a venv under HERMES_HOME
if [ ! -d "$VENV_DIR" ]; then
    info "Creating virtual environment at $VENV_DIR..."
    "$PYTHON" -m venv "$VENV_DIR"
fi

source "$VENV_DIR/bin/activate"
pip install --quiet --upgrade pip setuptools wheel
pip install --quiet -e .

info "hermes-id CLI installed: $(which hermes-id)"

# ── Check cryptography ────────────────────────────
if python3 -c "import cryptography" 2>/dev/null; then
    CRYPTO_VER=$(python3 -c "import cryptography; print(cryptography.__version__)")
    info "cryptography $CRYPTO_VER — OK"
else
    warn "cryptography not found — installing..."
    pip install "cryptography>=41.0.0"
fi

# ── Check argon2 (optional) ───────────────────────
if python3 -c "import argon2" 2>/dev/null; then
    info "argon2-cffi — available (strongest KDF)"
else
    warn "argon2-cffi not found — using scrypt (still strong)."
    warn "Install: pip install argon2-cffi"
fi

# ── Hermes plugin ─────────────────────────────────
PLUGIN_DIR="$HERMES_HOME/plugins/hermes-id"
if [ -d "$PLUGIN_DIR" ]; then
    info "Hermes plugin already installed at $PLUGIN_DIR"
else
    info "Installing Hermes plugin..."
    mkdir -p "$HERMES_HOME/plugins/hermes-id"
    cp "$REPO_DIR/plugins/hermes-id/"* "$PLUGIN_DIR/"
    info "Plugin copied to $PLUGIN_DIR"
    info "Enable with: hermes plugins enable hermes-id"
    info "Then restart: hermes gateway restart"
fi

echo ""
info "✅ hermes-id setup complete!"
echo ""
info "Quick start:"
info "  hermes-id init           # Create your identity"
info "  hermes-id status         # Check identity"
info "  hermes-id show           # Display identity card"
info ""
info "Documentation:"
info "  cat README.md"
echo ""
