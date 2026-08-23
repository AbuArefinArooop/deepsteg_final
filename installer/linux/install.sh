#!/usr/bin/env bash
# ============================================================
#  DeepSteg v4 — Linux Universal Installer
#  Supports: Kali Linux, Parrot OS, Ubuntu, Debian
#
#  Developer  : Abu Arefin Aroop
#  Role       : AI-Assisted Cyber Security Engineer
#  Institution: Arslan Institute of Technology (AiT)
#  Reg. No.   : AiT-IP-2026-DS-0001
#  Copyright  : © 2026 Abu Arefin Aroop — All Rights Reserved
#  Protected  : WIPO Berne Convention | Bangladesh Copyright Act 2000
# ============================================================
#
# USAGE:
#   chmod +x installer/linux/install.sh
#   ./installer/linux/install.sh
#   ./installer/linux/install.sh --uninstall    # remove
# ============================================================

set -euo pipefail

APP_NAME="DeepSteg v4"
APP_VERSION="4.0.2"
DEVELOPER="Abu Arefin Aroop"
ORG="Arslan Institute of Technology (AiT)"
REG_NO="AiT-IP-2026-DS-0001"

INSTALL_DIR="$HOME/.local/share/deepsteg"
BIN_LINK="/usr/local/bin/deepsteg"
DESKTOP_FILE="$HOME/.local/share/applications/deepsteg.desktop"
SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# ── Colors ────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'
YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
BOLD='\033[1m'

log_ok()   { echo -e "  ${GREEN}✓${NC}  $*"; }
log_fail() { echo -e "  ${RED}✗${NC}  $*"; }
log_info() { echo -e "  ${CYAN}ℹ${NC}  $*"; }
log_warn() { echo -e "  ${YELLOW}⚠${NC}  $*"; }
log_step() { echo -e "\n${BOLD}${BLUE}[$1]${NC} $2"; }

# ── Banner ────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║  DeepSteg v4 — Linux Universal Installer            ║${NC}"
echo -e "${CYAN}║  $DEVELOPER                           ║${NC}"
echo -e "${CYAN}║  $ORG              ║${NC}"
echo -e "${CYAN}║  © 2026 Abu Arefin Aroop — All Rights Reserved     ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════╝${NC}"
echo ""

# ── Uninstall mode ────────────────────────────────────────────
if [[ "${1:-}" == "--uninstall" ]]; then
    log_step "UNINSTALL" "Removing DeepSteg v4..."
    [ -d "$INSTALL_DIR" ] && rm -rf "$INSTALL_DIR" && log_ok "Removed $INSTALL_DIR"
    [ -L "$BIN_LINK" ]    && sudo rm -f "$BIN_LINK" && log_ok "Removed $BIN_LINK"
    [ -f "$DESKTOP_FILE" ] && rm -f "$DESKTOP_FILE" && log_ok "Removed desktop entry"
    echo ""
    log_ok "DeepSteg v4 uninstalled."
    exit 0
fi

# ── Detect distro ─────────────────────────────────────────────
log_step "1/7" "Detecting Linux distribution..."
DISTRO="unknown"
if [ -f /etc/os-release ]; then
    source /etc/os-release
    ID_LOWER="${ID,,}"
    if [[ "$ID_LOWER" == *"kali"* ]]; then
        DISTRO="kali"
    elif [[ "$ID_LOWER" == *"parrot"* ]]; then
        DISTRO="parrot"
    elif [[ "$ID_LOWER" == *"ubuntu"* ]]; then
        DISTRO="ubuntu"
    elif [[ "$ID_LOWER" == *"debian"* ]]; then
        DISTRO="debian"
    elif [[ "$ID_LOWER" == *"fedora"* ]]; then
        DISTRO="fedora"
    elif [[ "$ID_LOWER" == *"arch"* ]]; then
        DISTRO="arch"
    fi
fi
log_ok "Detected: $DISTRO (${PRETTY_NAME:-Linux})"

# ── Check Python 3.10+ ────────────────────────────────────────
log_step "2/7" "Checking Python 3.10+..."
PYTHON=""
for cmd in python3.12 python3.11 python3.10 python3; do
    if command -v "$cmd" &>/dev/null; then
        VER=$("$cmd" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
        MAJOR=$(echo "$VER" | cut -d. -f1)
        MINOR=$(echo "$VER" | cut -d. -f2)
        if [ "$MAJOR" -ge 3 ] && [ "$MINOR" -ge 10 ]; then
            PYTHON="$cmd"
            log_ok "Found Python $VER (via '$cmd')"
            break
        fi
    fi
done

if [ -z "$PYTHON" ]; then
    log_fail "Python 3.10+ not found. Installing..."
    case "$DISTRO" in
        kali|parrot|ubuntu|debian)
            sudo apt-get update -qq
            sudo apt-get install -y python3 python3-pip python3-venv python3-tk
            ;;
        fedora)
            sudo dnf install -y python3 python3-pip python3-tkinter
            ;;
        arch)
            sudo pacman -Sy --noconfirm python python-pip tk
            ;;
        *)
            log_fail "Cannot auto-install Python on $DISTRO. Install python3.10+ manually."
            exit 1
            ;;
    esac
    PYTHON="python3"
    log_ok "Python installed."
fi

# ── Install system dependencies ───────────────────────────────
log_step "3/7" "Installing system dependencies..."
case "$DISTRO" in
    kali|parrot|ubuntu|debian)
        PKGS="python3-tk python3-venv libgl1-mesa-glx libglib2.0-0"
        log_info "Running: sudo apt-get install -y $PKGS"
        sudo apt-get install -y $PKGS -qq 2>/dev/null || log_warn "Some packages may already be installed."
        log_ok "System dependencies ready."
        ;;
    fedora)
        sudo dnf install -y python3-tkinter mesa-libGL glib2 -q || true
        log_ok "System dependencies ready."
        ;;
    arch)
        sudo pacman -Sy --noconfirm tk mesa glib2 || true
        log_ok "System dependencies ready."
        ;;
    *)
        log_warn "Unknown distro — skipping system packages. Install tkinter + libGL manually."
        ;;
esac

# ── Create installation directory ────────────────────────────
log_step "4/7" "Creating installation directory..."
mkdir -p "$INSTALL_DIR"
mkdir -p "$HOME/.local/share/applications"
mkdir -p "$HOME/.local/share/deepsteg/logs"
mkdir -p "$HOME/.config/deepsteg"
log_ok "Install dir: $INSTALL_DIR"

# Copy app files
for item in deepsteg_app.py core assets tests docs __init__.py requirements.txt; do
    src="$SOURCE_DIR/$item"
    if [ -e "$src" ]; then
        cp -r "$src" "$INSTALL_DIR/"
        log_ok "Copied $item"
    fi
done

# ── Create virtual environment ────────────────────────────────
log_step "5/7" "Creating Python virtual environment..."
VENV="$INSTALL_DIR/venv"
"$PYTHON" -m venv "$VENV"
PIP="$VENV/bin/pip"
PY="$VENV/bin/python"
log_ok "venv: $VENV"

# Upgrade pip silently
"$PIP" install --upgrade pip --quiet

# Install Python dependencies
log_info "Installing Python packages (may take 1-3 minutes)..."
if [ -f "$INSTALL_DIR/requirements.txt" ]; then
    "$PIP" install -r "$INSTALL_DIR/requirements.txt" --quiet
else
    # Fallback pinned list if requirements.txt wasn't copied for some reason
    DEPS=(
        "cryptography==42.0.8"
        "opencv-python==4.10.0.84"
        "numpy==1.26.4"
        "Pillow==10.3.0"
        "scikit-image==0.23.2"
        "matplotlib==3.9.0"
    )
    for dep in "${DEPS[@]}"; do
        log_info "  Installing $dep..."
        "$PIP" install "$dep" --quiet
    done
fi
log_ok "All Python dependencies installed."

# Optional: Kyber-1024
log_info "Attempting Kyber-1024 (post-quantum KEM)..."
"$PIP" install kyber-py --quiet 2>/dev/null \
    && log_ok "kyber-py installed (Kyber-1024 active)" \
    || log_warn "kyber-py unavailable — X25519 fallback active"

# ── Create launcher script ────────────────────────────────────
log_step "6/7" "Creating launcher scripts..."
LAUNCHER="$INSTALL_DIR/run.sh"
cat > "$LAUNCHER" << EOF
#!/usr/bin/env bash
# DeepSteg v4 Launcher
# © 2026 $DEVELOPER | $ORG | $REG_NO
export PYTHONPATH="$INSTALL_DIR"
cd "$INSTALL_DIR"
exec "$PY" deepsteg_app.py "\$@"
EOF
chmod +x "$LAUNCHER"
log_ok "Launcher: $LAUNCHER"

# System-wide symlink (requires sudo)
if command -v sudo &>/dev/null; then
    sudo ln -sf "$LAUNCHER" "$BIN_LINK" 2>/dev/null \
        && log_ok "System link: $BIN_LINK (run 'deepsteg' from anywhere)" \
        || log_warn "Could not create /usr/local/bin/deepsteg (run without sudo?)"
fi

# ── .desktop entry (application menu) ────────────────────────
log_step "7/7" "Creating desktop application entry..."
ICON_PATH="$INSTALL_DIR/assets/AiT_Logo.png"
cat > "$DESKTOP_FILE" << EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=DeepSteg v4
GenericName=Secure Video Steganography
Comment=DeepSteg v4 by $DEVELOPER — $ORG
Exec=$LAUNCHER
Icon=$ICON_PATH
Terminal=false
StartupNotify=true
Categories=Security;Education;Science;
Keywords=steganography;cryptography;AES;security;AiT;
EOF
chmod +x "$DESKTOP_FILE"

# Refresh desktop database
update-desktop-database "$HOME/.local/share/applications" 2>/dev/null || true
log_ok "Desktop entry: $DESKTOP_FILE"

# ── Run tests ─────────────────────────────────────────────────
echo ""
echo -e "${BOLD}Running security test suite...${NC}"
PYTHONPATH="$INSTALL_DIR" "$PY" "$INSTALL_DIR/tests/test_security.py" 2>&1 | tail -20

# ── Final message ─────────────────────────────────────────────
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  ✅  DeepSteg v4 installed successfully!            ║${NC}"
echo -e "${GREEN}║                                                      ║${NC}"
echo -e "${GREEN}║  Run with:  deepsteg                                ║${NC}"
echo -e "${GREEN}║  Or:        $LAUNCHER${NC}"
echo -e "${GREEN}║                                                      ║${NC}"
echo -e "${GREEN}║  Desktop: Look for 'DeepSteg v4' in app menu       ║${NC}"
echo -e "${GREEN}║                                                      ║${NC}"
echo -e "${GREEN}║  © 2026 $DEVELOPER | $ORG     ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════╝${NC}"
echo ""
