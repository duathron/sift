#!/usr/bin/env bash
# sift — AI-Powered Alert Triage Summarizer
# Installation script for Linux / macOS / Kali Linux
#
# Usage: ./install.sh [--llm] [--enrich] [--all] [--dev]
#
#   --llm      Install with LLM extras (anthropic, openai)
#   --enrich   Install with enrichment extras (barb-phish)
#   --all      Install all optional extras
#   --dev      Install in editable mode from local source (dev/contributor workflow)
#
# Examples:
#   ./install.sh
#   ./install.sh --llm
#   ./install.sh --all
#   ./install.sh --dev
set -euo pipefail

SIFT_VERSION="0.1.0"
MINIMUM_PYTHON="3.11"
PACKAGE_NAME="sift-triage"

# ─── Colour helpers ────────────────────────────────────────────────────────────
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

info()    { echo -e "${CYAN}[sift]${RESET} $*"; }
success() { echo -e "${GREEN}[sift]${RESET} $*"; }
warn()    { echo -e "${YELLOW}[warn]${RESET} $*"; }
error()   { echo -e "${RED}[error]${RESET} $*" >&2; }

# ─── Parse flags ───────────────────────────────────────────────────────────────
OPT_LLM=false
OPT_ENRICH=false
OPT_ALL=false
OPT_DEV=false

for arg in "$@"; do
    case "$arg" in
        --llm)    OPT_LLM=true ;;
        --enrich) OPT_ENRICH=true ;;
        --all)    OPT_ALL=true ;;
        --dev)    OPT_DEV=true ;;
        --help|-h)
            sed -n '3,16p' "$0" | sed 's/^# \?//'
            exit 0
            ;;
        *)
            error "Unknown option: $arg"
            echo "Usage: $0 [--llm] [--enrich] [--all] [--dev]"
            exit 1
            ;;
    esac
done

# ─── Banner ────────────────────────────────────────────────────────────────────
echo -e "${BOLD}"
echo "  ███████╗██╗███████╗████████╗"
echo "  ██╔════╝██║██╔════╝╚══██╔══╝"
echo "  ███████╗██║█████╗     ██║   "
echo "  ╚════██║██║██╔══╝     ██║   "
echo "  ███████║██║██║        ██║   "
echo "  ╚══════╝╚═╝╚═╝        ╚═╝   v${SIFT_VERSION}"
echo -e "${RESET}"
echo "  AI-Powered Alert Triage Summarizer"
echo "  Install script for Linux / macOS / Kali Linux"
echo ""

# ─── 1. Locate a suitable Python interpreter ───────────────────────────────────
info "Checking Python version (minimum ${MINIMUM_PYTHON})..."

PYTHON=""
for candidate in python3 python3.14 python3.13 python3.12 python3.11 python; do
    if command -v "$candidate" &>/dev/null; then
        ver=$("$candidate" -c "import sys; print('%d.%d' % sys.version_info[:2])" 2>/dev/null || true)
        if [ -z "$ver" ]; then
            continue
        fi
        # Compare major.minor using sort -V (available on Linux; fallback arithmetic on macOS)
        if printf '%s\n%s\n' "$MINIMUM_PYTHON" "$ver" | sort -V -C 2>/dev/null; then
            PYTHON="$candidate"
            break
        fi
        # Fallback: arithmetic comparison for X.Y format
        min_maj=${MINIMUM_PYTHON%%.*}; min_min=${MINIMUM_PYTHON##*.}
        cur_maj=${ver%%.*};            cur_min=${ver##*.}
        if [ "$cur_maj" -gt "$min_maj" ] || \
           { [ "$cur_maj" -eq "$min_maj" ] && [ "$cur_min" -ge "$min_min" ]; }; then
            PYTHON="$candidate"
            break
        fi
    fi
done

if [ -z "$PYTHON" ]; then
    error "Python ${MINIMUM_PYTHON}+ is required but was not found."
    echo ""
    echo "  On Kali / Debian:"
    echo "    sudo apt install python3.11"
    echo ""
    echo "  On macOS with Homebrew:"
    echo "    brew install python@3.11"
    echo ""
    exit 1
fi

PYTHON_VER=$("$PYTHON" -c "import sys; print('%d.%d.%d' % sys.version_info[:3])")
success "Found Python ${PYTHON_VER} at $(command -v "$PYTHON")"

# ─── 2. Build the extras string ────────────────────────────────────────────────
EXTRAS=""
if [ "$OPT_ALL" = true ]; then
    EXTRAS="[all]"
elif [ "$OPT_LLM" = true ] && [ "$OPT_ENRICH" = true ]; then
    EXTRAS="[llm,enrich]"
elif [ "$OPT_LLM" = true ]; then
    EXTRAS="[llm]"
elif [ "$OPT_ENRICH" = true ]; then
    EXTRAS="[enrich]"
fi

# ─── 3. Dev mode — editable install from local source ──────────────────────────
if [ "$OPT_DEV" = true ]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    info "Dev mode: editable install from ${SCRIPT_DIR}"
    if [ ! -f "${SCRIPT_DIR}/pyproject.toml" ]; then
        error "pyproject.toml not found in ${SCRIPT_DIR}. Run install.sh from the repo root."
        exit 1
    fi
    DEV_TARGET="${SCRIPT_DIR}${EXTRAS:+${EXTRAS}}"
    if command -v pipx &>/dev/null; then
        warn "Dev mode uses pip, not pipx. Falling back to pip."
    fi
    "$PYTHON" -m pip install --quiet --upgrade pip
    "$PYTHON" -m pip install --quiet -e "${DEV_TARGET}[dev]"
    success "Editable dev install complete."
    echo ""
    echo -e "  Run ${BOLD}sift --help${RESET} to get started."
    exit 0
fi

# ─── 4. Normal install — prefer pipx, fall back to pip ─────────────────────────
INSTALL_TARGET="${PACKAGE_NAME}${EXTRAS}"

if command -v pipx &>/dev/null; then
    info "pipx detected — installing with pipx (recommended)."
    info "Target: ${INSTALL_TARGET}"
    pipx install "${INSTALL_TARGET}"
else
    warn "pipx not found. Falling back to: pip install --user"
    warn "Consider installing pipx for isolated installs:"
    warn "  sudo apt install pipx   (Kali / Debian)"
    warn "  brew install pipx       (macOS)"
    echo ""
    info "Target: ${INSTALL_TARGET}"
    "$PYTHON" -m pip install --quiet --user "${INSTALL_TARGET}"
fi

# ─── 5. PATH check — common issue on Kali ──────────────────────────────────────
LOCAL_BIN="${HOME}/.local/bin"
if [[ ":${PATH}:" != *":${LOCAL_BIN}:"* ]]; then
    echo ""
    warn "~/.local/bin is NOT in your PATH."
    warn "sift was installed there but won't be found without it."
    echo ""
    echo "  Add this to your ~/.bashrc or ~/.zshrc:"
    echo ""
    echo -e "    ${BOLD}export PATH=\"\$HOME/.local/bin:\$PATH\"${RESET}"
    echo ""
    echo "  Then reload your shell:"
    echo ""
    echo -e "    ${BOLD}source ~/.bashrc${RESET}   or   ${BOLD}source ~/.zshrc${RESET}"
    echo ""
fi

# ─── 6. Success ────────────────────────────────────────────────────────────────
echo ""
success "sift ${SIFT_VERSION} installed successfully."
echo ""
echo -e "  Get started:  ${BOLD}sift --help${RESET}"
echo -e "  Triage:       ${BOLD}sift triage alerts.json -o rich${RESET}"
echo ""
