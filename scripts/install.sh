#!/bin/bash
set -e
GREEN='\033[0;32m'; AMBER='\033[0;33m'; NC='\033[0m'; BOLD='\033[1m'
log() { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${AMBER}[!]${NC} $1"; }
section() { echo -e "\n${BOLD}${GREEN}━━━ $1 ━━━${NC}"; }
SUDO=$([[ $EUID -ne 0 ]] && echo "sudo" || echo "")

section "Phase 1 — Device Detection tools"
$SUDO apt-get update -qq
$SUDO apt-get install -y --no-install-recommends udev nmap avrdude python3 python3-pip git curl jq redis-server 2>/dev/null || warn "Some packages failed"

section "Phase 2 — Firmware Extraction tools"
$SUDO apt-get install -y --no-install-recommends binwalk mtd-utils libguestfs-tools device-tree-compiler u-boot-tools p7zip-full squashfs-tools 2>/dev/null || warn "Some packages failed"

section "Phase 3 — Static Analysis tools"
$SUDO apt-get install -y --no-install-recommends checksec john john-data openssl shellcheck ssdeep python3-bandit 2>/dev/null || warn "Some packages failed"

section "Python backend packages"
pip3 install --break-system-packages -q fastapi uvicorn[standard] websockets python-multipart pyserial pyusb requests python-dotenv celery redis sqlalchemy alembic python-jose passlib cyclonedx-bom reportlab bandit httpx pytest

section "unblob"
pip3 install --break-system-packages -q unblob 2>/dev/null || warn "unblob failed — try manually"

section "Node.js (Frontend)"
if ! command -v node &>/dev/null; then
  curl -fsSL https://deb.nodesource.com/setup_20.x | $SUDO bash - && $SUDO apt-get install -y nodejs
fi
log "Node: $(node --version) | npm: $(npm --version)"

section "Frontend npm install"
cd /home/naji/IIFVDCAS/frontend && npm install --silent && cd -

section "dialout group"
$SUDO usermod -aG dialout $USER 2>/dev/null && warn "Log out and back in for dialout group to take effect"

echo -e "\n${GREEN}${BOLD}Done! Run: ./scripts/dev.sh${NC}"
