#!/usr/bin/env bash
# CyberPartha BOT v3 — One-Command Safe Installation Script
# Operating System: Kali Linux on WSL2 / Debian-based Linux

set -euo pipefail

echo "================================================================================"
echo "                   CyberPartha BOT v3 — Installation Script                     "
echo "================================================================================"

# 1. Environment Detection
if ! grep -qi "microsoft\|wsl" /proc/version 2>/dev/null && [ ! -f /etc/debian_version ]; then
    echo "[!] Warning: Designed for Kali Linux on WSL2. Continuing..."
fi

# 2. Check Python 3
if ! command -v python3 &>/dev/null; then
    echo "[!] Error: python3 is required. Please install python3."
    exit 1
fi

PY_VER=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
echo "[+] Detected Python version: $PY_VER"

# 3. Create Timestamped Backup of Existing Project State
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
BACKUP_DIR="${HOME:?}/CyberPartha-BOT-backup-$TIMESTAMP"
echo "[+] Creating backup at: $BACKUP_DIR"
mkdir -p "$BACKUP_DIR"

if [ -d "programs" ]; then cp -r programs "$BACKUP_DIR/" 2>/dev/null || true; fi
if [ -d "state" ]; then cp -r state "$BACKUP_DIR/" 2>/dev/null || true; fi
if [ -d "reports" ]; then cp -r reports "$BACKUP_DIR/" 2>/dev/null || true; fi
if [ -d "logs" ]; then cp -r logs "$BACKUP_DIR/" 2>/dev/null || true; fi
echo "[+] Backup completed successfully."

# 4. Initialize / Activate .venv
if [ ! -d ".venv" ]; then
    echo "[+] Creating virtual environment (.venv)..."
    python3 -m venv .venv
fi

echo "[+] Activating .venv..."
source .venv/bin/activate

# 5. Install Dependencies
echo "[+] Installing dependencies from requirements.txt..."
python3 -m pip install --quiet --upgrade pip
python3 -m pip install --quiet -r requirements.txt

# 6. Run Automated QA Tests
echo "[+] Running verification test suite..."
python3 -m unittest discover -s tests -p 'test_*.py' -v

echo "================================================================================"
echo "       CyberPartha BOT v3 installed and verified successfully! (ALL TESTS PASS)"
echo "================================================================================"
