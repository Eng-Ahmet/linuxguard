#!/usr/bin/env bash
set -euo pipefail

echo "=========================================="
echo "      LinuxGuard Installer Script         "
echo "=========================================="

if [ "$EUID" -ne 0 ]; then
  echo "[-] Error: Please run install.sh as root (sudo ./scripts/install.sh)."
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "[+] Building LinuxGuard binary..."
export PATH=$PATH:/home/ahmet/.local/go/bin:/usr/local/go/bin
cd "${PROJECT_DIR}"
go build -o /tmp/linuxguard ./cmd/linuxguard

echo "[+] Installing binary to /usr/local/bin/linuxguard..."
install -m 0755 /tmp/linuxguard /usr/local/bin/linuxguard
rm -f /tmp/linuxguard

echo "[+] Creating LinuxGuard directories..."
mkdir -p /etc/linuxguard
mkdir -p /var/lib/linuxguard/quarantine
mkdir -p /var/log/linuxguard

chmod 0750 /etc/linuxguard
chmod 0700 /var/lib/linuxguard/quarantine
chmod 0750 /var/log/linuxguard

if [ ! -f /etc/linuxguard/config.yaml ]; then
  echo "[+] Installing default configuration to /etc/linuxguard/config.yaml..."
  cp "${PROJECT_DIR}/configs/linuxguard.example.yaml" /etc/linuxguard/config.yaml
  chmod 0640 /etc/linuxguard/config.yaml
fi

echo "[+] Installing systemd service..."
cp "${PROJECT_DIR}/deploy/linuxguard.service" /etc/systemd/system/linuxguard.service
chmod 0644 /etc/systemd/system/linuxguard.service

echo "[+] Reloading systemd daemon..."
systemctl daemon-reload

echo "[+] Enabling and starting linuxguard service..."
systemctl enable linuxguard.service
systemctl restart linuxguard.service

echo "=========================================="
echo "[+] LinuxGuard successfully installed & started!"
echo "[+] Web Dashboard running at http://127.0.0.1:8080"
echo "=========================================="
