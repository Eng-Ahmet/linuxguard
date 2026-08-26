#!/usr/bin/env bash
set -euo pipefail

echo "=========================================="
echo "      LinuxGuard Uninstaller Script       "
echo "=========================================="

if [ "$EUID" -ne 0 ]; then
  echo "[-] Error: Please run uninstall.sh as root (sudo ./scripts/uninstall.sh)."
  exit 1
fi

echo "[+] Stopping systemd service..."
systemctl stop linuxguard.service 2>/dev/null || true
systemctl disable linuxguard.service 2>/dev/null || true

echo "[+] Removing systemd unit..."
rm -f /etc/systemd/system/linuxguard.service
systemctl daemon-reload

echo "[+] Removing binary..."
rm -f /usr/local/bin/linuxguard

echo "[!] Note: Configuration (/etc/linuxguard) and data (/var/lib/linuxguard) were kept for safety."
echo "    To completely wipe data, execute: rm -rf /etc/linuxguard /var/lib/linuxguard /var/log/linuxguard"

echo "[+] LinuxGuard successfully uninstalled."
