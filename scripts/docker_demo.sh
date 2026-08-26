#!/usr/bin/env bash
set -euo pipefail

echo "=========================================================="
echo "    LinuxGuard Docker Container Deployment & Demo Script  "
echo "=========================================================="

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${PROJECT_DIR}"

echo "[1/4] Building Docker Container Image (linuxguard:latest)..."
docker build -t linuxguard:latest .

echo "[2/4] Stopping any existing demo container..."
docker rm -f linuxguard-demo 2>/dev/null || true

echo "[3/4] Starting LinuxGuard container on free port 9876..."
docker run -d \
  --name linuxguard-demo \
  -p 9876:9876 \
  --pid=host \
  --cap-add=DAC_READ_SEARCH \
  --cap-add=SYS_PTRACE \
  -v "${PROJECT_DIR}/testdata:/app/testdata" \
  -v "${PROJECT_DIR}:/app/data" \
  linuxguard:latest --config /app/configs/linuxguard.example.yaml

echo "[4/4] Waiting 2 seconds for agent initialization..."
sleep 2

# Verify container logs
echo "[+] Docker Container Logs:"
docker logs linuxguard-demo

echo ""
echo "=========================================================="
echo "  SUCCESS! LinuxGuard Container is Active & Protecting    "
echo "=========================================================="
echo ""
echo "  🌐 ACCESS FRONTEND DASHBOARD:"
echo "     Open your browser and navigate to:"
echo "     👉 http://127.0.0.1:9876"
echo "     👉 http://localhost:9876"
echo ""
echo "  🔍 CONTAINER COMMANDS:"
echo "     View container logs  : docker logs -f linuxguard-demo"
echo "     Stop container       : docker stop linuxguard-demo"
echo "     Remove container     : docker rm -f linuxguard-demo"
echo "=========================================================="
