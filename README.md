# LinuxGuard — Lightweight Linux Security Monitor

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Go Version](https://img.shields.io/badge/Go-1.23%20%7C%201.25%20%7C%201.26-00ADD8.svg)](https://golang.org/)
[![Docker Supported](https://img.shields.io/badge/Docker-Supported-blue.svg?logo=docker)](https://www.docker.com/)

> **Disclaimer**: LinuxGuard is a host-based security monitoring tool, not a replacement for a commercial antivirus, EDR, firewall, or SIEM.

LinuxGuard is a lightweight, modular, host-based security monitoring agent built in pure Go for Ubuntu/Linux servers. It monitors filesystem integrity, tracks running processes, calculates streaming SHA-256 hashes, scores threats using a modular rule engine, isolates suspicious files in a safe quarantine vault, and serves a modern dark-themed Web Dashboard with real-time WebSocket event feeds.

---

## 🌐 How to Access the Web Dashboard

Once LinuxGuard is running (natively, via Docker, or via systemd), open your web browser and navigate to:

👉 **`http://127.0.0.1:8080`**  
👉 **`http://localhost:8080`**

### Dashboard Main Sections

1. **Security Overview**: Real-time System Risk Level (`LOW`, `MEDIUM`, `HIGH`), Critical Threat Counter, Recent Activity Table, and Host System Diagnostics.
2. **Security Events Log**: Real-time event stream (`FILE_CREATED`, `FILE_MODIFIED`, `FILE_DELETED`, `PROCESS_STARTED`).
3. **Detected Threats**: Rule-based findings with calculated risk scores and direct **Quarantine Action** buttons.
4. **Active Processes**: Live PID listing with user execution paths and command lines.
5. **Quarantine Vault**: Isolated files table with **Restore** (SHA-256 verified) and **Delete** actions.
6. **System Status**: Host diagnostic details (Hostname, OS Kernel, CPU Cores, Memory Usage, Uptime).

---

## 🐳 Container & Docker Deployment

LinuxGuard fully supports containerized execution while maintaining host-level system security monitoring.

### Option A: Using Docker Demo Script

We provide a dedicated automated script to build, deploy, and verify the containerized agent:

```bash
./scripts/docker_demo.sh
```

Then visit **`http://127.0.0.1:8080`** in your browser.

### Option B: Using Docker Compose

Launch LinuxGuard using `docker-compose` with host-monitoring capabilities enabled:

```bash
# Build and start container
docker-compose up -d

# View container logs
docker-compose logs -f
```

### Host-Level Security Monitoring Flags Explained

To allow LinuxGuard inside Docker to monitor the underlying Linux host system:
* `--pid=host`: Enables container visibility into host system processes (`/proc`).
* `network_mode: "host"`: Binds the API and WebSocket server directly to host port `8080`.
* `cap_add: [SYS_PTRACE, DAC_READ_SEARCH]`: Grants essential process inspection capabilities without requiring uninhibited root container access.

---

## Quick Production Install (Native Ubuntu Systemd)

To build, configure, and install LinuxGuard natively as a systemd service:

```bash
git clone https://github.com/linuxguard/linuxguard.git
cd linuxguard
sudo ./scripts/install.sh
```

Verify service status:

```bash
systemctl status linuxguard.service
```

Access the Web Dashboard at **`http://127.0.0.1:8080`**.

### Uninstalling Native Service

```bash
sudo ./scripts/uninstall.sh
```

---

## Supported Environments & Tested Go Versions

* **Operating System**: Ubuntu 20.04 LTS / 22.04 LTS / 24.04 LTS (x86_64 / amd64)
* **Tested Go Toolchain Versions**:
  - `go1.23.0 linux/amd64`
  - `go1.25.0 linux/amd64`
  - `go1.26.7 linux/amd64`
* **Database**: `modernc.org/sqlite` (100% CGO-Free SQLite WAL implementation)
* **License**: Apache License 2.0 (`LICENSE`)

---

## Local Development & Testing (Zero Root Required)

During development, LinuxGuard runs entirely in user-space using local relative paths (e.g. `./testdata`, `./linuxguard.db`):

```bash
# 1. Build local binary
go build -o linuxguard ./cmd/linuxguard

# 2. Run CLI commands against ./testdata
./linuxguard scan
./linuxguard baseline create
./linuxguard baseline check

# 3. Start local agent daemon
./linuxguard
```

### Running Test Suite

Execute comprehensive unit tests across all packages with race condition detection:

```bash
go test -v -race ./...
gofmt -s -w .
go vet ./...
```

---

## CLI Usage Reference

LinuxGuard includes a CLI utility:

```bash
# Start daemon agent
linuxguard

# Show current agent status & config
linuxguard status

# Execute security scan on monitored paths
linuxguard scan

# Create file integrity baseline
linuxguard baseline create

# Compare filesystem state against baseline
linuxguard baseline check

# Display recent security events log
linuxguard events

# List items in quarantine vault
linuxguard quarantine list

# Print version
linuxguard version
```

---

## REST API Reference

All REST endpoints return standardized JSON structures:

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/health` | Healthcheck and agent identification |
| `GET` | `/api/system` | Host uptime, CPU, memory, hostname diagnostic data |
| `GET` | `/api/events?limit=50` | Query recent security event logs |
| `GET` | `/api/threats?limit=50` | Query detected high-score threat events |
| `GET` | `/api/files` | File catalog metadata scan results |
| `GET` | `/api/processes` | Active system processes snapshot |
| `GET` | `/api/quarantine` | List items in quarantine vault |
| `POST` | `/api/quarantine` | Isolate target file (`{"path": "/tmp/bad.sh"}`) |
| `POST` | `/api/quarantine/:id/restore` | Restore file from quarantine to original path |
| `DELETE` | `/api/quarantine/:id` | Permanently delete quarantined item |
| `POST` | `/api/baseline/create` | Trigger new baseline creation |
| `POST` | `/api/baseline/check` | Execute baseline comparison check |
| `WS` | `/ws/events` | Real-time WebSocket event broadcast stream |
