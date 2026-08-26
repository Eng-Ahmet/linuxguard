# LinuxGuard — Lightweight Linux Security Monitor

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Go Version](https://img.shields.io/badge/Go-1.23%20%7C%201.25%20%7C%201.26-00ADD8.svg)](https://golang.org/)

> **Disclaimer**: LinuxGuard is a host-based security monitoring tool, not a replacement for a commercial antivirus, EDR, firewall, or SIEM.

LinuxGuard is a lightweight, modular, host-based security monitoring agent built in pure Go for Ubuntu/Linux servers. It monitors filesystem integrity, tracks running processes, calculates streaming SHA-256 hashes, scores threats using a modular rule engine, isolates suspicious files in a safe quarantine vault, and serves a modern dark-themed Web Dashboard with real-time WebSocket event feeds.

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

## Key Features

* **Event-Driven Filesystem Monitoring**: Monitors `CREATE`, `WRITE`, `REMOVE`, `RENAME`, and `CHMOD` filesystem events using `fsnotify` with bounded directory watching and symlink protection.
* **Streaming SHA-256 Hashing**: Calculates file hashes using memory-efficient streaming without loading entire files into memory.
* **Integrity Baseline**: Baseline snapshot creation (`linuxguard baseline create`) and integrity drift checking (`linuxguard baseline check`) detecting modified, new, deleted, or re-permissioned system files.
* **Lightweight Process Monitoring**: Snapshot collector inspecting `/proc` PIDs, command lines, users, execution paths, and parent PIDs to emit `PROCESS_STARTED` events.
* **Rule-Based Threat Scoring**: Modular detection rules (`SuspiciousTmpExecutableRule`, `SensitiveFileModificationRule`, `HiddenExecutableRule`, `RootUnusualExecutableRule`, `SuspiciousPermissionRule`) accumulating threat scores (`0-100`) and categorizing risk levels (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
* **Hardened Quarantine Pipeline**: Secure file isolation pipeline validating paths, stripping permissions (`0400`), enforcing SHA-256 checksum verification on isolate/restore operations, and guarding against symlink/path traversal attacks.
* **Real-Time Web Dashboard**: Built-in dark-mode HTML/CSS/Vanilla JS interface served directly by Go (`//go:embed`) with live WebSocket event streaming (`/ws/events`).
* **Persistent SQLite Storage**: Embedded WAL-mode SQLite database (`modernc.org/sqlite`) for persistent security logs and quarantine metadata.
* **Production Ready**: Linux `systemd` integration with hardening directives, non-root local development support, and an automated installer/uninstaller script suite.

---

## Architecture Overview

```text
Linux Kernel / OS
 │
 ├── File Events (fsnotify) ─────┐
 │                               │
 └── Process Snapshots (/proc) ──┴──> Event Manager (PubSub)
                                           │
                                           ▼
                                    Detection Engine
                                           │
                           ┌───────────────┴───────────────┐
                           ▼                               ▼
                    SQLite Database                 Threat Event
                           │                               │
                   ┌───────┴───────┐               ┌───────┴───────┐
                   ▼               ▼               ▼               ▼
               REST API       Baseline Check   Dashboard (WS)  Quarantine Vault
```

---

## File & Package Responsibilities

```text
linuxguard/
├── cmd/linuxguard/main.go        # CLI Entry point & subcommand handler
├── internal/
│   ├── agent/agent.go            # Agent Central Orchestrator & Signal Handler
│   ├── config/config.go          # YAML Configuration parser with safe fallbacks
│   ├── database/database.go      # SQLite WAL Connection & Table CRUD operations
│   ├── events/manager.go         # Thread-safe pub/sub Event Manager
│   ├── filesystem/monitor.go     # fsnotify Directory Watcher & Scanner
│   ├── filesystem/baseline.go    # Baseline snapshot & comparison engine
│   ├── processes/monitor.go      # /proc Process snapshot collector & diff engine
│   ├── detection/engine.go       # Modular Security Rule Engine & Scoring
│   ├── quarantine/manager.go     # Hardened Quarantine isolation vault
│   ├── system/system.go          # Host System Diagnostics (CPU, RAM, Uptime)
│   └── api/server.go             # Embedded Web Server (//go:embed web/*) & WS Hub
```

---

## Quick Production Install (Ubuntu Server)

To build, configure, and install LinuxGuard as a systemd service:

```bash
git clone https://github.com/linuxguard/linuxguard.git
cd linuxguard
sudo ./scripts/install.sh
```

Verify service status:

```bash
systemctl status linuxguard.service
```

Access the local Web Dashboard at **`http://127.0.0.1:8080`**.

### Uninstalling

```bash
sudo ./scripts/uninstall.sh
```

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

## CLI Usage

LinuxGuard includes a powerful CLI utility:

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
