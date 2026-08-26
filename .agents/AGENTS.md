# LinuxGuard Project Code Structure & Architectural Guide

This document serves as the master guide for developers and agents working on **LinuxGuard**.

---

## 1. Directory & Package Responsibility Map

```text
linuxguard/
├── cmd/
│   └── linuxguard/
│       └── main.go               # CLI entrypoint and subcommand dispatcher
│
├── internal/
│   ├── agent/
│   │   ├── agent.go              # Central Orchestrator managing subsystem lifetimes
│   │   └── agent_test.go         # Agent startup & clean teardown tests
│   │
│   ├── config/
│   │   ├── config.go             # YAML configuration parser with dev/prod fallbacks
│   │   └── config_test.go        # Configuration unit tests
│   │
│   ├── database/
│   │   ├── database.go           # Thread-safe SQLite WAL interface & CRUD operations
│   │   ├── migrations.go         # Schema migrations for events, baseline, quarantine
│   │   └── database_test.go      # DB unit tests (SQLite WAL & table queries)
│   │
│   ├── events/
│   │   ├── event.go              # SecurityEvent model definitions & severity constants
│   │   ├── manager.go            # Thread-safe pub/sub EventManager
│   │   └── events_test.go       # Event manager pub/sub unit tests
│   │
│   ├── filesystem/
│   │   ├── monitor.go            # Bounded fsnotify watcher with recursive folder discovery
│   │   ├── scanner.go            # Directory walker with depth limit & symlink guards
│   │   ├── hash.go               # Streaming SHA-256 calculator & file metadata extractor
│   │   ├── baseline.go           # Baseline snapshot creation & comparison engine
│   │   ├── filesystem_test.go    # Hashing & fsnotify watcher tests
│   │   └── baseline_test.go      # Baseline create & drift comparison tests
│   │
│   ├── processes/
│   │   ├── process.go            # /proc process reader & ProcessInfo data structures
│   │   ├── monitor.go            # Periodic PID snapshot polling & diffing engine
│   │   └── processes_test.go     # Process monitor unit tests
│   │
│   ├── detection/
│   │   ├── scoring.go            # Finding struct, Rule interface, & severity mapping
│   │   ├── rules.go              # Modular security rules (TmpExec, SensitiveFile, etc.)
│   │   ├── engine.go             # Detection Engine accumulator & DB persistence
│   │   └── detection_test.go     # Detection rules & scoring unit tests
│   │
│   ├── quarantine/
│   │   ├── manager.go            # Hardened quarantine isolation, restore & delete pipeline
│   │   └── manager_test.go       # Quarantine pipeline integrity & path traversal tests
│   │
│   ├── system/
│   │   ├── system.go             # Host OS, CPU, memory & uptime metrics reader
│   │   └── system_test.go        # System metrics unit tests
│   │
│   └── api/
│       ├── server.go             # HTTP server with embedded web FS (//go:embed web/*)
│       ├── handlers.go           # REST API handlers (/api/health, /api/events, etc.)
│       ├── websocket.go          # WebSocket Hub broadcasting events to dashboard
│       ├── api_test.go           # REST API unit tests
│       └── web/                  # HTML5/CSS3/Vanilla JS Dark Dashboard source
│           ├── index.html
│           ├── css/style.css
│           └── js/app.js
│
├── configs/
│   └── linuxguard.example.yaml   # Production YAML configuration template
├── deploy/
│   └── linuxguard.service        # Hardened systemd service unit file
└── scripts/
    ├── install.sh                # Production installation script for Ubuntu
    └── uninstall.sh              # Uninstallation script
```

---

## 2. Core Architectural Principles

1. **Separation of Concerns**: The filesystem watcher and process scanner **only observe**. The `DetectionEngine` evaluates and scores events. The `QuarantineManager` isolates threat targets.
2. **Path Traversal & Symlink Protection**:
   - `filepath.Abs` is applied to all incoming paths.
   - `os.Lstat` is used to check `os.ModeSymlink`. Symlinks are strictly **not followed** during quarantine or baseline operations.
3. **CGO-Free SQLite**:
   - Built using `modernc.org/sqlite` so LinuxGuard compiles cleanly across architectures without external C toolchain dependencies.
4. **Race-Condition Safety**:
   - All shared state is protected with `sync.RWMutex`.
   - All tests run with `go test -v -race ./...`.
