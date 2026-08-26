# LinuxGuard Security Model & Trust Boundaries

## Overview

LinuxGuard is designed with security-first principles. As a security monitoring tool operating on host systems, protecting the monitoring infrastructure itself against exploitation is paramount.

## Trust Boundaries

```text
┌─────────────────────────────────────────────────────────────┐
│                     Untrusted Input                         │
│   (Filesystem events, HTTP requests, /proc process info)    │
└──────────────────────────────┬──────────────────────────────┘
                               │ Input Validation / Path Sanitize
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                    LinuxGuard Agent                         │
│   (Local Loopback REST API 127.0.0.1:8080, SQLite WAL,      │
│    Quarantine Vault /var/lib/linuxguard/quarantine)         │
└──────────────────────────────┬──────────────────────────────┘
                               │ Controlled Operations
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                 Linux OS Filesystem & Kernel                │
└─────────────────────────────────────────────────────────────┘
```

## Security Safeguards

### 1. Loopback Binding & API Restrictions
- By default, the REST API and WebSocket server bind exclusively to `127.0.0.1:8080`.
- External remote access should only be enabled via an authenticated reverse proxy (e.g. Nginx with TLS and Auth).

### 2. Path Traversal & Symlink Safety
- **Path Sanitization**: All user-supplied file paths in API requests are normalized using `filepath.Abs` and validated to prevent directory traversal (`../`).
- **Symlink Protection**: Before performing quarantine, scan, or restoration operations, LinuxGuard uses `os.Lstat` to verify that target items are regular files. **LinuxGuard explicitly refuses to follow symlinks** during destructive or quarantine operations to prevent TOCTOU symlink redirection attacks.

### 3. Safe Quarantine Pipeline
- Files moved to quarantine are stored inside `/var/lib/linuxguard/quarantine/` with UUID-based filenames (`q-xxxxxxxx.quarantine`).
- File permissions on quarantined items are locked down to `0400` (read-only owner) to eliminate accidental execution.
- SHA-256 integrity checks are enforced prior to and immediately following file relocation or restoration.

### 4. No Command Execution / Shell Injection
- LinuxGuard **never** uses `exec.Command` with user-supplied strings or constructs shell commands dynamically from input.
- System metrics and file operations rely directly on native Go system calls and standard library APIs.

### 5. Systemd Hardening
The provided `linuxguard.service` file includes Linux security isolation directives:
- `NoNewPrivileges=true`
- `PrivateTmp=true`
- `ProtectSystem=full`
- `CapabilityBoundingSet=CAP_DAC_READ_SEARCH CAP_SYS_PTRACE CAP_SYS_ADMIN`
