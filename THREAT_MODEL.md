# LinuxGuard Threat Model

This document outlines the threat model, attack vectors, detection mechanisms, and mitigations for LinuxGuard.

## Threat Matrix

| Threat ID | Threat Name | Impact | Detection Mechanism | Mitigation | Limitations |
|---|---|---|---|---|---|
| **T1** | Malicious File Creation | High | `fsnotify` directory watcher detects file creation in monitored paths | Event recorded, SHA-256 computed, evaluated by Detection Engine | Unmonitored paths won't generate events |
| **T2** | Sensitive File Modification | High | Baseline comparison & `fsnotify` `WRITE`/`CHMOD` on `/etc/passwd`, `/etc/sudoers` | Trigger `SensitiveFileModificationRule` (+50 score, MEDIUM/HIGH alert) | Real-time mitigation depends on user review |
| **T3** | Suspicious Executable | High | `SuspiciousTmpExecutableRule` & `HiddenExecutableRule` | Flags executables in `/tmp`, `/var/tmp`, `/dev/shm` or starting with `.` | Heuristic scoring may require rule customization |
| **T4** | Persistence Mechanism | High | Monitoring `/etc/crontab`, `/etc/cron.*`, `/etc/systemd/system` | Generates critical events on modification or file creation | Does not inspect user-level crontabs unless configured |
| **T5** | Malicious Process | High | Process monitor `/proc` diffing new PIDs | Emits `PROCESS_STARTED` events and flags processes run from `/tmp` or by root from unusual locations | MVP monitors rather than automatically terminating processes |
| **T6** | REST API Abuse | Medium | API bound to `127.0.0.1` by default, request validation | Restricted to local loopback interface | If bound to public IP without reverse proxy/TLS, remote unauthorized access is possible |
| **T7** | Path Traversal | Critical | `filepath.Abs` validation and prefix checking in Quarantine API | Rejects paths outside designated quarantine or target boundaries | None |
| **T8** | Symlink Attack | High | `os.Lstat` checking for `os.ModeSymlink` prior to scanning or quarantine | Refuses to follow or quarantine symlinks | Target pointed to by symlinks must be inspected directly |
| **T9** | Quarantine Escape | High | Destination hash verification on restore & permission restriction (`0400`) | Files stored in `/var/lib/linuxguard/quarantine` stripped of execution bits | Attacker with root privileges could manually override file permissions |
| **T10** | Agent Tampering | Critical | Service restart on failure in systemd unit file | `Restart=on-failure` & `RestartSec=5s` | Root attacker can stop systemd service (`systemctl stop linuxguard`) |
