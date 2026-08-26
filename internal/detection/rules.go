package detection

import (
	"os"
	"path/filepath"
	"strings"

	"linuxguard/internal/events"
)

// 1. SuspiciousTmpExecutableRule
type SuspiciousTmpExecutableRule struct{}

func (r *SuspiciousTmpExecutableRule) Name() string { return "SuspiciousTmpExecutable" }

func (r *SuspiciousTmpExecutableRule) Evaluate(event events.SecurityEvent) *Finding {
	if event.Path == "" {
		return nil
	}

	cleanPath := filepath.Clean(event.Path)
	inTmp := strings.HasPrefix(cleanPath, "/tmp") || strings.HasPrefix(cleanPath, "/var/tmp") || strings.HasPrefix(cleanPath, "/dev/shm")
	if !inTmp {
		return nil
	}

	// Check if executable or executable extension
	stat, err := os.Lstat(cleanPath)
	isExecutable := false
	if err == nil && (stat.Mode()&0111 != 0) {
		isExecutable = true
	}

	ext := strings.ToLower(filepath.Ext(cleanPath))
	suspiciousExt := ext == ".sh" || ext == ".bin" || ext == ".elf" || ext == ".py" || ext == ".pl" || ext == ".so"

	if isExecutable || suspiciousExt || event.Type == events.TypeProcessStarted {
		return &Finding{
			RuleName: r.Name(),
			Score:    40,
			Reason:   "Executable file created/launched inside temporary directory (" + cleanPath + ")",
		}
	}

	return nil
}

// 2. SensitiveFileModificationRule
type SensitiveFileModificationRule struct{}

func (r *SensitiveFileModificationRule) Name() string { return "SensitiveFileModification" }

func (r *SensitiveFileModificationRule) Evaluate(event events.SecurityEvent) *Finding {
	if event.Path == "" {
		return nil
	}

	cleanPath := filepath.Clean(event.Path)
	sensitiveFiles := []string{
		"/etc/passwd",
		"/etc/shadow",
		"/etc/sudoers",
		"/etc/crontab",
		"/etc/ssh/sshd_config",
		"/etc/hosts",
		"/etc/pam.d/common-auth",
	}

	for _, s := range sensitiveFiles {
		if cleanPath == s || strings.HasPrefix(cleanPath, "/etc/cron.") || strings.HasPrefix(cleanPath, "/etc/sudoers.d/") {
			if event.Type == events.TypeFileModified || event.Type == events.TypeFileCreated || event.Type == events.TypeFileDeleted || event.Type == events.TypeFilePermissionChange {
				return &Finding{
					RuleName: r.Name(),
					Score:    50,
					Reason:   "Modification of critical system security file (" + cleanPath + ")",
				}
			}
		}
	}
	return nil
}

// 3. HiddenExecutableRule
type HiddenExecutableRule struct{}

func (r *HiddenExecutableRule) Name() string { return "HiddenExecutable" }

func (r *HiddenExecutableRule) Evaluate(event events.SecurityEvent) *Finding {
	if event.Path == "" {
		return nil
	}

	base := filepath.Base(event.Path)
	if strings.HasPrefix(base, ".") && base != "." && base != ".." {
		stat, err := os.Lstat(event.Path)
		if err == nil && (stat.Mode()&0111 != 0) {
			return &Finding{
				RuleName: r.Name(),
				Score:    35,
				Reason:   "Hidden executable file detected (" + event.Path + ")",
			}
		}
	}
	return nil
}

// 4. RootUnusualExecutableRule
type RootUnusualExecutableRule struct{}

func (r *RootUnusualExecutableRule) Name() string { return "RootUnusualExecutable" }

func (r *RootUnusualExecutableRule) Evaluate(event events.SecurityEvent) *Finding {
	if event.User == "root" || event.User == "0" {
		cleanPath := filepath.Clean(event.Path)
		if strings.HasPrefix(cleanPath, "/tmp") || strings.HasPrefix(cleanPath, "/var/tmp") || strings.HasPrefix(cleanPath, "/dev/shm") || strings.HasPrefix(cleanPath, "/home") {
			return &Finding{
				RuleName: r.Name(),
				Score:    45,
				Reason:   "Root action/process running from unusual location (" + cleanPath + ")",
			}
		}
	}
	return nil
}

// 5. SuspiciousPermissionRule
type SuspiciousPermissionRule struct{}

func (r *SuspiciousPermissionRule) Name() string { return "SuspiciousPermission" }

func (r *SuspiciousPermissionRule) Evaluate(event events.SecurityEvent) *Finding {
	if event.Path == "" {
		return nil
	}

	stat, err := os.Lstat(event.Path)
	if err == nil {
		mode := stat.Mode()
		// Check for world-writable executable (0777) or SUID/SGID bits
		if (mode&0777 == 0777) || (mode&os.ModeSetuid != 0) || (mode&os.ModeSetgid != 0) {
			return &Finding{
				RuleName: r.Name(),
				Score:    30,
				Reason:   "File set with elevated/dangerous permissions or SUID/SGID bit (" + event.Path + ")",
			}
		}
	}
	return nil
}
