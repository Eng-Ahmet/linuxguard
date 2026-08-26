package events

import (
	"time"
)

const (
	TypeFileCreated          = "FILE_CREATED"
	TypeFileModified         = "FILE_MODIFIED"
	TypeFileDeleted          = "FILE_DELETED"
	TypeFileRenamed          = "FILE_RENAMED"
	TypeFilePermissionChange = "FILE_PERMISSION_CHANGED"
	TypeProcessStarted       = "PROCESS_STARTED"
	TypeBaselineChanged      = "BASELINE_CHANGED"
	TypeThreatDetected       = "THREAT_DETECTED"
	TypeQuarantineCreated    = "QUARANTINE_CREATED"
	TypeQuarantineRestored   = "QUARANTINE_RESTORED"
	TypeQuarantineDeleted    = "QUARANTINE_DELETED"
)

const (
	SeverityInfo     = "INFO"
	SeverityLow      = "LOW"
	SeverityMedium   = "MEDIUM"
	SeverityHigh     = "HIGH"
	SeverityCritical = "CRITICAL"
)

type SecurityEvent struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"`
	Severity    string    `json:"severity"`
	Score       int       `json:"score"`
	Path        string    `json:"path,omitempty"`
	PID         int       `json:"pid,omitempty"`
	Process     string    `json:"process,omitempty"`
	User        string    `json:"user,omitempty"`
	Description string    `json:"description"`
	Reasons     []string  `json:"reasons,omitempty"`
	Timestamp   time.Time `json:"timestamp"`
}
