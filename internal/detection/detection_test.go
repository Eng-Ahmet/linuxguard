package detection

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"linuxguard/internal/events"
)

func TestDetectionRulesAndScoring(t *testing.T) {
	tempDir := t.TempDir()

	// 1. Create a suspicious executable in tempDir (simulating /tmp)
	suspiciousFile := filepath.Join(tempDir, "suspicious.sh")
	if err := os.WriteFile(suspiciousFile, []byte("#!/bin/bash\necho hack"), 0755); err != nil {
		t.Fatalf("Failed writing suspicious file: %v", err)
	}

	engine := NewEngine(true, nil, nil)

	event := events.SecurityEvent{
		ID:        "evt-test-1",
		Type:      events.TypeFileCreated,
		Path:      suspiciousFile,
		User:      "root",
		Timestamp: time.Now(),
	}

	score, severity, reasons := engine.Evaluate(event)

	if score == 0 {
		t.Errorf("Expected non-zero score for root suspicious executable, got 0")
	}
	if severity == events.SeverityInfo {
		t.Errorf("Expected elevated severity, got %s", severity)
	}
	if len(reasons) == 0 {
		t.Errorf("Expected reasons to be populated")
	}

	t.Logf("Evaluated event score=%d, severity=%s, reasons=%v", score, severity, reasons)
}
