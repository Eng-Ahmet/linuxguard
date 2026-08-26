package agent

import (
	"path/filepath"
	"testing"
	"time"

	"linuxguard/internal/config"
)

func TestAgentStartStop(t *testing.T) {
	tempDir := t.TempDir()

	cfg := &config.Config{
		Server: config.ServerConfig{
			Host: "127.0.0.1",
			Port: 8089,
		},
		Database: config.DatabaseConfig{
			Path: filepath.Join(tempDir, "agent_test.db"),
		},
		Monitoring: config.MonitoringConfig{
			Paths:         []string{tempDir},
			ExcludedPaths: []string{},
		},
		ProcessMonitor: config.ProcessMonitorConfig{
			Enabled:         true,
			IntervalSeconds: 1,
		},
		Quarantine: config.QuarantineConfig{
			Enabled: true,
			Path:    filepath.Join(tempDir, "quarantine"),
		},
		Detection: config.DetectionConfig{
			Enabled: true,
		},
	}

	ag, err := NewAgent(cfg)
	if err != nil {
		t.Fatalf("Failed creating agent: %v", err)
	}

	if err := ag.Start(); err != nil {
		t.Fatalf("Failed starting agent: %v", err)
	}

	time.Sleep(100 * time.Millisecond)

	ag.Stop()
}
