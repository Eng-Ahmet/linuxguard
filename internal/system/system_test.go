package system

import (
	"testing"
)

func TestSystemInfo(t *testing.T) {
	info := GetSystemInfo()
	if info == nil {
		t.Fatalf("Expected non-nil SystemInfo")
	}

	if info.OS == "" || info.Arch == "" {
		t.Errorf("SystemInfo missing OS or Arch: %+v", info)
	}

	if info.CPUs <= 0 {
		t.Errorf("Expected CPUs > 0, got %d", info.CPUs)
	}

	uptime := GetAgentUptime()
	if uptime < 0 {
		t.Errorf("Expected uptime >= 0, got %v", uptime)
	}
}
