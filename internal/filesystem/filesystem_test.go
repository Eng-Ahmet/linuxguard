package filesystem

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"linuxguard/internal/events"
)

func TestCalculateSHA256(t *testing.T) {
	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "sample.txt")

	content := []byte("LinuxGuard Security Test File\n")
	if err := os.WriteFile(testFile, content, 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	hash, err := CalculateSHA256(testFile)
	if err != nil {
		t.Fatalf("Failed to hash file: %v", err)
	}

	// SHA256 of "LinuxGuard Security Test File\n" is known
	if hash == "" || len(hash) != 64 {
		t.Fatalf("Invalid SHA256 string produced: %s", hash)
	}

	meta, err := GetFileMetadata(testFile)
	if err != nil {
		t.Fatalf("Failed to get file metadata: %v", err)
	}

	if meta.Size != int64(len(content)) {
		t.Errorf("Expected size %d, got %d", len(content), meta.Size)
	}
	if meta.SHA256 != hash {
		t.Errorf("Metadata hash mismatch: %s vs %s", meta.SHA256, hash)
	}
}

func TestFilesystemMonitor(t *testing.T) {
	tempDir := t.TempDir()
	monitoredDir := filepath.Join(tempDir, "monitored")
	if err := os.MkdirAll(monitoredDir, 0755); err != nil {
		t.Fatalf("Failed to create dir: %v", err)
	}

	em := events.NewManager()
	received := make(chan events.SecurityEvent, 10)

	em.Subscribe(func(event events.SecurityEvent) {
		received <- event
	})

	mon, err := NewMonitor([]string{monitoredDir}, []string{}, em)
	if err != nil {
		t.Fatalf("Failed to create monitor: %v", err)
	}

	if err := mon.Start(); err != nil {
		t.Fatalf("Failed to start monitor: %v", err)
	}
	defer mon.Stop()

	// Create test file in monitored dir
	testFilePath := filepath.Join(monitoredDir, "created.txt")
	if err := os.WriteFile(testFilePath, []byte("hello"), 0644); err != nil {
		t.Fatalf("Failed writing file: %v", err)
	}

	select {
	case evt := <-received:
		if evt.Path != testFilePath {
			t.Errorf("Expected path %s, got %s", testFilePath, evt.Path)
		}
		if evt.Type != events.TypeFileCreated && evt.Type != events.TypeFileModified {
			t.Errorf("Unexpected event type: %s", evt.Type)
		}
	case <-time.After(2 * time.Second):
		t.Error("Timed out waiting for filesystem event")
	}
}
