package filesystem

import (
	"os"
	"path/filepath"
	"testing"

	"linuxguard/internal/database"
	"linuxguard/internal/events"
)

func TestBaselineEngine(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "baseline_test.db")
	monitoredDir := filepath.Join(tempDir, "monitored")

	if err := os.MkdirAll(monitoredDir, 0755); err != nil {
		t.Fatalf("Failed creating dir: %v", err)
	}

	file1 := filepath.Join(monitoredDir, "file1.txt")
	if err := os.WriteFile(file1, []byte("version1"), 0644); err != nil {
		t.Fatalf("Failed writing file1: %v", err)
	}

	db, err := database.Open(dbPath)
	if err != nil {
		t.Fatalf("Failed opening DB: %v", err)
	}
	defer db.Close()

	em := events.NewManager()
	scanner := NewScanner([]string{monitoredDir}, nil)
	engine := NewBaselineEngine(scanner, db, em)

	// 1. Create Baseline
	count, err := engine.CreateBaseline()
	if err != nil {
		t.Fatalf("Failed creating baseline: %v", err)
	}
	if count != 1 {
		t.Fatalf("Expected 1 baseline file, got %d", count)
	}

	// 2. Modify file1 & add file2
	if err := os.WriteFile(file1, []byte("version2_modified"), 0644); err != nil {
		t.Fatalf("Failed modifying file1: %v", err)
	}

	file2 := filepath.Join(monitoredDir, "file2.txt")
	if err := os.WriteFile(file2, []byte("newfile"), 0644); err != nil {
		t.Fatalf("Failed creating file2: %v", err)
	}

	// 3. Check Baseline
	diff, err := engine.CheckBaseline()
	if err != nil {
		t.Fatalf("Failed checking baseline: %v", err)
	}

	if len(diff.NewFiles) != 1 || diff.NewFiles[0] != file2 {
		t.Errorf("Expected file2 in NewFiles, got %v", diff.NewFiles)
	}
	if len(diff.ModifiedFiles) != 1 || diff.ModifiedFiles[0] != file1 {
		t.Errorf("Expected file1 in ModifiedFiles, got %v", diff.ModifiedFiles)
	}
}
