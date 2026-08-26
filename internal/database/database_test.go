package database

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"linuxguard/internal/events"
)

func TestDatabaseOperations(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")

	db, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	// 1. Test Event insertion & retrieval
	event := events.SecurityEvent{
		ID:          "evt-123",
		Type:        events.TypeFileCreated,
		Severity:    events.SeverityHigh,
		Score:       75,
		Path:        "/tmp/suspicious.sh",
		Description: "Suspicious executable file created in /tmp",
		Reasons:     []string{"Executable in /tmp", "Suspicious extension"},
		Timestamp:   time.Now().Truncate(time.Second),
	}

	if err := db.InsertEvent(event); err != nil {
		t.Fatalf("Failed to insert event: %v", err)
	}

	evts, err := db.GetEvents(10)
	if err != nil {
		t.Fatalf("Failed to get events: %v", err)
	}
	if len(evts) != 1 {
		t.Fatalf("Expected 1 event, got %d", len(evts))
	}
	if evts[0].ID != "evt-123" || evts[0].Score != 75 {
		t.Errorf("Event data mismatch: %+v", evts[0])
	}

	// 2. Test Baseline operations
	baseRec := BaselineRecord{
		Path:        "/etc/passwd",
		SHA256:      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		Permissions: "-rw-r--r--",
		Size:        1024,
		Owner:       "root",
		Group:       "root",
		UpdatedAt:   time.Now(),
	}

	if err := db.SaveBaselineRecord(baseRec); err != nil {
		t.Fatalf("Failed to save baseline record: %v", err)
	}

	records, err := db.GetBaselineRecords()
	if err != nil {
		t.Fatalf("Failed to get baseline records: %v", err)
	}
	if rec, exists := records["/etc/passwd"]; !exists || rec.SHA256 != baseRec.SHA256 {
		t.Errorf("Baseline record mismatch: %+v", rec)
	}

	// 3. Test Quarantine operations
	qRec := QuarantineRecord{
		ID:             "q-001",
		OriginalPath:   "/tmp/bad.sh",
		QuarantinePath: filepath.Join(tempDir, "q-001"),
		SHA256:         "dummyhash",
		Size:           512,
		Reason:         "Malware risk",
		Score:          90,
		CreatedAt:      time.Now(),
		Status:         "QUARANTINED",
	}

	if err := db.SaveQuarantineRecord(qRec); err != nil {
		t.Fatalf("Failed to save quarantine record: %v", err)
	}

	item, err := db.GetQuarantineItem("q-001")
	if err != nil || item == nil {
		t.Fatalf("Failed to get quarantine item: %v", err)
	}
	if item.Status != "QUARANTINED" {
		t.Errorf("Expected QUARANTINED status, got %s", item.Status)
	}

	if err := db.UpdateQuarantineStatus("q-001", "RESTORED"); err != nil {
		t.Fatalf("Failed to update quarantine status: %v", err)
	}

	itemUpdated, _ := db.GetQuarantineItem("q-001")
	if itemUpdated.Status != "RESTORED" {
		t.Errorf("Expected RESTORED status, got %s", itemUpdated.Status)
	}

	// Ensure DB file exists on disk
	if _, err := os.Stat(dbPath); err != nil {
		t.Errorf("DB file missing on disk: %v", err)
	}
}
