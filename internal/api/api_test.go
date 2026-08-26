package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"linuxguard/internal/database"
	"linuxguard/internal/events"
	"linuxguard/internal/filesystem"
	"linuxguard/internal/quarantine"
)

func TestAPIHandlers(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "api_test.db")
	qDir := filepath.Join(tempDir, "quarantine")

	db, err := database.Open(dbPath)
	if err != nil {
		t.Fatalf("Failed opening DB: %v", err)
	}
	defer db.Close()

	em := events.NewManager()
	qMgr, _ := quarantine.NewManager(qDir, db, em)
	scanner := filesystem.NewScanner([]string{tempDir}, nil)
	baseEng := filesystem.NewBaselineEngine(scanner, db, em)

	deps := &ServerDependencies{
		DB:                db,
		EventManager:      em,
		QuarantineManager: qMgr,
		BaselineEngine:    baseEng,
		Scanner:           scanner,
	}

	// 1. Test /api/health
	req := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	w := httptest.NewRecorder()
	handleHealth(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusOK {
		t.Errorf("Expected 200 OK from /api/health, got %d", res.StatusCode)
	}

	// 2. Test /api/events
	reqEvts := httptest.NewRequest(http.MethodGet, "/api/events", nil)
	wEvts := httptest.NewRecorder()
	handleGetEvents(deps)(wEvts, reqEvts)

	if wEvts.Result().StatusCode != http.StatusOK {
		t.Errorf("Expected 200 OK from /api/events, got %d", wEvts.Result().StatusCode)
	}

	var apiResp APIResponse
	_ = json.NewDecoder(wEvts.Body).Decode(&apiResp)
	if !apiResp.Success {
		t.Errorf("API response indicated failure: %+v", apiResp)
	}
}
