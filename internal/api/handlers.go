package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"linuxguard/internal/database"
	"linuxguard/internal/events"
	"linuxguard/internal/filesystem"
	"linuxguard/internal/processes"
	"linuxguard/internal/quarantine"
	"linuxguard/internal/system"
)

type APIResponse struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Error   *APIError   `json:"error,omitempty"`
}

type APIError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func sendJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(APIResponse{
		Success: status >= 200 && status < 300,
		Data:    data,
	})
}

func sendError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(APIResponse{
		Success: false,
		Error: &APIError{
			Code:    code,
			Message: message,
		},
	})
}

type ServerDependencies struct {
	DB                *database.DB
	EventManager      *events.Manager
	QuarantineManager *quarantine.Manager
	BaselineEngine    *filesystem.BaselineEngine
	Scanner           *filesystem.Scanner
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	sendJSON(w, http.StatusOK, map[string]string{
		"status": "healthy",
		"agent":  "LinuxGuard Security Agent",
	})
}

func handleSystem(w http.ResponseWriter, r *http.Request) {
	info := system.GetSystemInfo()
	sendJSON(w, http.StatusOK, info)
}

func handleGetEvents(deps *ServerDependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		limitStr := r.URL.Query().Get("limit")
		limit := 100
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}

		evts, err := deps.DB.GetEvents(limit)
		if err != nil {
			sendError(w, http.StatusInternalServerError, "DB_ERROR", err.Error())
			return
		}
		if evts == nil {
			evts = []events.SecurityEvent{}
		}
		sendJSON(w, http.StatusOK, evts)
	}
}

func handleGetThreats(deps *ServerDependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		limitStr := r.URL.Query().Get("limit")
		limit := 50
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}

		threats, err := deps.DB.GetThreats(limit)
		if err != nil {
			sendError(w, http.StatusInternalServerError, "DB_ERROR", err.Error())
			return
		}
		if threats == nil {
			threats = []events.SecurityEvent{}
		}
		sendJSON(w, http.StatusOK, threats)
	}
}

func handleGetProcesses(w http.ResponseWriter, r *http.Request) {
	procs, err := processes.GetRunningProcesses()
	if err != nil {
		sendError(w, http.StatusInternalServerError, "PROCESS_ERROR", err.Error())
		return
	}
	if procs == nil {
		procs = []*processes.ProcessInfo{}
	}
	sendJSON(w, http.StatusOK, procs)
}

func handleGetFiles(deps *ServerDependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		files, err := deps.Scanner.ScanDirectories(1)
		if err != nil {
			sendError(w, http.StatusInternalServerError, "SCANNER_ERROR", err.Error())
			return
		}
		if files == nil {
			files = []*filesystem.FileInfoMetadata{}
		}
		sendJSON(w, http.StatusOK, files)
	}
}

func handleQuarantine(deps *ServerDependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			items, err := deps.DB.GetQuarantineItems()
			if err != nil {
				sendError(w, http.StatusInternalServerError, "DB_ERROR", err.Error())
				return
			}
			if items == nil {
				items = []database.QuarantineRecord{}
			}
			sendJSON(w, http.StatusOK, items)

		case http.MethodPost:
			var req struct {
				Path   string `json:"path"`
				Reason string `json:"reason"`
				Score  int    `json:"score"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Path == "" {
				sendError(w, http.StatusBadRequest, "INVALID_REQUEST", "Path parameter is required")
				return
			}

			if req.Reason == "" {
				req.Reason = "Manual quarantine request via REST API"
			}
			if req.Score == 0 {
				req.Score = 80
			}

			record, err := deps.QuarantineManager.QuarantineFile(req.Path, req.Reason, req.Score)
			if err != nil {
				sendError(w, http.StatusBadRequest, "QUARANTINE_FAILED", err.Error())
				return
			}

			sendJSON(w, http.StatusOK, record)

		default:
			sendError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed")
		}
	}
}

func handleQuarantineActions(deps *ServerDependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/api/quarantine/")
		parts := strings.Split(path, "/")
		if len(parts) == 0 || parts[0] == "" {
			sendError(w, http.StatusBadRequest, "INVALID_ID", "Quarantine ID required")
			return
		}

		qID := parts[0]

		if len(parts) == 2 && parts[1] == "restore" && r.Method == http.MethodPost {
			if err := deps.QuarantineManager.RestoreFile(qID); err != nil {
				sendError(w, http.StatusBadRequest, "RESTORE_FAILED", err.Error())
				return
			}
			sendJSON(w, http.StatusOK, map[string]string{"status": "restored", "id": qID})
			return
		}

		if len(parts) == 1 && r.Method == http.MethodDelete {
			if err := deps.QuarantineManager.DeleteFile(qID); err != nil {
				sendError(w, http.StatusBadRequest, "DELETE_FAILED", err.Error())
				return
			}
			sendJSON(w, http.StatusOK, map[string]string{"status": "deleted", "id": qID})
			return
		}

		sendError(w, http.StatusNotFound, "NOT_FOUND", "Endpoint not found")
	}
}

func handleBaselineCreate(deps *ServerDependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			sendError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "POST required")
			return
		}

		count, err := deps.BaselineEngine.CreateBaseline()
		if err != nil {
			sendError(w, http.StatusInternalServerError, "BASELINE_FAILED", err.Error())
			return
		}

		sendJSON(w, http.StatusOK, map[string]int{"count": count})
	}
}

func handleBaselineCheck(deps *ServerDependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			sendError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "POST required")
			return
		}

		diff, err := deps.BaselineEngine.CheckBaseline()
		if err != nil {
			sendError(w, http.StatusInternalServerError, "BASELINE_FAILED", err.Error())
			return
		}

		sendJSON(w, http.StatusOK, diff)
	}
}
