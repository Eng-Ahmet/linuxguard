package database

import (
	"database/sql"
	"encoding/json"
	"fmt"

	"os"
	"path/filepath"
	"sync"
	"time"

	"linuxguard/internal/events"

	_ "modernc.org/sqlite"
)

type DB struct {
	db *sql.DB
	mu sync.RWMutex
}

type FileRecord struct {
	ID        int64     `json:"id"`
	Path      string    `json:"path"`
	SHA256    string    `json:"sha256"`
	Size      int64     `json:"size"`
	Mode      string    `json:"mode"`
	Owner     string    `json:"owner"`
	Group     string    `json:"group"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type BaselineRecord struct {
	Path        string    `json:"path"`
	SHA256      string    `json:"sha256"`
	Permissions string    `json:"permissions"`
	Size        int64     `json:"size"`
	Owner       string    `json:"owner"`
	Group       string    `json:"group"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type QuarantineRecord struct {
	ID             string    `json:"id"`
	OriginalPath   string    `json:"original_path"`
	QuarantinePath string    `json:"quarantine_path"`
	SHA256         string    `json:"sha256"`
	Size           int64     `json:"size"`
	Reason         string    `json:"reason"`
	Score          int       `json:"score"`
	CreatedAt      time.Time `json:"created_at"`
	Status         string    `json:"status"` // QUARANTINED, RESTORED, DELETED
}

func Open(dbPath string) (*DB, error) {
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create database directory %s: %w", dir, err)
	}

	conn, err := sql.Open("sqlite", dbPath+"?_pragma=busy_timeout=5000&_pragma=journal_mode=WAL")
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite db at %s: %w", dbPath, err)
	}

	if err := runMigrations(conn); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to run migrations: %w", err)
	}

	return &DB{db: conn}, nil
}

func (d *DB) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.db.Close()
}

// Event persistence
func (d *DB) InsertEvent(event events.SecurityEvent) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	reasonsJSON, _ := json.Marshal(event.Reasons)

	query := `INSERT INTO events (id, type, severity, score, path, pid, process, user, description, reasons, timestamp)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err := d.db.Exec(query, event.ID, event.Type, event.Severity, event.Score, event.Path, event.PID, event.Process, event.User, event.Description, string(reasonsJSON), event.Timestamp)
	return err
}

func (d *DB) GetEvents(limit int) ([]events.SecurityEvent, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if limit <= 0 {
		limit = 100
	}

	rows, err := d.db.Query(`SELECT id, type, severity, score, path, pid, process, user, description, reasons, timestamp FROM events ORDER BY timestamp DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []events.SecurityEvent
	for rows.Next() {
		var e events.SecurityEvent
		var reasonsStr string
		var path, process, user sql.NullString
		var pid sql.NullInt64

		if err := rows.Scan(&e.ID, &e.Type, &e.Severity, &e.Score, &path, &pid, &process, &user, &e.Description, &reasonsStr, &e.Timestamp); err != nil {
			return nil, err
		}

		if path.Valid {
			e.Path = path.String
		}
		if pid.Valid {
			e.PID = int(pid.Int64)
		}
		if process.Valid {
			e.Process = process.String
		}
		if user.Valid {
			e.User = user.String
		}
		if reasonsStr != "" {
			_ = json.Unmarshal([]byte(reasonsStr), &e.Reasons)
		}

		result = append(result, e)
	}
	return result, nil
}

// Threat query
func (d *DB) GetThreats(limit int) ([]events.SecurityEvent, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if limit <= 0 {
		limit = 50
	}

	rows, err := d.db.Query(`SELECT id, type, severity, score, path, pid, process, user, description, reasons, timestamp FROM events WHERE score > 0 ORDER BY timestamp DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []events.SecurityEvent
	for rows.Next() {
		var e events.SecurityEvent
		var reasonsStr string
		var path, process, user sql.NullString
		var pid sql.NullInt64

		if err := rows.Scan(&e.ID, &e.Type, &e.Severity, &e.Score, &path, &pid, &process, &user, &e.Description, &reasonsStr, &e.Timestamp); err != nil {
			return nil, err
		}

		if path.Valid {
			e.Path = path.String
		}
		if pid.Valid {
			e.PID = int(pid.Int64)
		}
		if process.Valid {
			e.Process = process.String
		}
		if user.Valid {
			e.User = user.String
		}
		if reasonsStr != "" {
			_ = json.Unmarshal([]byte(reasonsStr), &e.Reasons)
		}

		result = append(result, e)
	}
	return result, nil
}

// Baseline operations
func (d *DB) SaveBaselineRecord(record BaselineRecord) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	query := `INSERT INTO baseline_files (path, sha256, permissions, size, owner, group_name, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(path) DO UPDATE SET
			sha256 = excluded.sha256,
			permissions = excluded.permissions,
			size = excluded.size,
			owner = excluded.owner,
			group_name = excluded.group_name,
			updated_at = excluded.updated_at`

	_, err := d.db.Exec(query, record.Path, record.SHA256, record.Permissions, record.Size, record.Owner, record.Group, record.UpdatedAt)
	return err
}

func (d *DB) GetBaselineRecords() (map[string]BaselineRecord, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	rows, err := d.db.Query(`SELECT path, sha256, permissions, size, owner, group_name, updated_at FROM baseline_files`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	records := make(map[string]BaselineRecord)
	for rows.Next() {
		var r BaselineRecord
		if err := rows.Scan(&r.Path, &r.SHA256, &r.Permissions, &r.Size, &r.Owner, &r.Group, &r.UpdatedAt); err != nil {
			return nil, err
		}
		records[r.Path] = r
	}
	return records, nil
}

func (d *DB) ClearBaseline() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	_, err := d.db.Exec("DELETE FROM baseline_files")
	return err
}

// Quarantine operations
func (d *DB) SaveQuarantineRecord(record QuarantineRecord) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	query := `INSERT INTO quarantine_items (id, original_path, quarantine_path, sha256, size, reason, score, created_at, status)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
	_, err := d.db.Exec(query, record.ID, record.OriginalPath, record.QuarantinePath, record.SHA256, record.Size, record.Reason, record.Score, record.CreatedAt, record.Status)
	return err
}

func (d *DB) UpdateQuarantineStatus(id, status string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.db.Exec(`UPDATE quarantine_items SET status = ? WHERE id = ?`, status, id)
	return err
}

func (d *DB) GetQuarantineItem(id string) (*QuarantineRecord, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	var r QuarantineRecord
	err := d.db.QueryRow(`SELECT id, original_path, quarantine_path, sha256, size, reason, score, created_at, status FROM quarantine_items WHERE id = ?`, id).
		Scan(&r.ID, &r.OriginalPath, &r.QuarantinePath, &r.SHA256, &r.Size, &r.Reason, &r.Score, &r.CreatedAt, &r.Status)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &r, nil
}

func (d *DB) GetQuarantineItems() ([]QuarantineRecord, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	rows, err := d.db.Query(`SELECT id, original_path, quarantine_path, sha256, size, reason, score, created_at, status FROM quarantine_items ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []QuarantineRecord
	for rows.Next() {
		var r QuarantineRecord
		if err := rows.Scan(&r.ID, &r.OriginalPath, &r.QuarantinePath, &r.SHA256, &r.Size, &r.Reason, &r.Score, &r.CreatedAt, &r.Status); err != nil {
			return nil, err
		}
		result = append(result, r)
	}
	return result, nil
}

// File catalog operations
func (d *DB) SaveFileRecord(rec FileRecord) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	query := `INSERT INTO files (path, sha256, size, mode, owner, group_name, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(path) DO UPDATE SET
			sha256 = excluded.sha256,
			size = excluded.size,
			mode = excluded.mode,
			owner = excluded.owner,
			group_name = excluded.group_name,
			updated_at = excluded.updated_at`

	_, err := d.db.Exec(query, rec.Path, rec.SHA256, rec.Size, rec.Mode, rec.Owner, rec.Group, rec.CreatedAt, rec.UpdatedAt)
	return err
}

func (d *DB) GetFiles(limit int) ([]FileRecord, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if limit <= 0 {
		limit = 100
	}

	rows, err := d.db.Query(`SELECT id, path, sha256, size, mode, owner, group_name, created_at, updated_at FROM files ORDER BY updated_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []FileRecord
	for rows.Next() {
		var r FileRecord
		if err := rows.Scan(&r.ID, &r.Path, &r.SHA256, &r.Size, &r.Mode, &r.Owner, &r.Group, &r.CreatedAt, &r.UpdatedAt); err != nil {
			return nil, err
		}
		result = append(result, r)
	}
	return result, nil
}
