package database

import (
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite"
)

func runMigrations(db *sql.DB) error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS events (
			id TEXT PRIMARY KEY,
			type TEXT NOT NULL,
			severity TEXT NOT NULL,
			score INTEGER NOT NULL,
			path TEXT,
			pid INTEGER,
			process TEXT,
			user TEXT,
			description TEXT,
			reasons TEXT,
			timestamp DATETIME NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS files (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			path TEXT UNIQUE NOT NULL,
			sha256 TEXT NOT NULL,
			size INTEGER NOT NULL,
			mode TEXT NOT NULL,
			owner TEXT,
			group_name TEXT,
			created_at DATETIME NOT NULL,
			updated_at DATETIME NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS processes (
			pid INTEGER PRIMARY KEY,
			name TEXT NOT NULL,
			exe_path TEXT,
			cmdline TEXT,
			user TEXT,
			ppid INTEGER,
			start_time INTEGER,
			created_at DATETIME NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS baseline_files (
			path TEXT PRIMARY KEY,
			sha256 TEXT NOT NULL,
			permissions TEXT NOT NULL,
			size INTEGER NOT NULL,
			owner TEXT,
			group_name TEXT,
			updated_at DATETIME NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS quarantine_items (
			id TEXT PRIMARY KEY,
			original_path TEXT NOT NULL,
			quarantine_path TEXT NOT NULL,
			sha256 TEXT NOT NULL,
			size INTEGER NOT NULL,
			reason TEXT,
			score INTEGER NOT NULL,
			created_at DATETIME NOT NULL,
			status TEXT NOT NULL
		);`,
		`CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp DESC);`,
		`CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);`,
		`CREATE INDEX IF NOT EXISTS idx_quarantine_status ON quarantine_items(status);`,
	}

	for i, q := range queries {
		if _, err := db.Exec(q); err != nil {
			return fmt.Errorf("migration step %d failed: %w", i+1, err)
		}
	}

	return nil
}
