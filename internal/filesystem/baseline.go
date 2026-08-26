package filesystem

import (
	"fmt"
	"os"
	"time"

	"linuxguard/internal/database"
	"linuxguard/internal/events"

	"github.com/google/uuid"
)

type BaselineDiff struct {
	NewFiles         []string `json:"new_files"`
	ModifiedFiles    []string `json:"modified_files"`
	DeletedFiles     []string `json:"deleted_files"`
	PermissionErrors []string `json:"permission_errors"`
	TotalScanned     int      `json:"total_scanned"`
}

type BaselineEngine struct {
	scanner      *Scanner
	db           *database.DB
	eventManager *events.Manager
}

func NewBaselineEngine(scanner *Scanner, db *database.DB, eventManager *events.Manager) *BaselineEngine {
	return &BaselineEngine{
		scanner:      scanner,
		db:           db,
		eventManager: eventManager,
	}
}

// Create Baseline snapshots all monitored files into SQLite
func (b *BaselineEngine) CreateBaseline() (int, error) {
	if err := b.db.ClearBaseline(); err != nil {
		return 0, fmt.Errorf("failed clearing old baseline: %w", err)
	}

	files, err := b.scanner.ScanDirectories(0)
	if err != nil {
		return 0, fmt.Errorf("failed scanning directories for baseline: %w", err)
	}

	now := time.Now()
	count := 0
	for _, f := range files {
		record := database.BaselineRecord{
			Path:        f.Path,
			SHA256:      f.SHA256,
			Permissions: f.Permissions,
			Size:        f.Size,
			Owner:       f.Owner,
			Group:       f.Group,
			UpdatedAt:   now,
		}
		if err := b.db.SaveBaselineRecord(record); err == nil {
			count++
		}
	}

	if b.eventManager != nil {
		b.eventManager.Publish(events.SecurityEvent{
			ID:          "evt-" + uuid.New().String()[:8],
			Type:        events.TypeBaselineChanged,
			Severity:    events.SeverityInfo,
			Description: fmt.Sprintf("Created security baseline for %d files", count),
			Timestamp:   now,
		})
	}

	return count, nil
}

// Check Baseline compares current filesystem state against saved baseline in SQLite
func (b *BaselineEngine) CheckBaseline() (*BaselineDiff, error) {
	baselineMap, err := b.db.GetBaselineRecords()
	if err != nil {
		return nil, fmt.Errorf("failed reading baseline records: %w", err)
	}

	currentFiles, err := b.scanner.ScanDirectories(0)
	if err != nil {
		return nil, fmt.Errorf("failed scanning current directories: %w", err)
	}

	diff := &BaselineDiff{
		NewFiles:         make([]string, 0),
		ModifiedFiles:    make([]string, 0),
		DeletedFiles:     make([]string, 0),
		PermissionErrors: make([]string, 0),
		TotalScanned:     len(currentFiles),
	}

	currentMap := make(map[string]*FileInfoMetadata)
	now := time.Now()

	for _, cur := range currentFiles {
		currentMap[cur.Path] = cur
		base, exists := baselineMap[cur.Path]

		if !exists {
			diff.NewFiles = append(diff.NewFiles, cur.Path)
			if b.eventManager != nil {
				b.eventManager.Publish(events.SecurityEvent{
					ID:          "evt-" + uuid.New().String()[:8],
					Type:        events.TypeFileCreated,
					Severity:    events.SeverityInfo,
					Path:        cur.Path,
					Description: fmt.Sprintf("New file detected during baseline check: %s", cur.Path),
					Timestamp:   now,
				})
			}
		} else {
			// Check for content modification
			if cur.SHA256 != "" && cur.SHA256 != base.SHA256 {
				diff.ModifiedFiles = append(diff.ModifiedFiles, cur.Path)
				if b.eventManager != nil {
					b.eventManager.Publish(events.SecurityEvent{
						ID:          "evt-" + uuid.New().String()[:8],
						Type:        events.TypeFileModified,
						Severity:    events.SeverityMedium,
						Path:        cur.Path,
						Description: fmt.Sprintf("File modification detected against baseline: %s", cur.Path),
						Timestamp:   now,
					})
				}
			}

			// Check permissions
			if cur.Permissions != base.Permissions {
				diff.PermissionErrors = append(diff.PermissionErrors, cur.Path)
				if b.eventManager != nil {
					b.eventManager.Publish(events.SecurityEvent{
						ID:          "evt-" + uuid.New().String()[:8],
						Type:        events.TypeFilePermissionChange,
						Severity:    events.SeverityLow,
						Path:        cur.Path,
						Description: fmt.Sprintf("Permissions changed on file: %s (%s -> %s)", cur.Path, base.Permissions, cur.Permissions),
						Timestamp:   now,
					})
				}
			}
		}
	}

	// Check deleted files
	for baseFile := range baselineMap {
		if _, exists := currentMap[baseFile]; !exists {
			// Double check if file really doesn't exist
			if _, err := os.Lstat(baseFile); os.IsNotExist(err) {
				diff.DeletedFiles = append(diff.DeletedFiles, baseFile)
				if b.eventManager != nil {
					b.eventManager.Publish(events.SecurityEvent{
						ID:          "evt-" + uuid.New().String()[:8],
						Type:        events.TypeFileDeleted,
						Severity:    events.SeverityMedium,
						Path:        baseFile,
						Description: fmt.Sprintf("File removed from baseline: %s", baseFile),
						Timestamp:   now,
					})
				}
			}
		}
	}

	return diff, nil
}
