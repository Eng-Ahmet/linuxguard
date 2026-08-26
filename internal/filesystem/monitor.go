package filesystem

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"linuxguard/internal/events"

	"github.com/fsnotify/fsnotify"
	"github.com/google/uuid"
)

type Monitor struct {
	watcher      *fsnotify.Watcher
	scanner      *Scanner
	eventManager *events.Manager
	ctx          context.Context
	cancel       context.CancelFunc
	wg           sync.WaitGroup
	mu           sync.Mutex
	watchedDirs  map[string]bool
}

func NewMonitor(monitoredPaths, excludedPaths []string, eventManager *events.Manager) (*Monitor, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("failed to create fsnotify watcher: %w", err)
	}

	scanner := NewScanner(monitoredPaths, excludedPaths)
	ctx, cancel := context.WithCancel(context.Background())

	return &Monitor{
		watcher:      watcher,
		scanner:      scanner,
		eventManager: eventManager,
		ctx:          ctx,
		cancel:       cancel,
		watchedDirs:  make(map[string]bool),
	}, nil
}

func (m *Monitor) Start() error {
	for _, path := range m.scanner.monitoredPaths {
		if err := m.addRecursive(path); err != nil {
			// Log or ignore unreadable directories gracefully
		}
	}

	m.wg.Add(1)
	go m.eventLoop()
	return nil
}

func (m *Monitor) Stop() {
	m.cancel()
	m.watcher.Close()
	m.wg.Wait()
}

func (m *Monitor) addRecursive(root string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.scanner.IsExcluded(root) {
		return nil
	}

	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		if m.scanner.IsExcluded(path) {
			if info.IsDir() && path != root {
				return filepath.SkipDir
			}
			return nil
		}

		// Don't follow symlinks for directory watching
		if info.Mode()&os.ModeSymlink != 0 {
			return nil
		}

		if info.IsDir() {
			if !m.watchedDirs[path] {
				if err := m.watcher.Add(path); err == nil {
					m.watchedDirs[path] = true
				}
			}
		}
		return nil
	})
}

func (m *Monitor) eventLoop() {
	defer m.wg.Done()

	for {
		select {
		case <-m.ctx.Done():
			return

		case err, ok := <-m.watcher.Errors:
			if !ok {
				return
			}
			_ = err // Ignore or log internal watcher errors

		case fsEvent, ok := <-m.watcher.Events:
			if !ok {
				return
			}

			if m.scanner.IsExcluded(fsEvent.Name) {
				continue
			}

			// Determine event type
			var eventType string
			switch {
			case fsEvent.Op&fsnotify.Create == fsnotify.Create:
				eventType = events.TypeFileCreated
				// If new directory, add watcher
				if stat, err := os.Lstat(fsEvent.Name); err == nil && stat.IsDir() {
					_ = m.addRecursive(fsEvent.Name)
				}
			case fsEvent.Op&fsnotify.Write == fsnotify.Write:
				eventType = events.TypeFileModified
			case fsEvent.Op&fsnotify.Remove == fsnotify.Remove:
				eventType = events.TypeFileDeleted
			case fsEvent.Op&fsnotify.Rename == fsnotify.Rename:
				eventType = events.TypeFileRenamed
			case fsEvent.Op&fsnotify.Chmod == fsnotify.Chmod:
				eventType = events.TypeFilePermissionChange
			default:
				continue
			}

			secEvent := events.SecurityEvent{
				ID:          "evt-" + uuid.New().String()[:8],
				Type:        eventType,
				Severity:    events.SeverityInfo,
				Score:       0,
				Path:        fsEvent.Name,
				Description: fmt.Sprintf("Filesystem event %s on %s", eventType, fsEvent.Name),
				Timestamp:   time.Now(),
			}

			m.eventManager.Publish(secEvent)
		}
	}
}
