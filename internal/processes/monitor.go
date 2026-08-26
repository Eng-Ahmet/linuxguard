package processes

import (
	"context"
	"fmt"
	"sync"
	"time"

	"linuxguard/internal/events"

	"github.com/google/uuid"
)

type Monitor struct {
	interval     time.Duration
	eventManager *events.Manager
	knownPIDs    map[int32]*ProcessInfo
	mu           sync.RWMutex
	ctx          context.Context
	cancel       context.CancelFunc
	wg           sync.WaitGroup
}

func NewMonitor(intervalSeconds int, eventManager *events.Manager) *Monitor {
	if intervalSeconds <= 0 {
		intervalSeconds = 3
	}

	ctx, cancel := context.WithCancel(context.Background())
	return &Monitor{
		interval:     time.Duration(intervalSeconds) * time.Second,
		eventManager: eventManager,
		knownPIDs:    make(map[int32]*ProcessInfo),
		ctx:          ctx,
		cancel:       cancel,
	}
}

func (m *Monitor) Start() {
	// Initialize first snapshot
	procs, err := GetRunningProcesses()
	if err == nil {
		m.mu.Lock()
		for _, p := range procs {
			m.knownPIDs[p.PID] = p
		}
		m.mu.Unlock()
	}

	m.wg.Add(1)
	go m.loop()
}

func (m *Monitor) Stop() {
	m.cancel()
	m.wg.Wait()
}

func (m *Monitor) loop() {
	defer m.wg.Done()
	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			m.checkProcesses()
		}
	}
}

func (m *Monitor) checkProcesses() {
	currentProcs, err := GetRunningProcesses()
	if err != nil {
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	currentMap := make(map[int32]*ProcessInfo)
	for _, p := range currentProcs {
		currentMap[p.PID] = p

		// If PID was not previously known, emit PROCESS_STARTED
		if _, exists := m.knownPIDs[p.PID]; !exists {
			secEvent := events.SecurityEvent{
				ID:          "evt-" + uuid.New().String()[:8],
				Type:        events.TypeProcessStarted,
				Severity:    events.SeverityInfo,
				PID:         int(p.PID),
				Process:     p.Name,
				Path:        p.ExePath,
				User:        p.User,
				Description: fmt.Sprintf("Process started: %s (PID %d, Path: %s, User: %s)", p.Name, p.PID, p.ExePath, p.User),
				Timestamp:   time.Now(),
			}

			if m.eventManager != nil {
				m.eventManager.Publish(secEvent)
			}
		}
	}

	// Update known map
	m.knownPIDs = currentMap
}
