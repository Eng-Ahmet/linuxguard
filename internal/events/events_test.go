package events

import (
	"sync"
	"testing"
	"time"
)

func TestEventManagerPubSub(t *testing.T) {
	mgr := NewManager()

	var wg sync.WaitGroup
	var received []SecurityEvent
	var mu sync.Mutex

	wg.Add(2)
	mgr.Subscribe(func(e SecurityEvent) {
		defer wg.Done()
		mu.Lock()
		received = append(received, e)
		mu.Unlock()
	})

	evt1 := SecurityEvent{
		ID:          "evt-1",
		Type:        TypeFileCreated,
		Severity:    SeverityInfo,
		Description: "Test event 1",
		Timestamp:   time.Now(),
	}

	evt2 := SecurityEvent{
		ID:          "evt-2",
		Type:        TypeThreatDetected,
		Severity:    SeverityHigh,
		Description: "Test event 2",
		Timestamp:   time.Now(),
	}

	mgr.Publish(evt1)
	mgr.Publish(evt2)

	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	if len(received) != 2 {
		t.Fatalf("Expected 2 events, received %d", len(received))
	}
}
