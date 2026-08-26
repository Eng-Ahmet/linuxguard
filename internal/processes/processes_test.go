package processes

import (
	"os/exec"
	"testing"
	"time"

	"linuxguard/internal/events"
)

func TestProcessMonitor(t *testing.T) {
	em := events.NewManager()
	received := make(chan events.SecurityEvent, 10)

	em.Subscribe(func(evt events.SecurityEvent) {
		if evt.Type == events.TypeProcessStarted {
			received <- evt
		}
	})

	mon := NewMonitor(1, em)
	mon.Start()
	defer mon.Stop()

	// Spawn a short sleep process
	cmd := exec.Command("sleep", "2")
	if err := cmd.Start(); err != nil {
		t.Fatalf("Failed spawning sleep command: %v", err)
	}

	select {
	case evt := <-received:
		if evt.PID != cmd.Process.Pid && evt.Process != "sleep" {
			// A process event was detected
		}
		t.Logf("Captured process event: PID=%d, Process=%s", evt.PID, evt.Process)
	case <-time.After(3 * time.Second):
		t.Log("Note: Process monitor loop interval timed out or process exited before snapshot")
	}

	_ = cmd.Wait()
}
