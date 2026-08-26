package detection

import (
	"fmt"

	"linuxguard/internal/database"
	"linuxguard/internal/events"

	"github.com/google/uuid"
)

type Engine struct {
	rules        []Rule
	db           *database.DB
	eventManager *events.Manager
	enabled      bool
}

func NewEngine(enabled bool, db *database.DB, eventManager *events.Manager) *Engine {
	eng := &Engine{
		rules: []Rule{
			&SuspiciousTmpExecutableRule{},
			&SensitiveFileModificationRule{},
			&HiddenExecutableRule{},
			&RootUnusualExecutableRule{},
			&SuspiciousPermissionRule{},
		},
		db:           db,
		eventManager: eventManager,
		enabled:      enabled,
	}

	// Register event listener if enabled
	if enabled && eventManager != nil {
		eventManager.Subscribe(eng.ProcessEvent)
	}

	return eng
}

func (e *Engine) AddRule(rule Rule) {
	e.rules = append(e.rules, rule)
}

func (e *Engine) Evaluate(event events.SecurityEvent) (int, string, []string) {
	totalScore := 0
	var reasons []string

	for _, rule := range e.rules {
		finding := rule.Evaluate(event)
		if finding != nil {
			totalScore += finding.Score
			reasons = append(reasons, fmt.Sprintf("[%s] %s (+%d)", finding.RuleName, finding.Reason, finding.Score))
		}
	}

	if totalScore > 100 {
		totalScore = 100
	}

	severity := CalculateSeverity(totalScore)
	return totalScore, severity, reasons
}

func (e *Engine) ProcessEvent(event events.SecurityEvent) {
	score, severity, reasons := e.Evaluate(event)

	// Update event fields
	event.Score = score
	event.Severity = severity
	event.Reasons = reasons

	if score >= 30 {
		event.Type = events.TypeThreatDetected
	}

	// Save to DB
	if e.db != nil {
		_ = e.db.InsertEvent(event)
	}

	// Publish threat event if high score
	if score >= 30 && e.eventManager != nil {
		threatEvent := events.SecurityEvent{
			ID:          "threat-" + uuid.New().String()[:8],
			Type:        events.TypeThreatDetected,
			Severity:    severity,
			Score:       score,
			Path:        event.Path,
			PID:         event.PID,
			Process:     event.Process,
			User:        event.User,
			Description: fmt.Sprintf("Threat detected (%s score: %d) on %s", severity, score, event.Path),
			Reasons:     reasons,
			Timestamp:   event.Timestamp,
		}
		e.eventManager.Publish(threatEvent)
	}
}
