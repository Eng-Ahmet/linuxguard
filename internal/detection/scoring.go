package detection

import "linuxguard/internal/events"

type Finding struct {
	RuleName string `json:"rule_name"`
	Score    int    `json:"score"`
	Reason   string `json:"reason"`
}

type Rule interface {
	Name() string
	Evaluate(event events.SecurityEvent) *Finding
}

// CalculateSeverity maps numerical score (0-100) to severity category string.
func CalculateSeverity(score int) string {
	switch {
	case score >= 80:
		return events.SeverityCritical
	case score >= 60:
		return events.SeverityHigh
	case score >= 30:
		return events.SeverityMedium
	case score > 0:
		return events.SeverityLow
	default:
		return events.SeverityInfo
	}
}
