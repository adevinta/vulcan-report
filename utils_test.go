package report

import "testing"

func TestVulnerabilityRank(t *testing.T) {
	tests := []struct {
		name     string
		v        Vulnerability
		wantRank int
	}{
		{
			name:     "Informational",
			v:        vulnerabilityWithCategoryAndScore("", 0.0),
			wantRank: 0,
		},
		{
			name:     "Low",
			v:        vulnerabilityWithCategoryAndScore("", 3.9),
			wantRank: 1,
		},
		{
			name:     "Medium",
			v:        vulnerabilityWithCategoryAndScore("", 6.9),
			wantRank: 2,
		},
		{
			name:     "High",
			v:        vulnerabilityWithCategoryAndScore("", 8.9),
			wantRank: 3,
		},
		{
			name:     "High",
			v:        vulnerabilityWithCategoryAndScore("", 10.0),
			wantRank: 4,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vRank := int(tt.v.Severity())
			if tt.wantRank != vRank {
				t.Errorf("vulnerability rank does not match: have: %d - want: %d", vRank, tt.wantRank)
			}
		})
	}
}

func TestScoreSeverity(t *testing.T) {
	tests := []struct {
		name                  string
		severity              SeverityRank
		wantSeverityThreshold float32
	}{
		{
			name:                  "SeverityNone",
			severity:              SeverityNone,
			wantSeverityThreshold: SeverityThresholdNone,
		},
		{
			name:                  "SeverityLow",
			severity:              SeverityLow,
			wantSeverityThreshold: SeverityThresholdLow,
		},
		{
			name:                  "SeverityMedium",
			severity:              SeverityMedium,
			wantSeverityThreshold: SeverityThresholdMedium,
		},
		{
			name:                  "SeverityHigh",
			severity:              SeverityHigh,
			wantSeverityThreshold: SeverityThresholdHigh,
		},
		{
			name:                  "SeverityCritical",
			severity:              SeverityCritical,
			wantSeverityThreshold: SeverityThresholdCritical,
		},
		{
			name:                  "SeverityUnknown",
			severity:              5,
			wantSeverityThreshold: SeverityThresholdCritical,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			severityThreshold := ScoreSeverity(tt.severity)
			if severityThreshold != tt.wantSeverityThreshold {
				t.Errorf("severity threshold does not match severity: have: %f.2 - want: %f.2", severityThreshold, tt.wantSeverityThreshold)
			}
		})
	}
}

func TestSecurityStatus(t *testing.T) {
	tests := []struct {
		name       string
		score      float32
		wantStatus string
	}{
		{
			name:       "StatusA",
			score:      0,
			wantStatus: "A",
		},
		{
			name:       "StatusB",
			score:      3.5,
			wantStatus: "B",
		},
		{
			name:       "StatusC",
			score:      5.0,
			wantStatus: "C",
		},
		{
			name:       "StatusD",
			score:      6.5,
			wantStatus: "D",
		},
		{
			name:       "StatusE",
			score:      8,
			wantStatus: "E",
		},
		{
			name:       "StatusF",
			score:      9,
			wantStatus: "F",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status := SecurityStatus(tt.score)
			if status != tt.wantStatus {
				t.Errorf("status does not match score: have: %s - want: %s", status, tt.wantStatus)
			}
		})
	}
}

func TestAggregateScoreWithNoVulnerabilities(t *testing.T) {
	score := AggregateScore([]Vulnerability{})
	if score != 0.0 {
		t.Errorf("unexpected score for empty vulnerability array: have: %f.2 - want: %f.2", score, 0.0)
	}
}
