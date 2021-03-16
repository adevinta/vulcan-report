/*
Copyright 2019 Adevinta
*/

package report

import (
	"errors"
	"sort"
	"time"
)

// https://nvd.nist.gov/vuln-metrics/cvss/
// CVSS v3.0 Ratings
//
// Severity   Base Score Range
// None       0.0
// Low        0.1 - 3.9
// Medium     4.0 - 6.9
// High       7.0 - 8.9
// Critical   9.0 -10.0
const (
	// SeverityThresholdNone defines interesting findings that are not vulnerabilities.
	SeverityThresholdNone = 0
	// SeverityThresholdLow defines vulnerabilities with low impact.
	SeverityThresholdLow = 3.9
	// SeverityThresholdMedium defines vulnerabilities with medium impact.
	SeverityThresholdMedium = 6.9
	// SeverityThresholdHigh defines vulnerabilities with high impact.
	SeverityThresholdHigh = 8.9
	// SeverityThresholdCritical defines vulnerabilities with critical impact.
	SeverityThresholdCritical = 10
)

type SeverityRank int

const (
	// SeverityNone defines interesting findings that are not vulnerabilities.
	SeverityNone SeverityRank = iota
	// SeverityLow defines vulnerabilities with low impact.
	SeverityLow
	// SeverityMedium defines vulnerabilities with medium impact.
	SeverityMedium
	// SeverityHigh defines vulnerabilities with high impact.
	SeverityHigh
	// SeverityCritical defines vulnerabilities with critical impact.
	SeverityCritical
)

type ByScore []Vulnerability

func (v ByScore) Len() int {
	return len(v)
}
func (v ByScore) Swap(i, j int) {
	v[i], v[j] = v[j], v[i]
}
func (v ByScore) Less(i, j int) bool {
	return v[i].Score > v[j].Score
}

// AggregateScore returns an aggregated score for a group of vulnerabilities.
// NOTE: This is currently a placeholder function which returns the maximum severity score.
func AggregateScore(vulnerabilities []Vulnerability) float32 {
	if len(vulnerabilities) == 0 {
		return 0
	}
	sort.Sort(ByScore(vulnerabilities))
	return vulnerabilities[0].Score
}

// RankSeverity returns the severity rank according to predefined score thresholds.
func RankSeverity(score float32) SeverityRank {
	switch {
	case score <= SeverityThresholdNone:
		return SeverityNone
	case score <= SeverityThresholdLow:
		return SeverityLow
	case score <= SeverityThresholdMedium:
		return SeverityMedium
	case score <= SeverityThresholdHigh:
		return SeverityHigh
	default:
		return SeverityCritical
	}
}

// ScoreSeverity returns the maximum score according to a severity rank.
func ScoreSeverity(severity SeverityRank) float32 {
	switch severity {
	case SeverityNone:
		return SeverityThresholdNone
	case SeverityLow:
		return SeverityThresholdLow
	case SeverityMedium:
		return SeverityThresholdMedium
	case SeverityHigh:
		return SeverityThresholdHigh
	case SeverityCritical:
		return SeverityThresholdCritical
	default:
		return SeverityThresholdCritical
	}
}

// SecurityStatus returns a grade from A to F (A is good, F is bad) given a target aggregated score
func SecurityStatus(score float32) string {
	switch {
	case score < 2.0:
		return "A"
	case score <= 3.5:
		return "B"
	case score <= 5.0:
		return "C"
	case score <= 6.5:
		return "D"
	case score <= 8.0:
		return "E"
	default:
		return "F"
	}
}

// ValidateReport validates a Report.
func ValidateReport(r Report) error {
	// Must have basic check information.
	if r.CheckID == "" {
		return errors.New("report is missing check ID")
	}
	if r.ChecktypeName == "" {
		return errors.New("report is missing check type name")
	}
	if r.ChecktypeVersion == "" {
		return errors.New("report is missing check type version")
	}

	// Must have basic check job information.
	if r.Target == "" {
		return errors.New("report is missing target")
	}
	if r.Status == "" {
		return errors.New("report is missing status")
	}

	// Must have a start time.
	if r.StartTime == (time.Time{}) {
		return errors.New("report is missing start time")
	}

	// All vulnerabilities must be valid.
	for _, v := range r.Vulnerabilities {
		err := v.Validate()
		if err != nil {
			return err
		}
	}

	return nil
}

// ValidateVulnerability validates a Vulnerability.
func ValidateVulnerability(v Vulnerability) error {
	if v.Summary == "" {
		return errors.New("vulnerability group is missing summary")
	}

	// Validate vulnerabilities.
	for _, vulnerability := range v.Vulnerabilities {
		err := vulnerability.Validate()
		if err != nil {
			return err
		}

		if len(vulnerability.Vulnerabilities) > 0 {
			return errors.New("child vulnerabilities are not allowed to have children")
		}
	}

	return nil
}
