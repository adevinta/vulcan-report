/*
Copyright 2019 Adevinta
*/

package report

import (
	"encoding/json"
	"time"
)

const layout = "2006-01-02 15:04:05"

// Report represents a check vulnerability report.
type Report struct {
	CheckData
	ResultData
}

// ResultData contains the data regarding result of the execution of a check, for instance: vulnerabilities, notes, etc.
type ResultData struct {
	Vulnerabilities []Vulnerability `json:"vulnerabilities"` // Array of identified vulnerabilities.

	Data  []byte `json:"data,omitempty"`  // Free field for additional data.
	Notes string `json:"notes,omitempty"` // Free field for additional notes.
	Error string `json:"error"`           // Error message, if any.

	NotApplicable bool `json:"not_applicable,omitempty"` // If the check was not really applicable.
}

// CheckData defines the data about the execution of the check that generated the report.
type CheckData struct {
	CheckID          string `json:"check_id"`          // Mandatory.
	ChecktypeName    string `json:"checktype_name"`    // Mandatory.
	ChecktypeVersion string `json:"checktype_version"` // Mandatory.

	Status string `json:"status"` // Mandatory.

	Target  string `json:"target"` // Mandatory.
	Options string `json:"options"`
	Tag     string `json:"tag"`

	StartTime time.Time `json:"start_time"` // Mandatory.
	EndTime   time.Time `json:"end_time"`
}

// AddVulnerabilities is a handy method to add one or more Vulnerabilities to the ResultData.Vulnerability array.
// It's equivalent to r.Vulnerabilities = append(r.Vulnerabilities,v).
func (r *ResultData) AddVulnerabilities(v ...Vulnerability) {
	r.Vulnerabilities = append(r.Vulnerabilities, v...)
}

// MarshalJSONTimeAsString marshals a Report to JSON using time as string
// A custom marshaler is used to rewrite times for Athena and Rails.
// TODO: Discuss if this is necessary or if we can drop it.
func (r *Report) MarshalJSONTimeAsString() ([]byte, error) {
	return json.Marshal(struct {
		Report
		StartTime string `json:"start_time"`
		EndTime   string `json:"end_time"`
	}{
		Report:    *r,
		StartTime: formatTime(&r.StartTime, layout),
		EndTime:   formatTime(&r.EndTime, layout),
	})
}

// UnmarshalJSONTimeAsString unmarshals a JSON to a Report using time as string
func (r *Report) UnmarshalJSONTimeAsString(data []byte) error {
	aux := &struct {
		*Report
		StartTime string `json:"start_time"`
		EndTime   string `json:"end_time"`
	}{
		Report: r,
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	if len(aux.StartTime) > 0 {
		startTime, err := time.Parse(layout, aux.StartTime)
		if err != nil {
			return err
		}
		r.StartTime = startTime
	}

	if len(aux.EndTime) > 0 {
		endTime, err := time.Parse(layout, aux.EndTime)
		if err != nil {
			return err
		}
		r.EndTime = endTime
	}

	return nil
}

func formatTime(t *time.Time, layout string) string {
	if t != nil {
		return t.Format(layout)
	}
	return ""
}

func (r Report) Validate() error {
	return ValidateReport(r)
}

// Vulnerability represents a single security vulnerability found while running a check.
type Vulnerability struct {
	ID string `json:"id"` // Arbitrary UUID that uniquely identifies the vulnerability in every scan.

	Summary string  `json:"summary"` // Mandatory. Vulnerability title.
	Score   float32 `json:"score"`   // Vulnerability severity score. According to CVSSv3 base score.

	CWEID           uint32           `json:"cwe_id,omitempty"`          // CWE-ID.
	Description     string           `json:"description,omitempty"`     // Vulnerability description.
	Details         string           `json:"details,omitempty"`         // Vulnerability details generated when running the check against the target
	ImpactDetails   string           `json:"impact_details,omitempty"`  // Vulnerability impact details.
	Recommendations []string         `json:"recommendations,omitempty"` // Vulnerability remediation suggestions.
	References      []string         `json:"references,omitempty"`      // Reference URLs for more information.
	Resources       []ResourcesGroup `json:"resources,omitempty"`       // ResourcesGroups found when running the check.
	Attachments     []Attachment     `json:"attachments,omitempty"`     // Attachments found when running the check

	Vulnerabilities []Vulnerability `json:"vulnerabilities"` // Mandatory. Array of identified vulnerabilities.
}

// AddVulnerabilities is a handy method to add one or more Vulnerabilities to the Vulnerability.Vulnerabilities array.
// It's equivalent to v.Vulnerabilities = append(v.Vulnerabilities,vulnerabilities)
func (v *Vulnerability) AddVulnerabilities(vulnerabilities ...Vulnerability) {
	v.Vulnerabilities = append(v.Vulnerabilities, vulnerabilities...)
}

// AggregateScore recalculates the score field for a parent vulnerability.
func (v *Vulnerability) AggregateScore() {
	if len(v.Vulnerabilities) > 0 {
		v.Score = AggregateScore(v.Vulnerabilities)
	}
}

// Severity returns the severity rank for a vulnerability.
func (v Vulnerability) Severity() SeverityRank {
	return RankSeverity(v.Score)
}

// Validate checks if a vulnerability is valid.
func (v Vulnerability) Validate() error {
	return ValidateVulnerability(v)
}

// Attachment found when running the check
type Attachment struct {
	Name        string `json:"name"`
	ContentType string `json:"content_type"`
	Data        []byte `json:"data"`
}

// ResourcesGroup a self-defined table for resources sharing the same attributes.
// Example:
// Name: Network Resource
// Header: | Hostname | Port | Protocol | Service |
// Rows:
//	| www.adevinta.com | 80  | tcp | http |
//	| www.adevinta.com | 443 | tcp | http |
//
// The way the Rows are defined is using a map with values for every key defined
// at the Header attribute.
type ResourcesGroup struct {
	Name   string
	Header []string
	Rows   []map[string]string
}
