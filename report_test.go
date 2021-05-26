package report

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"testing"
	"time"
)

const (
	st    = "2021-05-18T13:30:15.00000Z"
	stStr = "2021-05-18 13:30:15"
	et    = "2021-05-18T14:00:50.00000Z"
	etStr = "2021-05-18 14:00:50"
)

var (
	cd0 = CheckData{
		CheckID:          "ID0",
		ChecktypeName:    "CT0",
		ChecktypeVersion: "CTV0",
		Target:           "example.com",
		Status:           "FINISHED",
		StartTime:        mustConvertStrToDateTime(st),
		EndTime:          mustConvertStrToDateTime(et),
	}
)

func mustConvertStrToDateTime(ts string) time.Time {
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		fmt.Printf("error converting date string: %s", err)
		os.Exit(1)
	}
	return t
}

func vulnerabilityWithCategoryAndScore(category string, score float32) Vulnerability {
	return Vulnerability{
		Summary:          "mocked vulnerability",
		Category:         category,
		AffectedResource: "port-80",
		Score:            score,
	}
}

func TestMarshalJSONTimeAsString(t *testing.T) {
	r := Report{
		CheckData:  cd0,
		ResultData: ResultData{},
	}
	b, err := r.MarshalJSONTimeAsString()
	if err != nil {
		t.Errorf("unexpected error with MarshalJSONTimeAsString: %s", err)
	}
	jsonMap := make(map[string]interface{})
	err = json.Unmarshal(b, &jsonMap)
	if err != nil {
		t.Errorf("unexpected error with unmarshaling json string: %s", err)
	}
	if jsonMap["start_time"] != stStr ||
		jsonMap["end_time"] != etStr {
		t.Errorf(
			"unexpected MarshalJSONTimeAsString values: have: %s-%s want: %s-%s",
			jsonMap["start_time"], jsonMap["end_time"],
			stStr, etStr,
		)
	}
}

func TestUnmarshalJSONTimeAsString(t *testing.T) {
	rStr := []byte(`{"check_id":"ID0","checktype_name":"CT0","checktype_version":"CTV0","status":"FINISHED","target":"example.com","options":"","tag":"","vulnerabilities":null,"error":"","start_time":"2021-05-18 13:30:15","end_time":"2021-05-18 14:00:50"}`)
	var r Report
	err := r.UnmarshalJSONTimeAsString(rStr)
	if err != nil {
		t.Errorf("unexpected error with UnmarshalJSONTimeAsString: %s", err)
	}
	if r.StartTime != mustConvertStrToDateTime(st) ||
		r.EndTime != mustConvertStrToDateTime(et) {
		t.Errorf(
			"unexpected UnmarshalJSONTimeAsString values: have: %s-%s want: %s-%s",
			r.StartTime, r.EndTime,
			mustConvertStrToDateTime(st), mustConvertStrToDateTime(et),
		)
	}
}

func TestVulnerabilityAggregateScore(t *testing.T) {
	tests := []struct {
		name      string
		v         Vulnerability
		wantScore float32
	}{
		{
			name:      "SingleVulnerability",
			v:         vulnerabilityWithCategoryAndScore("ISSUE", 3.9),
			wantScore: 3.9,
		},
		{
			name: "MultipleVulnerabilitiesSameScore",
			v: Vulnerability{
				Score: 3.9,
				Vulnerabilities: []Vulnerability{
					vulnerabilityWithCategoryAndScore("ISSUE", 3.9),
					vulnerabilityWithCategoryAndScore("ISSUE", 3.9),
					vulnerabilityWithCategoryAndScore("ISSUE", 3.9),
				},
			},
			wantScore: 3.9,
		},
		{
			name: "MultipleVulnerabilitiesDifferentScores",
			v: Vulnerability{
				Score: 8.9,
				Vulnerabilities: []Vulnerability{
					vulnerabilityWithCategoryAndScore("ISSUE", 3.9),
					vulnerabilityWithCategoryAndScore("ISSUE", 6.9),
					vulnerabilityWithCategoryAndScore("POTENTIAL_ISSUE", 8.9),
				},
			},
			wantScore: 8.9,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.v.AggregateScore()
			if tt.wantScore != tt.v.Score {
				t.Errorf("vulnerability score does not match: have: %f - want: %f", tt.v.Score, tt.wantScore)
			}
		})
	}
}

func TestAddVulnerabilitiesToVulnerability(t *testing.T) {
	tests := []struct {
		name                   string
		v                      Vulnerability
		vToAdd                 []Vulnerability
		wantSubVulnerabilities []Vulnerability
	}{
		{
			name:                   "NoSubvulnerabilites",
			v:                      vulnerabilityWithCategoryAndScore("COMPLIANCE", 3.9),
			vToAdd:                 []Vulnerability{},
			wantSubVulnerabilities: nil,
		},
		{
			name:                   "AddOneVulnerabilityToVulnerability",
			v:                      vulnerabilityWithCategoryAndScore("ISSUE", 6.9),
			vToAdd:                 []Vulnerability{vulnerabilityWithCategoryAndScore("ISSUE", 4.0)},
			wantSubVulnerabilities: []Vulnerability{vulnerabilityWithCategoryAndScore("ISSUE", 4.0)},
		},
		{
			name: "AddMultpileVulnerabilityToVulnerability",
			v:    vulnerabilityWithCategoryAndScore("POTENTIAL_ISSUE", 8.9),
			vToAdd: []Vulnerability{
				vulnerabilityWithCategoryAndScore("INFORMATIONAL", 0.0),
				vulnerabilityWithCategoryAndScore("ISSUE", 3.9),
				vulnerabilityWithCategoryAndScore("ISSUE", 8.9),
			},
			wantSubVulnerabilities: []Vulnerability{
				vulnerabilityWithCategoryAndScore("INFORMATIONAL", 0.0),
				vulnerabilityWithCategoryAndScore("ISSUE", 3.9),
				vulnerabilityWithCategoryAndScore("ISSUE", 8.9),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.v.AddVulnerabilities(tt.vToAdd...)
			if !reflect.DeepEqual(tt.v.Vulnerabilities, tt.wantSubVulnerabilities) {
				t.Errorf("subvulnerabilities does not match: have: %+v - want: %+v", tt.v.Vulnerabilities, tt.wantSubVulnerabilities)
			}
		})
	}
}

func TestValidateVulnerability(t *testing.T) {
	tests := []struct {
		name      string
		v         Vulnerability
		wantErr   bool
		errString string
	}{
		{
			name:    "HappyPath",
			v:       vulnerabilityWithCategoryAndScore("ISSUE", 8.9),
			wantErr: false,
		},
		{
			name: "HappyPathWithSubvulnerabilities",
			v: Vulnerability{
				Summary:          "vulnerability with subvulns",
				AffectedResource: "port-80",
				Score:            8.9,
				Category:         "POTENTIAL_ISSUE",
				Vulnerabilities: []Vulnerability{
					vulnerabilityWithCategoryAndScore("POTENTIAL_ISSUE", 6.9),
				},
			},
			wantErr: false,
		},
		{
			name: "MissingSummary",
			v: Vulnerability{
				AffectedResource: "port-80",

				Category: "INFORMATIONAL",
				Score:    0.0,
			},
			wantErr:   true,
			errString: "vulnerability group is missing summary",
		},
		{
			name: "MissingCategory",
			v: Vulnerability{
				Summary:          "mocked vulnerability",
				AffectedResource: "port-80",
				Score:            0.0,
			},
			wantErr:   true,
			errString: "vulnerability category is missing",
		},
		{
			name: "MissingAffectedResource",
			v: Vulnerability{
				Summary:  "mocked vulnerability",
				Category: "INFORMATIONAL",
				Score:    0.0,
			},
			wantErr:   true,
			errString: "vulnerability affected resource is missing",
		},
		{
			name: "MalformedComposedVulnerbility",
			v: Vulnerability{
				Summary:          "mocked vulnerability with subvulns",
				AffectedResource: "port-80",
				Score:            8.9,
				Category:         "POTENTIAL_ISSUE",
				Vulnerabilities: []Vulnerability{
					{
						Category:         "INFORMATIONAL",
						AffectedResource: "port-80",
						Score:            0.0,
					},
				},
			},
			wantErr:   true,
			errString: "vulnerability group is missing summary",
		},
		{
			name: "ChildVulnerabilityHasChild",
			v: Vulnerability{
				Summary:          "mocked vulnerability with subvulns",
				AffectedResource: "port-80",
				Score:            8.9,
				Category:         "POTENTIAL_ISSUE",
				Vulnerabilities: []Vulnerability{
					{
						Summary:          "mocked subvuln level 1",
						AffectedResource: "port-80",
						Score:            6.9,
						Category:         "POTENTIAL_ISSUE",
						Vulnerabilities: []Vulnerability{
							{
								Summary:          "mocked subvuln level 2",
								AffectedResource: "port-80",
								Category:         "INFORMATIONAL",
								Score:            0.0,
							},
						},
					},
				},
			},
			wantErr:   true,
			errString: "child vulnerabilities are not allowed to have children",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.v.Validate()
			if (err != nil) && !tt.wantErr {
				t.Errorf("unexpected error: have: %v - want: %v", tt.wantErr, err != nil)
			}
			if err != nil {
				if err.Error() != tt.errString {
					t.Errorf("vulnerability validation failed: have: %s - want: %s", err, tt.errString)
				}
			}
		})
	}
}

func TestValidateReport(t *testing.T) {
	tests := []struct {
		name      string
		r         Report
		wantErr   bool
		errString string
	}{
		{
			name: "HappyPath",
			r: Report{
				CheckData: cd0,
			},
			wantErr: false,
		},
		{
			name: "HappyPathWithVulnerabilities",
			r: Report{
				CheckData: cd0,
				ResultData: ResultData{
					Vulnerabilities: []Vulnerability{vulnerabilityWithCategoryAndScore("ISSUE", 3.9)},
				},
			},
			wantErr: false,
		},
		{
			name: "ReportWithMalformedVulnerabilities",
			r: Report{
				CheckData: cd0,
				ResultData: ResultData{
					Vulnerabilities: []Vulnerability{
						{
							Category:         "INFORMATIONAL",
							AffectedResource: "port-80",
							Score:            0.0,
						},
					},
				},
			},
			wantErr:   true,
			errString: "vulnerability group is missing summary",
		},
		{
			name: "ReportMissingCheckID",
			r: Report{
				CheckData: CheckData{
					ChecktypeName:    "CT0",
					ChecktypeVersion: "CTV0",
					Target:           "example.com",
					Status:           "FINISHED",
					StartTime:        mustConvertStrToDateTime(st),
					EndTime:          mustConvertStrToDateTime(et),
				},
			},
			wantErr:   true,
			errString: "report is missing check ID",
		},
		{
			name: "ReportMissingChecktypeName",
			r: Report{
				CheckData: CheckData{
					CheckID:          "ID0",
					ChecktypeVersion: "CTV0",
					Target:           "example.com",
					Status:           "FINISHED",
					StartTime:        mustConvertStrToDateTime(st),
					EndTime:          mustConvertStrToDateTime(et),
				},
			},
			wantErr:   true,
			errString: "report is missing check type name",
		},
		{
			name: "ReportMissingChecktypeVersion",
			r: Report{
				CheckData: CheckData{
					CheckID:       "ID0",
					ChecktypeName: "CT0",
					Target:        "example.com",
					Status:        "FINISHED",
					StartTime:     mustConvertStrToDateTime(st),
					EndTime:       mustConvertStrToDateTime(et),
				},
			},
			wantErr:   true,
			errString: "report is missing check type version",
		},
		{
			name: "ReportMissingStatus",
			r: Report{
				CheckData: CheckData{
					CheckID:          "ID0",
					ChecktypeName:    "CT0",
					ChecktypeVersion: "CTV0",
					Target:           "example.com",
					StartTime:        mustConvertStrToDateTime(st),
					EndTime:          mustConvertStrToDateTime(et),
				},
			},
			wantErr:   true,
			errString: "report is missing status",
		},
		{
			name: "ReportMissingTarget",
			r: Report{
				CheckData: CheckData{
					CheckID:          "ID0",
					ChecktypeName:    "CT0",
					ChecktypeVersion: "CTV0",
					Status:           "FINISHED",
					StartTime:        mustConvertStrToDateTime(st),
					EndTime:          mustConvertStrToDateTime(et),
				},
			},
			wantErr:   true,
			errString: "report is missing target",
		},
		{
			name: "ReportMissingStartTime",
			r: Report{
				CheckData: CheckData{
					CheckID:          "ID0",
					ChecktypeName:    "CT0",
					ChecktypeVersion: "CTV0",
					Status:           "FINISHED",
					Target:           "example.com",
					EndTime:          mustConvertStrToDateTime(et),
				},
			},
			wantErr:   true,
			errString: "report is missing start time",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.r.Validate()
			if (err == nil) && tt.wantErr {
				t.Errorf("unexpected error: have error: %v - want error: %v", err != nil, tt.wantErr)
			}
			if err != nil {
				if err.Error() != tt.errString {
					t.Errorf("report validation failed: have error: %s - want error: %s", err, tt.errString)
				}
			}
		})
	}
}
