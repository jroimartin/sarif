// Copyright 2024 Roi Martin

package sarif

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestDecode(t *testing.T) {
	b, err := os.ReadFile("testdata/govulncheck.json")
	if err != nil {
		t.Fatalf("could not read testdata: %v", err)
	}

	var doc Log
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("could not decode SARIF document: %v", err)
	}

	if doc.Version != "2.1.0" {
		t.Errorf("SARIF version mismatch: got: %v", doc.Version)
	}

	if len(doc.Runs) != 1 {
		t.Fatalf("wrong number of runs: got: %v", len(doc.Runs))
	}
	run := doc.Runs[0]

	if len(run.Results) != 2 {
		t.Fatalf("wrong number of results: got: %v", len(run.Results))
	}
	result := run.Results[0]

	if result.RuleID != "GO-2021-0113" {
		t.Errorf("rule ID mismatch: got: %v", result.RuleID)
	}
}

func TestLog_FindRule(t *testing.T) {
	doc := Log{
		Runs: []Run{
			{
				Tool: Tool{
					Driver: Driver{
						Rules: []Rule{
							{
								ID: "id-1",
								ShortDescription: Description{
									Text: "description 1",
								},
							},
							{
								ID: "id-2",
								ShortDescription: Description{
									Text: "description 2",
								},
							},
						},
					},
				},
			},
		},
	}

	tests := []struct {
		name      string
		id        string
		wantRule  Rule
		wantFound bool
	}{
		{
			name: "found",
			id:   "id-2",
			wantRule: Rule{
				ID: "id-2",
				ShortDescription: Description{
					Text: "description 2",
				},
			},
			wantFound: true,
		},
		{
			name:      "not found",
			id:        "id-3",
			wantRule:  Rule{},
			wantFound: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule, found := doc.FindRule(tt.id)
			if diff := cmp.Diff(tt.wantRule, rule); diff != "" {
				t.Errorf("rule mismatch (-want +got):\n%v", diff)
			}
			if found != tt.wantFound {
				t.Errorf("found mismatch: want: %v, got: %v", tt.wantFound, found)
			}
		})
	}
}

func TestPhysicalLocation_String(t *testing.T) {
	tests := []struct {
		name string
		loc  PhysicalLocation
		want string
	}{
		{
			name: "sl",
			loc: PhysicalLocation{
				ArtifactLocation: ArtifactLocation{
					URI:       "uri",
					URIBaseID: "uribase",
				},
				Region: Region{
					StartLine: 1,
				},
			},
			want: "uribase/uri:1",
		},
		{
			name: "sl+sc",
			loc: PhysicalLocation{
				ArtifactLocation: ArtifactLocation{
					URI:       "uri",
					URIBaseID: "uribase",
				},
				Region: Region{
					StartLine:   1,
					StartColumn: 2,
				},
			},
			want: "uribase/uri:1:2",
		},
		{
			name: "sl+sc+el",
			loc: PhysicalLocation{
				ArtifactLocation: ArtifactLocation{
					URI:       "uri",
					URIBaseID: "uribase",
				},
				Region: Region{
					StartLine:   1,
					StartColumn: 2,
					EndLine:     3,
				},
			},
			want: "uribase/uri:1:2,3",
		},
		{
			name: "sl+sc+el+ec",
			loc: PhysicalLocation{
				ArtifactLocation: ArtifactLocation{
					URI:       "uri",
					URIBaseID: "uribase",
				},
				Region: Region{
					StartLine:   1,
					StartColumn: 2,
					EndLine:     3,
					EndColumn:   4,
				},
			},
			want: "uribase/uri:1:2,3:4",
		},
		{
			name: "sl+el",
			loc: PhysicalLocation{
				ArtifactLocation: ArtifactLocation{
					URI:       "uri",
					URIBaseID: "uribase",
				},
				Region: Region{
					StartLine: 1,
					EndLine:   3,
				},
			},
			want: "uribase/uri:1,3",
		},
		{
			name: "sl+el+ec",
			loc: PhysicalLocation{
				ArtifactLocation: ArtifactLocation{
					URI:       "uri",
					URIBaseID: "uribase",
				},
				Region: Region{
					StartLine: 1,
					EndLine:   3,
					EndColumn: 4,
				},
			},
			want: "uribase/uri:1,3:4",
		},
		{
			name: "sl+ec",
			loc: PhysicalLocation{
				ArtifactLocation: ArtifactLocation{
					URI:       "uri",
					URIBaseID: "uribase",
				},
				Region: Region{
					StartLine: 1,
					EndColumn: 4,
				},
			},
			want: "uribase/uri:1",
		},
		{
			name: "sc+el",
			loc: PhysicalLocation{
				ArtifactLocation: ArtifactLocation{
					URI:       "uri",
					URIBaseID: "uribase",
				},
				Region: Region{
					StartColumn: 2,
					EndLine:     3,
				},
			},
			want: "uribase/uri",
		},
		{
			name: "no region",
			loc: PhysicalLocation{
				ArtifactLocation: ArtifactLocation{
					URI:       "uri",
					URIBaseID: "uribase",
				},
				Region: Region{},
			},
			want: "uribase/uri",
		},
		{
			name: "zero value",
			loc:  PhysicalLocation{},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if s := tt.loc.String(); s != tt.want {
				t.Errorf("string mismatch: got: %q, want: %q", s, tt.want)
			}
		})
	}
}
