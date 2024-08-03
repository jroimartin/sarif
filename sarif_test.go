// Copyright 2024 Roi Martin

package sarif

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestDecodeFile(t *testing.T) {
	tests := []struct {
		name       string
		path       string
		wantNilErr bool
		validate   func(l Log)
	}{
		{
			name:       "valid",
			path:       "testdata/govulncheck.json",
			wantNilErr: true,
			validate: func(l Log) {
				if len(l.Runs) != 1 {
					t.Fatalf("wrong number of runs: got: %v", len(l.Runs))
				}
				run := l.Runs[0]

				if len(run.Results) != 2 {
					t.Fatalf("wrong number of results: got: %v", len(run.Results))
				}
				result := run.Results[0]

				if result.RuleID != "GO-2021-0113" {
					t.Errorf("rule ID mismatch: got: %v", result.RuleID)
				}
			},
		},
		{
			name:       "invalid version",
			path:       "testdata/invalid_version.json",
			wantNilErr: false,
		},
		{
			name:       "malformed",
			path:       "testdata/malformed.json",
			wantNilErr: false,
		},
		{
			name:       "invalid path",
			path:       "invalid",
			wantNilErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l, err := DecodeFile(tt.path)
			if err != nil {
				if tt.wantNilErr {
					t.Fatalf("expected nil error: got: %v", err)
				}
				return
			}

			if !tt.wantNilErr {
				t.Fatalf("expected non-nil error")
			}

			if l.Version != "2.1.0" {
				t.Errorf("SARIF version mismatch: got: %v", l.Version)
			}

			if tt.validate != nil {
				tt.validate(l)
			}
		})
	}
}

func TestEncodeFile(t *testing.T) {
	tmpdir, err := os.MkdirTemp("", "sarif")
	if err != nil {
		t.Fatalf("make temp dir: %v", err)
	}
	defer os.RemoveAll(tmpdir)

	const testSchema = "https://example.org/sarif-2.1.0.json"

	tests := []struct {
		name       string
		l          Log
		path       string
		wantNilErr bool
		validate   func(l Log)
	}{
		{
			name:       "valid version",
			l:          Log{Version: "2.1.0"},
			path:       filepath.Join(tmpdir, "valid_version.json"),
			wantNilErr: true,
			validate: func(l Log) {
				if l.Schema != sarifSchema {
					t.Errorf("unexpected SARIF schema: want: %v, got: %v", sarifSchema, l.Schema)
				}
			},
		},
		{
			name:       "empty version",
			l:          Log{},
			path:       filepath.Join(tmpdir, "empty_version.json"),
			wantNilErr: true,
		},
		{
			name:       "invalid version",
			l:          Log{Version: "3.1.0"},
			path:       filepath.Join(tmpdir, "invalid_version.json"),
			wantNilErr: false,
		},
		{
			name:       "custom schema",
			l:          Log{Schema: testSchema},
			path:       filepath.Join(tmpdir, "custom_schema.json"),
			wantNilErr: true,
			validate: func(l Log) {
				if l.Schema != testSchema {
					t.Errorf("unexpected SARIF schema: want: %v, got: %v", testSchema, l.Schema)
				}
			},
		},
		{
			name:       "invalid path",
			l:          Log{},
			path:       tmpdir,
			wantNilErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.l.EncodeFile(tt.path); err != nil {
				if tt.wantNilErr {
					t.Fatalf("expected nil error: got: %v", err)
				}
				return
			}

			if !tt.wantNilErr {
				t.Fatalf("expected non-nil error")
			}

			l, err := DecodeFile(tt.path)
			if err != nil {
				t.Fatalf("could not decode SARIF file: %v", err)
			}

			if tt.validate != nil {
				tt.validate(l)
			}
		})
	}
}

func TestLog_FindRule(t *testing.T) {
	l := Log{
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
			rule, found := l.FindRule(tt.id)
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
