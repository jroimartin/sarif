// Copyright 2024 Roi Martin

// Package sarif provides the data structures required to encode and
// decode a [SARIF] document.
//
// [SARIF]: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
package sarif

import (
	"fmt"
	"path"
)

// Log specifies the version of the file format and contains the
// output from one or more runs.
type Log struct {
	// Version is a string designating the version of the SARIF
	// specification to which this log file conforms. This string
	// SHALL have the value "2.1.0".
	Version string `json:"version,omitempty"`

	// Schema is a string containing an absolute URI from which a
	// JSON schema document describing the version of the SARIF
	// format to which this log file conforms can be obtained.
	Schema string `json:"$schema,omitempty"`

	// Runs contains the data provided by the executed tools.
	Runs []Run `json:"runs,omitempty"`
}

// FindRule returns the rule with the provided identifier.
func (l *Log) FindRule(id string) (rule Rule, found bool) {
	for _, run := range l.Runs {
		for _, rule := range run.Tool.Driver.Rules {
			if rule.ID == id {
				return rule, true
			}
		}
	}
	return Rule{}, false
}

// Run describes a single run of an analysis tool and contains the
// output of that run.
type Run struct {
	// Tool describes the analysis tool that was run.
	Tool Tool `json:"tool,omitempty"`

	// Results contains the results detected in the course of the
	// run.
	Results []Result `json:"results,omitempty"`
}

// Tool describes the analysis tool that was run.
type Tool struct {
	// Driver describes the component containing the tool’s
	// primary executable file.
	Driver Driver `json:"driver,omitempty"`
}

// Driver represents one of the components which comprise an analysis
// tool or a converter.
type Driver struct {
	// Name is the name of the tool component.
	Name string `json:"name,omitempty"`

	// Version is the tool component’s version in whatever format
	// the component natively provides.
	Version string `json:"semanticVersion,omitempty"`

	// InformationURI contains the absolute URI at which
	// information about this version of the tool component can be
	// found.
	InformationURI string `json:"informationUri,omitempty"`

	// Properties are govulncheck run metadata, such as vuln db, Go version, etc.
	Properties map[string]any `json:"properties,omitempty"`

	// Rules provides information about the analysis rules
	// supported by the tool component.
	Rules []Rule `json:"rules,omitempty"`
}

// Rule contains information that describes a "reporting item"
// generated by a tool. A reporting item is either a result produced
// by the tool’s analysis, or a notification of a condition
// encountered by the tool.
type Rule struct {
	// ID is the rule identifier.
	ID string `json:"id,omitempty"`

	// ShortDescription provides a concise description of the
	// reporting item.
	ShortDescription Description `json:"shortDescription,omitempty"`

	// FullDescription describes the reporting item.
	FullDescription Description `json:"fullDescription,omitempty"`

	// Help provides the primary documentation for the reporting
	// item.
	Help Description `json:"help,omitempty"`

	// HelpURI is the absolute URI of the primary documentation
	// for the reporting item.
	HelpURI string `json:"helpUri,omitempty"`

	// Properties is an unordered set of properties with arbitrary
	// names.
	Properties map[string]any `json:"properties,omitempty"`
}

// Description groups together all available textual formats for a
// message string.
type Description struct {
	// Text contains a plain text representation of the message.
	Text string `json:"text,omitempty"`

	// Markdown contains a formatted message expressed in
	// GitHub-Flavored Markdown.
	Markdown string `json:"markdown,omitempty"`
}

// Result describes a single result detected by an analysis tool.
type Result struct {
	// RuleID is the identifier of the rule that was evaluated to
	// produce the result.
	RuleID string `json:"ruleId,omitempty"`

	// Level specifies the severity level of the result.
	Level string `json:"level,omitempty"`

	// Message describes the result.
	Message Description `json:"message,omitempty"`

	// Locations specifies the locations where the result
	// occurred.
	Locations []Location `json:"locations,omitempty"`

	// CodeFlows is intended for use by analysis tools that
	// provide execution path details that illustrate a possible
	// problem in the code.
	CodeFlows []CodeFlow `json:"codeFlows,omitempty"`

	// Stacks is intended for use by analysis tools that compute
	// or collect call stack information in the process of
	// producing results.
	Stacks []Stack `json:"stacks,omitempty"`
}

// CodeFlow describes the progress of one or more programs through one
// or more thread flows, which together lead to the detection of a
// problem in the system being analyzed.
type CodeFlow struct {
	// ThreadFlows describes the progress of a program through a
	// single thread of execution such as an operating system
	// thread or a fiber.
	ThreadFlows []ThreadFlow `json:"threadFlows,omitempty"`

	// Message is a message object relevant to the code flow.
	Message Description `json:"message,omitempty"`
}

// ThreadFlow is a sequence of code locations that specify a possible
// path through a single thread of execution such as an operating
// system thread or a fiber.
type ThreadFlow struct {
	// Locations is a list locations visited by the tool in the
	// course of producing the result.
	Locations []ThreadFlowLocation `json:"locations,omitempty"`
}

// ThreadFlowLocation represents a location visited by an analysis
// tool in the course of simulating or monitoring the execution of a
// program.
type ThreadFlowLocation struct {
	// Module is the name of the module that contains the code
	// location specified by this [ThreadFlowLocation] value.
	Module string `json:"module,omitempty"`

	// Location specifies the location to which the
	// [ThreadFlowLocation] value refers.
	Location Location `json:"location,omitempty"`
}

// Stack describes a single call stack. A call stack is a sequence of
// nested function calls, each of which is referred to as a stack
// frame.
type Stack struct {
	// Message is a message relevant to this call stack.
	Message Description `json:"message,omitempty"`

	// Frames includes every function call in the stack for which
	// the tool has information.
	Frames []Frame `json:"frames,omitempty"`
}

// Frame describes a single stack frame within a call stack.
type Frame struct {
	// Module is the name of the module that contains the location
	// to which this stack frame refers.
	Module string `json:"module,omitempty"`

	// Location specifies the location to which this stack frame
	// refers.
	Location Location `json:"location,omitempty"`
}

// Location describes a location.
type Location struct {
	// PhysicalLocation identifies the file within which the
	// location lies.
	PhysicalLocation PhysicalLocation `json:"physicalLocation,omitempty"`

	// Message is a message relevant to the location.
	Message Description `json:"message,omitempty"`
}

// PhysicalLocation represents the physical location where a result
// was detected.
type PhysicalLocation struct {
	// ArtifactLocation represents the location of the artifact.
	ArtifactLocation ArtifactLocation `json:"artifactLocation,omitempty"`

	// Region represents a relevant portion of the artifact.
	Region Region `json:"region,omitempty"`
}

// String returns the string representation of the physical location.
func (loc PhysicalLocation) String() string {
	if (loc == PhysicalLocation{}) {
		return ""
	}

	s := path.Join(loc.ArtifactLocation.URIBaseID, loc.ArtifactLocation.URI)
	if loc.Region.StartLine != 0 {
		s += fmt.Sprintf(":%v", loc.Region.StartLine)
		if loc.Region.StartColumn != 0 {
			s += fmt.Sprintf(":%v", loc.Region.StartColumn)
		}
		if loc.Region.EndLine != 0 {
			s += fmt.Sprintf(",%v", loc.Region.EndLine)
			if loc.Region.EndColumn != 0 {
				s += fmt.Sprintf(":%v", loc.Region.EndColumn)
			}
		}
	}

	return s
}

// ArtifactLocation represents an artifact’s location.
type ArtifactLocation struct {
	// URI specifies the location of the artifact. It is relative
	// to [ArtifactLocation.URIBaseID].
	URI string `json:"uri,omitempty"`

	// URIBaseID describes a top-level artifact.
	URIBaseID string `json:"uriBaseId,omitempty"`
}

// Region represents a contiguous portion of an artifact.
type Region struct {
	// StartLine is the line number of the line containing the
	// first character in the region.
	StartLine int `json:"startLine,omitempty"`

	// StartColumn is the column number of the first character in
	// the region.
	StartColumn int `json:"startColumn,omitempty"`

	// EndLine is the line number of the line containing the last
	// character in the region.
	EndLine int `json:"endLine,omitempty"`

	// EndColumn is the column number of the last character in the
	// region.
	EndColumn int `json:"endColumn,omitempty"`
}
