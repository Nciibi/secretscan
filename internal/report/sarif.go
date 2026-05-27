package report

import (
	"encoding/json"

	"github.com/secretscan/secretscan/internal/models"
)

// SARIF output structures conforming to SARIF v2.1.0 schema.

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name    string      `json:"name"`
	Version string      `json:"version"`
	Rules   []sarifRule `json:"rules,omitempty"`
}

type sarifRule struct {
	ID               string          `json:"id"`
	Name             string          `json:"name"`
	ShortDescription sarifMessage    `json:"shortDescription"`
	DefaultConfig    sarifRuleConfig `json:"defaultConfiguration"`
}

type sarifRuleConfig struct {
	Level string `json:"level"`
}

type sarifResult struct {
	RuleID     string          `json:"ruleId"`
	Level      string          `json:"level"`
	Message    sarifMessage    `json:"message"`
	Locations  []sarifLocation `json:"locations"`
	Properties map[string]any  `json:"properties,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           sarifRegion   `json:"region"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn"`
}

func (rw *Writer) writeSARIF(result models.ScanResult) error {
	ruleMap := make(map[string]bool)
	var rules []sarifRule
	for _, f := range result.Findings {
		if !ruleMap[f.Detector] {
			ruleMap[f.Detector] = true
			rules = append(rules, sarifRule{
				ID:   f.Detector,
				Name: f.Type,
				ShortDescription: sarifMessage{
					Text: "Detects " + f.Type + " in source code and configuration",
				},
				DefaultConfig: sarifRuleConfig{
					Level: severityToSARIFLevel(f.Severity),
				},
			})
		}
	}

	var results []sarifResult
	for _, f := range result.Findings {
		props := map[string]any{
			"confidence": f.Confidence,
			"source":     f.Source,
			"preview":    f.Preview,
		}
		if f.Validation != "" {
			props["validation"] = f.Validation
		}
		if f.EncodingType != "" {
			props["encoding"] = f.EncodingType
		}

		results = append(results, sarifResult{
			RuleID:  f.Detector,
			Level:   severityToSARIFLevel(f.Severity),
			Message: sarifMessage{Text: f.Reason},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysical{
					ArtifactLocation: sarifArtifact{URI: f.File},
					Region: sarifRegion{
						StartLine:   f.Line,
						StartColumn: f.Column,
					},
				},
			}},
			Properties: props,
		})
	}

	log := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{
				Driver: sarifDriver{
					Name:    "secretscan",
					Version: "2.0.0",
					Rules:   rules,
				},
			},
			Results: results,
		}},
	}

	enc := json.NewEncoder(rw.w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

func severityToSARIFLevel(s models.Severity) string {
	switch s {
	case models.SeverityCritical, models.SeverityHigh:
		return "error"
	case models.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}
