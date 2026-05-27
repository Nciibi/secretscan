package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/secretscan/secretscan/internal/models"
)

func sampleResult() models.ScanResult {
	return models.ScanResult{
		Findings: []models.Finding{
			{
				Type: "AWS Access Key", Severity: models.SeverityCritical,
				Confidence: 90, File: "config/.env", Line: 3, Column: 15,
				Preview: `AWS_KEY=AKIAIOSFODNN7EXAMPLE`, Reason: "Matched AWS key",
				Detector: "aws-key", Source: models.SourceFilesystem,
			},
			{
				Type: "Hardcoded Password", Severity: models.SeverityHigh,
				Confidence: 75, File: "app/config.py", Line: 10, Column: 12,
				Preview: `password = "s3cr3t"`, Reason: "Hardcoded password",
				Detector: "password", Source: models.SourceFilesystem,
			},
		},
		ScannedFiles: 42,
		Duration:     "123ms",
		ScanPath:     "./test",
		ScanMode:     "filesystem",
	}
}

func TestTextOutput(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf, "text")
	if err := w.Write(sampleResult()); err != nil {
		t.Fatal(err)
	}

	output := buf.String()
	if !strings.Contains(output, "secretscan") {
		t.Error("text output should contain tool name")
	}
	if !strings.Contains(output, "CRITICAL") {
		t.Error("text output should contain severity")
	}
	if !strings.Contains(output, "config/.env") {
		t.Error("text output should contain file path")
	}
}

func TestJSONOutput(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf, "json")
	if err := w.Write(sampleResult()); err != nil {
		t.Fatal(err)
	}

	var result models.ScanResult
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("JSON output is not valid: %v", err)
	}

	if len(result.Findings) != 2 {
		t.Errorf("expected 2 findings, got %d", len(result.Findings))
	}
	if result.ScannedFiles != 42 {
		t.Errorf("expected 42 files, got %d", result.ScannedFiles)
	}
}

func TestSARIFOutput(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf, "sarif")
	if err := w.Write(sampleResult()); err != nil {
		t.Fatal(err)
	}

	// Verify it's valid JSON.
	var raw map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("SARIF output is not valid JSON: %v", err)
	}

	// Check SARIF structure.
	if v, ok := raw["version"]; !ok || v != "2.1.0" {
		t.Error("SARIF should have version 2.1.0")
	}
	if _, ok := raw["runs"]; !ok {
		t.Error("SARIF should have runs array")
	}
}

func TestEmptyResult(t *testing.T) {
	result := models.ScanResult{
		ScannedFiles: 10,
		Duration:     "50ms",
		ScanPath:     ".",
		ScanMode:     "filesystem",
	}

	var buf bytes.Buffer
	w := NewWriter(&buf, "text")
	if err := w.Write(result); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "No secrets found") {
		t.Error("empty result should show 'No secrets found'")
	}
}
