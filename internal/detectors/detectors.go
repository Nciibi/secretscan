// Package detectors provides secret detection logic with multi-signal analysis.
// Each detector uses a combination of regex patterns, context keywords, entropy analysis,
// and type-specific validation to minimize false positives.
package detectors

import (
	"regexp"
	"strings"

	"github.com/secretscan/secretscan/internal/entropy"
	"github.com/secretscan/secretscan/internal/models"
)

// Detector interface defines how a secret detector works.
type Detector interface {
	// Name returns the detector's identifier.
	Name() string
	// Type returns the secret type this detector looks for.
	Type() string
	// Detect analyzes a line and returns any findings.
	Detect(line string, lineNum int, filePath string) []models.Finding
}

// contextKeywords are words that, when near a match, increase confidence.
var contextKeywords = []string{
	"key", "secret", "token", "password", "passwd", "pwd", "api_key",
	"apikey", "api-key", "access_key", "secret_key", "private_key",
	"auth", "credential", "bearer", "authorization", "connection_string",
	"database_url", "db_password", "encryption_key", "signing_key", "aws_key", "aws_access_key_id", "twilio",
}

// hasContextKeyword checks if any context keyword appears near the match.
func hasContextKeyword(line string) (bool, string) {
	lower := strings.ToLower(line)
	for _, kw := range contextKeywords {
		if strings.Contains(lower, kw) {
			return true, kw
		}
	}
	return false, ""
}

// isFalsePositive checks for common false positive patterns.
func isFalsePositive(line string) bool {
	lower := strings.ToLower(strings.TrimSpace(line))

	// Skip comments that reference documentation or examples.
	falsePatterns := []string{
		"example", "sample", "placeholder", "your_", "xxx", "todo",
		"fixme", "replace_me", "changeme", "insert_", "dummy",
		"<your", "{your", "${", "{{", "test_key", "fake",
		"sha256-", "sha512-", `"integrity":`,
	}
	for _, fp := range falsePatterns {
		if strings.Contains(lower, fp) {
			return true
		}
	}
	return false
}

// computeConfidence aggregates multiple signals into a confidence score.
func computeConfidence(regexMatch bool, hasContext bool, entropyScore int, specificValidation bool) int {
	score := 0

	if regexMatch {
		score += 30
	}
	if hasContext {
		score += 20
	}
	if entropyScore > 50 {
		score += 25
	} else if entropyScore > 30 {
		score += 15
	}
	if specificValidation {
		score += 25
	}

	if score > 100 {
		score = 100
	}
	return score
}

// BaseDetector provides common functionality for all detectors.
type BaseDetector struct {
	name     string
	typeName string
	severity models.Severity
	pattern  *regexp.Regexp
	keywords []string
}

func (d *BaseDetector) Name() string { return d.name }
func (d *BaseDetector) Type() string { return d.typeName }

func (d *BaseDetector) baseDetect(line string, lineNum int, filePath string) []models.Finding {
	if isFalsePositive(line) {
		return nil
	}

	matches := d.pattern.FindAllStringSubmatchIndex(line, -1)
	if len(matches) == 0 {
		return nil
	}

	var findings []models.Finding
	for _, loc := range matches {
		var start, end int
		if len(loc) >= 4 && loc[2] != -1 && loc[3] != -1 {
			start, end = loc[2], loc[3]
		} else {
			start, end = loc[0], loc[1]
		}
		matched := line[start:end]
		entropyScore := entropy.Score(matched)
		hasCtx, ctxKeyword := hasContextKeyword(line)

		confidence := computeConfidence(true, hasCtx, entropyScore, d.validate(matched))

		if confidence < 25 {
			continue // too low confidence
		}

		reason := buildReason(d.typeName, hasCtx, ctxKeyword, entropyScore, d.validate(matched))

		findings = append(findings, models.Finding{
			Type:         d.typeName,
			Severity:     d.adjustSeverity(confidence),
			Confidence:   confidence,
			File:         filePath,
			Line:         lineNum,
			Column:       start + 1,
			Preview:      truncateContext(line, start, end),
			Reason:       reason,
			Detector:     d.name,
			Source:       models.SourceFilesystem,
			MatchedValue: matched,
			LineContent:  line,
		})
	}
	return findings
}

func (d *BaseDetector) validate(match string) bool {
	// Default validation: check entropy is reasonable.
	return entropy.Shannon(match) > 3.5
}

func (d *BaseDetector) adjustSeverity(confidence int) models.Severity {
	if confidence >= 80 {
		return d.severity
	}
	if confidence >= 60 {
		if d.severity == models.SeverityCritical {
			return models.SeverityHigh
		}
		return d.severity
	}
	if confidence >= 40 {
		return models.SeverityMedium
	}
	return models.SeverityLow
}

func buildReason(secretType string, hasCtx bool, ctxKeyword string, entropyScore int, validated bool) string {
	parts := []string{"Matched " + secretType + " pattern"}
	if hasCtx {
		parts = append(parts, "context keyword '"+ctxKeyword+"' found nearby")
	}
	if entropyScore > 50 {
		parts = append(parts, "high entropy detected")
	}
	if validated {
		parts = append(parts, "passed type-specific validation")
	}
	return strings.Join(parts, "; ")
}

func truncateContext(line string, start, end int) string {
	// Show some context around the match.
	contextChars := 20
	s := start - contextChars
	if s < 0 {
		s = 0
	}
	e := end + contextChars
	if e > len(line) {
		e = len(line)
	}

	preview := line[s:e]
	if s > 0 {
		preview = "..." + preview
	}
	if e < len(line) {
		preview = preview + "..."
	}

	if len(preview) > 120 {
		preview = preview[:117] + "..."
	}
	return preview
}
