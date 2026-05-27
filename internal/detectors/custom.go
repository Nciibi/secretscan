package detectors

import (
	"regexp"

	"github.com/secretscan/secretscan/internal/entropy"
	"github.com/secretscan/secretscan/internal/models"
)

// CustomDetector supports user-defined regex patterns from the config.
type CustomDetector struct {
	BaseDetector
}

func NewCustomDetector(p models.DetectorPattern) (*CustomDetector, error) {
	compiled, err := regexp.Compile(p.Pattern)
	if err != nil {
		return nil, err
	}
	sev := p.Severity
	if sev == "" {
		sev = models.SeverityMedium
	}
	return &CustomDetector{
		BaseDetector: BaseDetector{
			name: "custom-" + p.Name, typeName: p.Name, severity: sev,
			pattern: compiled, keywords: p.Keywords,
		},
	}, nil
}

func (d *CustomDetector) Detect(line string, lineNum int, filePath string) []models.Finding {
	if isFalsePositive(line) {
		return nil
	}
	matches := d.pattern.FindAllStringIndex(line, -1)
	if matches == nil {
		return nil
	}
	var findings []models.Finding
	for _, loc := range matches {
		matched := line[loc[0]:loc[1]]
		es := entropy.Score(matched)
		hasCtx, kw := hasContextKeyword(line)
		conf := computeConfidence(true, hasCtx, es, false)
		if conf < 25 {
			continue
		}
		findings = append(findings, models.Finding{
			Type: d.typeName, Severity: d.adjustSeverity(conf), Confidence: conf,
			File: filePath, Line: lineNum, Column: loc[0] + 1,
			Preview: truncateContext(line, loc[0], loc[1]),
			Reason: buildReason("custom pattern '"+d.typeName+"'", hasCtx, kw, es, false),
			Detector: d.name, Source: models.SourceFilesystem,
		})
	}
	return findings
}
