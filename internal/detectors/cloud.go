package detectors

import (
	"regexp"
	"strings"

	"github.com/secretscan/secretscan/internal/entropy"
	"github.com/secretscan/secretscan/internal/models"
)

// AzureSASDetector detects Azure Shared Access Signature tokens.
type AzureSASDetector struct {
	BaseDetector
}

func NewAzureSASDetector() *AzureSASDetector {
	return &AzureSASDetector{
		BaseDetector: BaseDetector{
			name:     "azure-sas",
			typeName: "Azure SAS Token",
			severity: models.SeverityHigh,
			pattern:  regexp.MustCompile(`(?i)sig=[A-Za-z0-9%+/]{43,}`),
			keywords: []string{"azure", "blob", "storage", "sas", "SharedAccessSignature"},
		},
	}
}

func (d *AzureSASDetector) Detect(line string, lineNum int, filePath string) []models.Finding {
	if isFalsePositive(line) {
		return nil
	}
	return d.baseDetect(line, lineNum, filePath)
}

// AzureConnectionStringDetector detects Azure storage connection strings.
type AzureConnectionStringDetector struct {
	BaseDetector
}

func NewAzureConnectionStringDetector() *AzureConnectionStringDetector {
	return &AzureConnectionStringDetector{
		BaseDetector: BaseDetector{
			name:     "azure-connection",
			typeName: "Azure Connection String",
			severity: models.SeverityCritical,
			pattern:  regexp.MustCompile(`DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{44,}`),
		},
	}
}

func (d *AzureConnectionStringDetector) Detect(line string, lineNum int, filePath string) []models.Finding {
	if isFalsePositive(line) {
		return nil
	}
	matches := d.pattern.FindAllStringIndex(line, -1)
	if matches == nil {
		return nil
	}
	var findings []models.Finding
	for _, loc := range matches {
		findings = append(findings, models.Finding{
			Type:       d.typeName,
			Severity:   models.SeverityCritical,
			Confidence: 95,
			File:       filePath,
			Line:       lineNum,
			Column:     loc[0] + 1,
			Preview:    truncateContext(line, loc[0], loc[1]),
			Reason:     "Azure storage connection string with AccountKey detected",
			Detector:   d.name,
			Source:     models.SourceFilesystem,
		})
	}
	return findings
}

// GCPServiceAccountDetector detects GCP service account JSON key files.
type GCPServiceAccountDetector struct {
	BaseDetector
}

func NewGCPServiceAccountDetector() *GCPServiceAccountDetector {
	return &GCPServiceAccountDetector{
		BaseDetector: BaseDetector{
			name:     "gcp-service-account",
			typeName: "GCP Service Account Key",
			severity: models.SeverityCritical,
			pattern:  regexp.MustCompile(`"type"\s*:\s*"service_account"`),
		},
	}
}

func (d *GCPServiceAccountDetector) Detect(line string, lineNum int, filePath string) []models.Finding {
	if isFalsePositive(line) {
		return nil
	}
	if !d.pattern.MatchString(line) {
		return nil
	}

	// Only flag in JSON files or when nearby keys exist.
	lower := strings.ToLower(filePath)
	isJSON := strings.HasSuffix(lower, ".json")
	hasContext := strings.Contains(line, "private_key") || strings.Contains(line, "client_email")

	confidence := 60
	if isJSON {
		confidence = 85
	}
	if hasContext {
		confidence = 95
	}

	loc := d.pattern.FindStringIndex(line)
	return []models.Finding{{
		Type:       d.typeName,
		Severity:   models.SeverityCritical,
		Confidence: confidence,
		File:       filePath,
		Line:       lineNum,
		Column:     loc[0] + 1,
		Preview:    truncateContext(line, loc[0], loc[1]),
		Reason:     "GCP service account key file marker detected",
		Detector:   d.name,
		Source:     models.SourceFilesystem,
	}}
}

// GCPAPIKeyDetector detects GCP/Google API keys (AIza prefix).
type GCPAPIKeyDetector struct {
	BaseDetector
}

func NewGCPAPIKeyDetector() *GCPAPIKeyDetector {
	return &GCPAPIKeyDetector{
		BaseDetector: BaseDetector{
			name:     "gcp-api-key",
			typeName: "GCP API Key",
			severity: models.SeverityHigh,
			pattern:  regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`),
		},
	}
}

func (d *GCPAPIKeyDetector) Detect(line string, lineNum int, filePath string) []models.Finding {
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
		conf := computeConfidence(true, hasCtx, es, true)
		if conf < 25 {
			continue
		}
		findings = append(findings, models.Finding{
			Type:       d.typeName,
			Severity:   d.adjustSeverity(conf),
			Confidence: conf,
			File:       filePath,
			Line:       lineNum,
			Column:     loc[0] + 1,
			Preview:    truncateContext(line, loc[0], loc[1]),
			Reason:     buildReason("GCP API Key (AIza prefix)", hasCtx, kw, es, true),
			Detector:   d.name,
			Source:     models.SourceFilesystem,
		})
	}
	return findings
}
