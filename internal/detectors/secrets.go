package detectors

import (
	"regexp"
	"strings"

	"github.com/secretscan/secretscan/internal/entropy"
	"github.com/secretscan/secretscan/internal/models"
)

// PrivateKeyDetector detects RSA/PEM/SSH private keys.
type PrivateKeyDetector struct {
	BaseDetector
}

func NewPrivateKeyDetector() *PrivateKeyDetector {
	return &PrivateKeyDetector{
		BaseDetector: BaseDetector{
			name:     "private-key",
			typeName: "Private Key",
			severity: models.SeverityCritical,
			pattern:  regexp.MustCompile(`-----BEGIN\s+(RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY( BLOCK)?-----`),
		},
	}
}

func (d *PrivateKeyDetector) Detect(line string, lineNum int, filePath string) []models.Finding {
	if isFalsePositive(line) {
		return nil
	}
	findings := d.baseDetect(line, lineNum, filePath)
	// Override confidence for private keys — pattern is very specific.
	for i := range findings {
		findings[i].Confidence = 95
		findings[i].Severity = models.SeverityCritical
		findings[i].Reason = "PEM/RSA private key header detected — this is almost certainly a real private key"
	}
	return findings
}

// FirebaseDetector detects Firebase configuration values.
type FirebaseDetector struct {
	BaseDetector
	configPattern *regexp.Regexp
}

func NewFirebaseDetector() *FirebaseDetector {
	return &FirebaseDetector{
		BaseDetector: BaseDetector{
			name:     "firebase",
			typeName: "Firebase Config",
			severity: models.SeverityMedium,
			pattern:  regexp.MustCompile(`(?i)(?:firebase|firebaseio\.com)[A-Za-z0-9_]*\s*[=:]\s*['"]?([A-Za-z0-9_-]{20,})['"]?`),
		},
		configPattern: regexp.MustCompile(`AIza[0-9A-Za-z_-]{35}`),
	}
}

func (d *FirebaseDetector) Detect(line string, lineNum int, filePath string) []models.Finding {
	if isFalsePositive(line) {
		return nil
	}

	var findings []models.Finding
	findings = append(findings, d.baseDetect(line, lineNum, filePath)...)

	// Also detect Google API keys (used in Firebase).
	if matches := d.configPattern.FindAllStringIndex(line, -1); matches != nil {
		for _, loc := range matches {
			matched := line[loc[0]:loc[1]]
			hasCtx, ctxKeyword := hasContextKeyword(line)

			confidence := computeConfidence(true, hasCtx, entropy.Score(matched), true)
			findings = append(findings, models.Finding{
				Type:       "Google API Key",
				Severity:   models.SeverityHigh,
				Confidence: confidence,
				File:       filePath,
				Line:       lineNum,
				Column:     loc[0] + 1,
				Preview:    truncateContext(line, loc[0], loc[1]),
				Reason:     buildReason("Google/Firebase API Key", hasCtx, ctxKeyword, entropy.Score(matched), true),
				Detector:   d.name,
				Source:     models.SourceFilesystem,
			})
		}
	}

	return findings
}

// JWTDetector detects JWT tokens and signing secrets in code/config.
type JWTDetector struct {
	BaseDetector
	secretPattern *regexp.Regexp
}

func NewJWTDetector() *JWTDetector {
	return &JWTDetector{
		BaseDetector: BaseDetector{
			name:     "jwt",
			typeName: "JWT Token",
			severity: models.SeverityHigh,
			pattern:  regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`),
		},
		secretPattern: regexp.MustCompile(`(?i)(?:jwt[_-]?secret|jwt[_-]?key|signing[_-]?secret|signing[_-]?key)\s*[=:]\s*['"]?([A-Za-z0-9/+=_-]{16,})['"]?`),
	}
}

func (d *JWTDetector) Detect(line string, lineNum int, filePath string) []models.Finding {
	if isFalsePositive(line) {
		return nil
	}

	var findings []models.Finding

	// Detect full JWT tokens embedded in source.
	if matches := d.pattern.FindAllStringIndex(line, -1); matches != nil {
		for _, loc := range matches {
			findings = append(findings, models.Finding{
				Type:       "JWT Token",
				Severity:   models.SeverityHigh,
				Confidence: 85,
				File:       filePath,
				Line:       lineNum,
				Column:     loc[0] + 1,
				Preview:    truncateContext(line, loc[0], loc[1]),
				Reason:     "Embedded JWT token detected (eyJ header with three base64 segments)",
				Detector:   d.name,
				Source:     models.SourceFilesystem,
			})
		}
	}

	// Detect JWT signing secrets in config.
	if matches := d.secretPattern.FindAllStringSubmatchIndex(line, -1); matches != nil {
		for _, loc := range matches {
			if len(loc) >= 4 {
				matched := line[loc[2]:loc[3]]
				entropyScore := entropy.Score(matched)

				if entropyScore < 30 {
					continue
				}

				confidence := computeConfidence(true, true, entropyScore, false)
				findings = append(findings, models.Finding{
					Type:       "JWT Signing Secret",
					Severity:   models.SeverityCritical,
					Confidence: confidence,
					File:       filePath,
					Line:       lineNum,
					Column:     loc[2] + 1,
					Preview:    truncateContext(line, loc[2], loc[3]),
					Reason:     "JWT signing secret/key assignment detected",
					Detector:   d.name,
					Source:     models.SourceFilesystem,
				})
			}
		}
	}

	return findings
}

// GenericHighEntropyDetector detects high-entropy strings that look like secrets.
type GenericHighEntropyDetector struct {
	BaseDetector
	threshold float64
}

func NewGenericHighEntropyDetector(threshold float64) *GenericHighEntropyDetector {
	if threshold <= 0 {
		threshold = 4.5
	}
	return &GenericHighEntropyDetector{
		BaseDetector: BaseDetector{
			name:     "high-entropy",
			typeName: "High Entropy String",
			severity: models.SeverityMedium,
			// Match assignments of long strings.
			pattern: regexp.MustCompile(`(?i)(?:key|secret|token|password|api_key|apikey|auth|credential|private|signing)\s*[=:]\s*['"]([A-Za-z0-9/+=_-]{20,})['"]`),
		},
		threshold: threshold,
	}
}

func (d *GenericHighEntropyDetector) Detect(line string, lineNum int, filePath string) []models.Finding {
	if isFalsePositive(line) {
		return nil
	}

	matches := d.pattern.FindAllStringSubmatchIndex(line, -1)
	if matches == nil {
		return nil
	}

	var findings []models.Finding
	for _, loc := range matches {
		if len(loc) < 4 {
			continue
		}
		matched := line[loc[2]:loc[3]]

		// Must have high entropy.
		e := entropy.Shannon(matched)
		if e < d.threshold {
			continue
		}

		// Skip common non-secret patterns.
		if isLikelyNotSecret(matched) {
			continue
		}

		entropyScore := entropy.Score(matched)
		_, ctxKeyword := hasContextKeyword(line)
		confidence := computeConfidence(true, true, entropyScore, false)

		if confidence < 35 {
			continue
		}

		findings = append(findings, models.Finding{
			Type:       d.typeName,
			Severity:   d.adjustSeverity(confidence),
			Confidence: confidence,
			File:       filePath,
			Line:       lineNum,
			Column:     loc[2] + 1,
			Preview:    truncateContext(line, loc[2], loc[3]),
			Reason:     buildReason("high entropy string near context keyword '"+ctxKeyword+"'", true, ctxKeyword, entropyScore, false),
			Detector:   d.name,
			Source:     models.SourceFilesystem,
		})
	}
	return findings
}

// GenericPasswordDetector detects hardcoded passwords.
type GenericPasswordDetector struct {
	BaseDetector
}

func NewGenericPasswordDetector() *GenericPasswordDetector {
	return &GenericPasswordDetector{
		BaseDetector: BaseDetector{
			name:     "password",
			typeName: "Hardcoded Password",
			severity: models.SeverityHigh,
			pattern:  regexp.MustCompile(`(?i)(?:password|passwd|pwd|pass)\s*[=:]\s*['"]([^'"]{8,})['"]`),
		},
	}
}

func (d *GenericPasswordDetector) Detect(line string, lineNum int, filePath string) []models.Finding {
	if isFalsePositive(line) {
		return nil
	}

	matches := d.pattern.FindAllStringSubmatchIndex(line, -1)
	if matches == nil {
		return nil
	}

	var findings []models.Finding
	for _, loc := range matches {
		if len(loc) < 4 {
			continue
		}
		matched := line[loc[2]:loc[3]]

		// Skip very low entropy passwords (likely placeholders).
		e := entropy.Shannon(matched)
		if e < 2.5 {
			continue
		}

		entropyScore := entropy.Score(matched)
		confidence := computeConfidence(true, true, entropyScore, e > 3.5)

		if confidence < 30 {
			continue
		}

		findings = append(findings, models.Finding{
			Type:       d.typeName,
			Severity:   d.adjustSeverity(confidence),
			Confidence: confidence,
			File:       filePath,
			Line:       lineNum,
			Column:     loc[2] + 1,
			Preview:    truncateContext(line, loc[2], loc[3]),
			Reason:     "Hardcoded password assignment detected",
			Detector:   d.name,
			Source:     models.SourceFilesystem,
		})
	}
	return findings
}

// ConnectionStringDetector detects database connection strings.
type ConnectionStringDetector struct {
	BaseDetector
}

func NewConnectionStringDetector() *ConnectionStringDetector {
	return &ConnectionStringDetector{
		BaseDetector: BaseDetector{
			name:     "connection-string",
			typeName: "Database Connection String",
			severity: models.SeverityHigh,
			pattern:  regexp.MustCompile(`(?i)(?:mongodb|postgres|postgresql|mysql|redis|amqp|mssql)://[^\s'"]{10,}`),
		},
	}
}

func (d *ConnectionStringDetector) Detect(line string, lineNum int, filePath string) []models.Finding {
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

		// Check if it contains credentials (user:pass@).
		hasCredentials := strings.Contains(matched, "@") && strings.Contains(matched, ":")
		confidence := 50
		if hasCredentials {
			confidence = 85
		}

		findings = append(findings, models.Finding{
			Type:       d.typeName,
			Severity:   d.adjustSeverity(confidence),
			Confidence: confidence,
			File:       filePath,
			Line:       lineNum,
			Column:     loc[0] + 1,
			Preview:    truncateContext(line, loc[0], loc[1]),
			Reason:     "Database connection string detected",
			Detector:   d.name,
			Source:     models.SourceFilesystem,
		})
	}
	return findings
}

func isLikelyNotSecret(s string) bool {
	lower := strings.ToLower(s)

	// Common non-secret patterns.
	nonSecretPatterns := []string{
		"abcdef", "123456", "qwerty", "aaaaaa", "000000",
	}
	for _, p := range nonSecretPatterns {
		if strings.Contains(lower, p) {
			return true
		}
	}

	// Check if it's all the same character repeated.
	if len(s) > 0 {
		allSame := true
		first := rune(s[0])
		for _, r := range s[1:] {
			if r != first {
				allSame = false
				break
			}
		}
		if allSame {
			return true
		}
	}

	return false
}
