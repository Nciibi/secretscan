package detectors

import (
	"regexp"
	"strings"

	"github.com/secretscan/secretscan/internal/entropy"
	"github.com/secretscan/secretscan/internal/models"
)

// NPMTokenDetector detects npm access tokens.
type NPMTokenDetector struct {
	BaseDetector
}

func NewNPMTokenDetector() *NPMTokenDetector {
	return &NPMTokenDetector{
		BaseDetector: BaseDetector{
			name:     "npm-token",
			typeName: "npm Token",
			severity: models.SeverityHigh,
			pattern:  regexp.MustCompile(`(?:^|[^A-Za-z0-9_-])(npm_[A-Za-z0-9]{36})(?:[^A-Za-z0-9_-]|$)`),
		},
	}
}

func (d *NPMTokenDetector) Detect(line string, lineNum int, filePath string) []models.Finding {
	if isFalsePositive(line) {
		return nil
	}
	return d.baseDetect(line, lineNum, filePath)
}

// PyPITokenDetector detects PyPI API tokens.
type PyPITokenDetector struct {
	BaseDetector
}

func NewPyPITokenDetector() *PyPITokenDetector {
	return &PyPITokenDetector{
		BaseDetector: BaseDetector{
			name:     "pypi-token",
			typeName: "PyPI API Token",
			severity: models.SeverityHigh,
			pattern:  regexp.MustCompile(`(?:^|[^A-Za-z0-9_-])(pypi-[A-Za-z0-9_-]{50,})(?:[^A-Za-z0-9_-]|$)`),
		},
	}
}

func (d *PyPITokenDetector) Detect(line string, lineNum int, filePath string) []models.Finding {
	if isFalsePositive(line) {
		return nil
	}
	return d.baseDetect(line, lineNum, filePath)
}

// DockerHubTokenDetector detects Docker Hub personal access tokens.
type DockerHubTokenDetector struct {
	BaseDetector
}

func NewDockerHubTokenDetector() *DockerHubTokenDetector {
	return &DockerHubTokenDetector{
		BaseDetector: BaseDetector{
			name:     "dockerhub-token",
			typeName: "Docker Hub Token",
			severity: models.SeverityHigh,
			pattern:  regexp.MustCompile(`(?:^|[^A-Za-z0-9_-])(dckr_pat_[A-Za-z0-9_-]{27})(?:[^A-Za-z0-9_-]|$)`),
		},
	}
}

func (d *DockerHubTokenDetector) Detect(line string, lineNum int, filePath string) []models.Finding {
	if isFalsePositive(line) {
		return nil
	}
	return d.baseDetect(line, lineNum, filePath)
}

// CloudflareTokenDetector detects Cloudflare API tokens via context keywords.
type CloudflareTokenDetector struct {
	BaseDetector
}

func NewCloudflareTokenDetector() *CloudflareTokenDetector {
	return &CloudflareTokenDetector{
		BaseDetector: BaseDetector{
			name:     "cloudflare-token",
			typeName: "Cloudflare API Token",
			severity: models.SeverityHigh,
			pattern:  regexp.MustCompile(`(?i)(?:cloudflare|cf)[_-]?(?:api[_-]?)?(?:token|key)\s*[=:]\s*['"]?([A-Za-z0-9_-]{40})['"]?`),
			keywords: []string{"cloudflare", "CF_API", "CLOUDFLARE"},
		},
	}
}

func (d *CloudflareTokenDetector) Detect(line string, lineNum int, filePath string) []models.Finding {
	if isFalsePositive(line) {
		return nil
	}

	lower := strings.ToLower(line)
	if !strings.Contains(lower, "cloudflare") && !strings.Contains(lower, "cf_api") {
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
		es := entropy.Score(matched)
		conf := computeConfidence(true, true, es, entropy.Shannon(matched) > 3.5)
		if conf < 30 {
			continue
		}
		findings = append(findings, models.Finding{
			Type:       d.typeName,
			Severity:   d.adjustSeverity(conf),
			Confidence: conf,
			File:       filePath,
			Line:       lineNum,
			Column:     loc[2] + 1,
			Preview:    truncateContext(line, loc[2], loc[3]),
			Reason:     "Cloudflare API token detected with context keyword",
			Detector:   d.name,
			Source:     models.SourceFilesystem,
		})
	}
	return findings
}

// VaultTokenDetector detects HashiCorp Vault tokens.
type VaultTokenDetector struct {
	BaseDetector
}

func NewVaultTokenDetector() *VaultTokenDetector {
	return &VaultTokenDetector{
		BaseDetector: BaseDetector{
			name:     "vault-token",
			typeName: "HashiCorp Vault Token",
			severity: models.SeverityCritical,
			pattern:  regexp.MustCompile(`(?:^|[^A-Za-z0-9._-])(s\.[A-Za-z0-9]{24})(?:[^A-Za-z0-9._-]|$)`),
			keywords: []string{"vault", "VAULT_TOKEN", "vault_token"},
		},
	}
}

func (d *VaultTokenDetector) Detect(line string, lineNum int, filePath string) []models.Finding {
	if isFalsePositive(line) {
		return nil
	}

	lower := strings.ToLower(line)
	hasVaultCtx := strings.Contains(lower, "vault")

	matches := d.pattern.FindAllStringIndex(line, -1)
	if matches == nil {
		return nil
	}

	var findings []models.Finding
	for _, loc := range matches {
		matched := line[loc[0]:loc[1]]
		es := entropy.Score(matched)
		conf := computeConfidence(true, hasVaultCtx, es, true)

		// Require vault context since s.xxx is a short pattern.
		if !hasVaultCtx {
			conf -= 20
		}
		if conf < 30 {
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
			Reason:     "HashiCorp Vault token pattern (s.xxx) detected",
			Detector:   d.name,
			Source:     models.SourceFilesystem,
		})
	}
	return findings
}
