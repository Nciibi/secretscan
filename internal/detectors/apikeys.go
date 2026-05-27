package detectors

import (
	"regexp"

	"github.com/secretscan/secretscan/internal/entropy"
	"github.com/secretscan/secretscan/internal/models"
)

// OpenAIKeyDetector detects OpenAI API keys.
type OpenAIKeyDetector struct {
	BaseDetector
}

func NewOpenAIKeyDetector() *OpenAIKeyDetector {
	return &OpenAIKeyDetector{
		BaseDetector: BaseDetector{
			name:     "openai-key",
			typeName: "OpenAI API Key",
			severity: models.SeverityHigh,
			pattern:  regexp.MustCompile(`(?:^|[^A-Za-z0-9_-])(sk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,})(?:[^A-Za-z0-9_-]|$)`),
		},
	}
}

func (d *OpenAIKeyDetector) Detect(line string, lineNum int, filePath string) []models.Finding {
	if isFalsePositive(line) {
		return nil
	}

	// Also detect newer sk-proj- pattern.
	patterns := []*regexp.Regexp{
		d.pattern,
		regexp.MustCompile(`(?:^|[^A-Za-z0-9_-])(sk-proj-[A-Za-z0-9_-]{40,})(?:[^A-Za-z0-9_-]|$)`),
		regexp.MustCompile(`(?:^|[^A-Za-z0-9_-])(sk-[A-Za-z0-9]{48,})(?:[^A-Za-z0-9_-]|$)`),
	}

	var findings []models.Finding
	for _, pat := range patterns {
		if matches := pat.FindAllStringIndex(line, -1); matches != nil {
			for _, loc := range matches {
				matched := line[loc[0]:loc[1]]
				entropyScore := entropy.Score(matched)
				hasCtx, ctxKeyword := hasContextKeyword(line)
				confidence := computeConfidence(true, hasCtx, entropyScore, true)

				if confidence < 25 {
					continue
				}

				findings = append(findings, models.Finding{
					Type:       d.typeName,
					Severity:   d.adjustSeverity(confidence),
					Confidence: confidence,
					File:       filePath,
					Line:       lineNum,
					Column:     loc[0] + 1,
					Preview:    truncateContext(line, loc[0], loc[1]),
					Reason:     buildReason(d.typeName, hasCtx, ctxKeyword, entropyScore, true),
					Detector:   d.name,
					Source:     models.SourceFilesystem,
				})
			}
		}
	}
	return findings
}

// SlackTokenDetector detects Slack API tokens and webhooks.
type SlackTokenDetector struct {
	BaseDetector
	webhookPattern *regexp.Regexp
}

func NewSlackTokenDetector() *SlackTokenDetector {
	return &SlackTokenDetector{
		BaseDetector: BaseDetector{
			name:     "slack-token",
			typeName: "Slack Token",
			severity: models.SeverityHigh,
			pattern:  regexp.MustCompile(`(?:^|[^A-Za-z0-9_-])(xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*)(?:[^A-Za-z0-9_-]|$)`),
		},
		webhookPattern: regexp.MustCompile(`https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24}`),
	}
}

func (d *SlackTokenDetector) Detect(line string, lineNum int, filePath string) []models.Finding {
	if isFalsePositive(line) {
		return nil
	}

	var findings []models.Finding
	findings = append(findings, d.baseDetect(line, lineNum, filePath)...)

	// Webhook URLs.
	if matches := d.webhookPattern.FindAllStringIndex(line, -1); matches != nil {
		for _, loc := range matches {
			findings = append(findings, models.Finding{
				Type:       "Slack Webhook URL",
				Severity:   models.SeverityHigh,
				Confidence: 90,
				File:       filePath,
				Line:       lineNum,
				Column:     loc[0] + 1,
				Preview:    truncateContext(line, loc[0], loc[1]),
				Reason:     "Matched Slack webhook URL pattern",
				Detector:   d.name,
				Source:     models.SourceFilesystem,
			})
		}
	}

	return findings
}

// StripeKeyDetector detects Stripe API keys.
type StripeKeyDetector struct {
	BaseDetector
}

func NewStripeKeyDetector() *StripeKeyDetector {
	return &StripeKeyDetector{
		BaseDetector: BaseDetector{
			name:     "stripe-key",
			typeName: "Stripe API Key",
			severity: models.SeverityCritical,
			pattern:  regexp.MustCompile(`(?:^|[^A-Za-z0-9_-])((?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{24,})(?:[^A-Za-z0-9_-]|$)`),
		},
	}
}

func (d *StripeKeyDetector) Detect(line string, lineNum int, filePath string) []models.Finding {
	if isFalsePositive(line) {
		return nil
	}
	return d.baseDetect(line, lineNum, filePath)
}
