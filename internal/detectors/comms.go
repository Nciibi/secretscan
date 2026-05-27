package detectors

import (
	"regexp"

	"github.com/secretscan/secretscan/internal/entropy"
	"github.com/secretscan/secretscan/internal/models"
)

// TwilioSIDDetector detects Twilio Account SIDs.
type TwilioSIDDetector struct {
	BaseDetector
}

func NewTwilioSIDDetector() *TwilioSIDDetector {
	return &TwilioSIDDetector{
		BaseDetector: BaseDetector{
			name:     "twilio-sid",
			typeName: "Twilio Account SID",
			severity: models.SeverityHigh,
			pattern:  regexp.MustCompile(`(?:^|[^A-Za-z0-9])(AC[a-z0-9]{32})(?:[^A-Za-z0-9]|$)`),
			keywords: []string{"twilio", "account_sid", "TWILIO"},
		},
	}
}

func (d *TwilioSIDDetector) Detect(line string, lineNum int, filePath string) []models.Finding {
	if isFalsePositive(line) {
		return nil
	}
	return d.baseDetect(line, lineNum, filePath)
}

// TwilioAuthTokenDetector detects Twilio auth tokens via context keywords.
type TwilioAuthTokenDetector struct {
	BaseDetector
}

func NewTwilioAuthTokenDetector() *TwilioAuthTokenDetector {
	return &TwilioAuthTokenDetector{
		BaseDetector: BaseDetector{
			name:     "twilio-auth",
			typeName: "Twilio Auth Token",
			severity: models.SeverityHigh,
			pattern:  regexp.MustCompile(`(?i)(?:twilio[_-]?auth[_-]?token|TWILIO_AUTH_TOKEN)\s*[=:]\s*['"]?([a-f0-9]{32})['"]?`),
			keywords: []string{"twilio", "auth_token"},
		},
	}
}

func (d *TwilioAuthTokenDetector) Detect(line string, lineNum int, filePath string) []models.Finding {
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
		es := entropy.Score(matched)
		conf := computeConfidence(true, true, es, true)
		if conf < 30 {
			continue
		}
		findings = append(findings, models.Finding{
			Type:       d.typeName,
			Severity:   models.SeverityHigh,
			Confidence: conf,
			File:       filePath,
			Line:       lineNum,
			Column:     loc[2] + 1,
			Preview:    truncateContext(line, loc[2], loc[3]),
			Reason:     "Twilio auth token detected via context keyword",
			Detector:   d.name,
			Source:     models.SourceFilesystem,
		})
	}
	return findings
}

// SendGridDetector detects SendGrid API keys.
type SendGridDetector struct {
	BaseDetector
}

func NewSendGridDetector() *SendGridDetector {
	return &SendGridDetector{
		BaseDetector: BaseDetector{
			name:     "sendgrid",
			typeName: "SendGrid API Key",
			severity: models.SeverityHigh,
			pattern:  regexp.MustCompile(`SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}`),
		},
	}
}

func (d *SendGridDetector) Detect(line string, lineNum int, filePath string) []models.Finding {
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
			Severity:   models.SeverityHigh,
			Confidence: 90,
			File:       filePath,
			Line:       lineNum,
			Column:     loc[0] + 1,
			Preview:    truncateContext(line, loc[0], loc[1]),
			Reason:     "SendGrid API key pattern matched (SG.xxx.xxx format)",
			Detector:   d.name,
			Source:     models.SourceFilesystem,
		})
	}
	return findings
}

// MailgunDetector detects Mailgun API keys.
type MailgunDetector struct {
	BaseDetector
}

func NewMailgunDetector() *MailgunDetector {
	return &MailgunDetector{
		BaseDetector: BaseDetector{
			name:     "mailgun",
			typeName: "Mailgun API Key",
			severity: models.SeverityHigh,
			pattern:  regexp.MustCompile(`(?:^|[^A-Za-z0-9_-])(key-[0-9a-z]{32})(?:[^A-Za-z0-9_-]|$)`),
			keywords: []string{"mailgun", "MAILGUN"},
		},
	}
}

func (d *MailgunDetector) Detect(line string, lineNum int, filePath string) []models.Finding {
	if isFalsePositive(line) {
		return nil
	}
	return d.baseDetect(line, lineNum, filePath)
}
