package detectors

import (
	"testing"
)

func TestCommsDetectors(t *testing.T) {
	tests := []struct {
		name     string
		detector Detector
		tps      []string
		tns      []string
	}{
		{
			name:     "TwilioSID",
			detector: NewTwilioSIDDetector(),
			tps: []string{
				`TWILIO_SID=AC1234567890abcdef1234567890abcdef`,
				`account_sid = "ACabcdef1234567890abcdef1234567890"`,
				`export TWILIO_ACCOUNT_SID=AC11111111111111111111111111111111`,
			},
			tns: []string{
				`TWILIO_SID=ACyour_account_sid_here_xxxxxxxxx`,
				`TWILIO_SID=ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`,
				`TWILIO_SID=ACplaceholder`, // Too short, shouldn't match regex
			},
		},
		{
			name:     "TwilioAuthToken",
			detector: NewTwilioAuthTokenDetector(),
			tps: []string{
				`TWILIO_AUTH_TOKEN=1234567890abcdef1234567890abcdef`,
				`twilio_auth_token: "abcdef1234567890abcdef1234567890"`,
				`export TWILIO_AUTH_TOKEN=0987654321fedcba0987654321fedcba`,
			},
			tns: []string{
				`TWILIO_AUTH_TOKEN=your_auth_token_here_xxxxxxxxx`, // May not match hex regex, or low entropy
				`TWILIO_AUTH_TOKEN=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`,
				`TWILIO_AUTH_TOKEN=placeholder`,
			},
		},
		{
			name:     "SendGrid",
			detector: NewSendGridDetector(),
			tps: []string{
				`SENDGRID_KEY=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`,
				`sg_key: "SG.ABCDEFGHIJKLMNOPQRSTUV.abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ"`,
				`api_key="SG.1234567890123456789012.1234567890123456789012345678901234567890123"`,
			},
			tns: []string{
				`SENDGRID_KEY=SG.your_api_key_here.your_api_key_here_xxxx`,
				`SENDGRID_KEY=SG.xxxxxxxxxxxxxxxxxxxxxx.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`,
				`SENDGRID_KEY=SG.placeholder`,
			},
		},
		{
			name:     "Mailgun",
			detector: NewMailgunDetector(),
			tps: []string{
				`MAILGUN_API_KEY=key-1234567890abcdef1234567890abcdef`,
				`mailgun_key: "key-abcdef1234567890abcdef1234567890"`,
				`export MAILGUN_KEY=key-0987654321fedcba0987654321fedcba`,
			},
			tns: []string{
				`MAILGUN_API_KEY=key-your_api_key_here_xxxxxxxxx`,
				`MAILGUN_API_KEY=key-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`,
				`MAILGUN_API_KEY=key-placeholder`,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Run("True Positives", func(t *testing.T) {
				for _, tc := range tt.tps {
					findings := tt.detector.Detect(tc, 1, "test.txt")
					if len(findings) == 0 {
						t.Errorf("Expected finding for %s, got none", tc)
						continue
					}
					if findings[0].Confidence < 50 {
						t.Errorf("Expected confidence >= 50 for %s, got %d", tc, findings[0].Confidence)
					}
				}
			})

			t.Run("True Negatives", func(t *testing.T) {
				for _, tc := range tt.tns {
					findings := tt.detector.Detect(tc, 1, "test.txt")
					for _, f := range findings {
						if f.Confidence >= 25 {
							t.Errorf("Expected confidence < 25 for %s, got %d", tc, f.Confidence)
						}
					}
				}
			})
		})
	}
}
