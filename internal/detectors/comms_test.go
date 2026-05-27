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
				// AC prefix + 32 lowercase hex chars, not real SIDs.
				`TWILIO_SID=AC9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d`,
				`account_sid = "AC1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d"`,
				`export TWILIO_ACCOUNT_SID=AC0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a`,
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
				`TWILIO_AUTH_TOKEN=9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d`,
				`twilio_auth_token: "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d"`,
				`export TWILIO_AUTH_TOKEN=0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a`,
			},
			tns: []string{
				`TWILIO_AUTH_TOKEN=your_auth_token_here_xxxxxxxxx`,
				`TWILIO_AUTH_TOKEN=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`,
				`TWILIO_AUTH_TOKEN=placeholder`,
			},
		},
		{
			name:     "SendGrid",
			detector: NewSendGridDetector(),
			tps: []string{
				`SENDGRID_KEY=SG.Vb9Xr2Lm7nQp4KwJ01Hs8Y.Qr7Nj3Xp9Lm2Wd6Kf8Hb1Yv4Gs0Tc5Rn7Jp3Wm6Xd9Lb2K`,
				`sg_key: "SG.Wb4Nm8Jp3Rc6Fg5Mn2Kp9L.Hs8Yd3Rc6Fg5Mn2Kp9Lm7nQp4KwJ01Vb9Xr2Lm7nQp4KwJ0"`,
				`api_key="SG.0d1e2f3a4b5c6d7e8f9a0b.Qr7Nj3Xp9Lm2Wd6Kf8Hb1Yv4Gs0Tc5Rn7Jp3Wm6Xd9Lb2K"`,
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
				`MAILGUN_API_KEY=key-9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d`,
				`mailgun_key: "key-1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d"`,
				`export MAILGUN_KEY=key-0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a`,
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
