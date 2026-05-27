package detectors

import (
	"testing"
)

func TestAPIKeysDetectors(t *testing.T) {
	tests := []struct {
		name     string
		detector Detector
		tps      []string
		tns      []string
	}{
		{
			name:     "OpenAI",
			detector: NewOpenAIKeyDetector(),
			tps: []string{
				// These match the sk-...T3BlbkFJ... pattern but are revoked/invalid values.
				`OPENAI_API_KEY=sk-Vb9Xr2Lm7nQp4KwJ01AAT3BlbkFJHs8Yd3Rc6Fg5Mn2Kp9xAA`,
				`openai_secret: "sk-Wb4Nm8Jp3Rc6Fg5Mn2Kp9BBT3BlbkFJp4KwJ01Hs8Yd3Rc6FgBB"`,
				`Bearer sk-Qr7Nj3Xp9Lm2Wd6Kf8Hb1CCT3BlbkFJTc5Rn7Jp3Wm6Xd9Lb2KCC`,
			},
			tns: []string{
				`OPENAI_API_KEY="your_api_key_here"`,
				`sk-placeholder-do-not-use-this-key`,
				`sk-xxxT3BlbkFJxxx`,
			},
		},
		{
			name:     "Slack",
			detector: NewSlackTokenDetector(),
			tps: []string{
				`SLACK_TOKEN=xoxb-9876543210-9876543210-Vb3Xr7Lm2Kp`,
				`slack_api_token: "xoxp-9876543210-9876543210-9876543210-Wb4Nm8Jp3Rc"`,
				`https://hooks.slack.com/services/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`,
			},
			tns: []string{
				`SLACK_TOKEN=xoxb-your-token-here`,
				`SLACK_TOKEN=xoxb-xxxxxxxxxx-xxxxxxxxxx-xxxxxxxxxxxx`,
				`https://hooks.slack.com/services/T00000000/B00000000/xxxxxxxxxxxxxxxxxxxxxxxx`,
			},
		},
		{
			name:     "Stripe",
			detector: NewStripeKeyDetector(),
			tps: []string{
				`STRIPE_KEY="sk_live_Vb9Xr2Lm7nQp4KwJ01Hs8Yd3"`,
				`stripe_secret: pk_live_Wb4Nm8Jp3Rc6Fg5Mn2Kp9Lm7`,
				`rk_live_Qr7Nj3Xp9Lm2Wd6Kf8Hb1Yv4Gs`,
			},
			tns: []string{
				`STRIPE_KEY="sk_test_example_key_do_not_use"`,
				`STRIPE_KEY="your_stripe_key"`,
				`sk_live_xxxxxxxxxxxxxxxxxxxxxxxx`,
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
