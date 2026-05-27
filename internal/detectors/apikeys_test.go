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
				`OPENAI_API_KEY=sk-abc123def456ghi789jT3BlbkFJabc123def456ghi789j`,
				`sk-proj-abc123def456ghi789jabc123def456ghi789j`,
				`key: sk-abc123def456ghi789jabc123def456ghi789jabc123def`,
			},
			tns: []string{
				`OPENAI_API_KEY="your_api_key_here"`,
				`sk-placeholder-do-not-use-this-key`,
				`sk-xxxT3BlbkFJxxx`, // length/entropy too low but format matches? (might not match regex anyway, but if it does, confidence should be low)
			},
		},
		{
			name:     "Slack",
			detector: NewSlackTokenDetector(),
			tps: []string{
				`SLACK_TOKEN=xoxb-1234567890-1234567890-AbCdEfGhIjKl`,
				`slack_api_token: "xoxp-1234567890-1234567890-1234567890-AbCdEfGhIjKl"`,
				`https://hooks.slack.com/services/T12345678/B12345678/AbCdEfGhIjKlMnOpQrStUvWx`,
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
				`STRIPE_KEY="sk_live_4eC39HqLyjWDarjtT1zdp7dc"`,
				`stripe_secret: pk_test_TYooMQauvdEDq54NiTphI7jx`,
				`rk_live_1234567890abcdefGHIJKLMN`,
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
