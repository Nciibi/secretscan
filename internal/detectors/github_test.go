package detectors

import (
	"testing"
)

func TestGitHubTokenDetector(t *testing.T) {
	detector := NewGitHubTokenDetector()

	t.Run("True Positives", func(t *testing.T) {
		tests := []string{
			`token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn"`,
			`GITHUB_TOKEN=ghp_R4nd0mT0k3nV4lu3W1thM0r3Ch4r4ct3rsHere`,
			`auth: github_pat_11ABCD01234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890`,
		}

		for _, tc := range tests {
			findings := detector.Detect(tc, 1, "test.yml")
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
		tests := []string{
			`export GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`,
			`token = "ghp_placeholder_token_for_example_only"`,
			`GITHUB_PAT=github_pat_your_token_here_replace_me`,
		}

		for _, tc := range tests {
			findings := detector.Detect(tc, 1, "test.yml")
			for _, f := range findings {
				if f.Confidence >= 25 {
					t.Errorf("Expected confidence < 25 for %s, got %d", tc, f.Confidence)
				}
			}
		}
	})
}
