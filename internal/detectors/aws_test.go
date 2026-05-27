package detectors

import (
	"testing"
)

func TestAWSKeyDetector(t *testing.T) {
	detector := NewAWSKeyDetector()

	t.Run("True Positives", func(t *testing.T) {
		tests := []string{
			`AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE`,
			`aws_access_key_id = "AKIAI44QH8DHBEXAMPLE"`,
			`export AWS_KEY=AKIAZ7PRVBN3WEXAMPLE`,
			`aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"`,
		}

		for _, tc := range tests {
			findings := detector.Detect(tc, 1, "test.env")
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
			`AWS_KEY=AKIA_EXAMPLE_PLACEHOLDER`,
			`aws_access_key_id = "your_key_here"`,
			`aws_secret_access_key = "changeme"`,
		}

		for _, tc := range tests {
			findings := detector.Detect(tc, 1, "test.env")
			for _, f := range findings {
				if f.Confidence >= 25 {
					t.Errorf("Expected confidence < 25 for %s, got %d", tc, f.Confidence)
				}
			}
		}
	})
}
