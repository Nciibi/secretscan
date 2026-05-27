package detectors

import (
	"testing"

	"github.com/secretscan/secretscan/internal/models"
)

func TestAWSKeyDetector(t *testing.T) {
	d := NewAWSKeyDetector()

	tests := []struct {
		name    string
		line    string
		wantHit bool
	}{
		{"valid AKIA key", `AWS_KEY=AKIAIOSFODNN7EXAMPLE`, true},
		{"key in quotes", `aws_access_key_id = "AKIAIOSFODNN7EXAMPLE"`, true},
		{"no match", `some random text without keys`, false},
		{"placeholder", `AWS_KEY=AKIA_EXAMPLE_PLACEHOLDER`, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := d.Detect(tt.line, 1, "test.go")
			if tt.wantHit && len(findings) == 0 {
				t.Error("expected finding but got none")
			}
			if !tt.wantHit && len(findings) > 0 {
				t.Errorf("expected no finding but got %d", len(findings))
			}
		})
	}
}

func TestGitHubTokenDetector(t *testing.T) {
	d := NewGitHubTokenDetector()

	tests := []struct {
		name    string
		line    string
		wantHit bool
	}{
		{"classic PAT", `token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn"`, true},
		{"no match", `this is not a token`, false},
		{"placeholder", `token = "ghp_example_placeholder_for_testing"`, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := d.Detect(tt.line, 1, "test.go")
			if tt.wantHit && len(findings) == 0 {
				t.Error("expected finding but got none")
			}
			if !tt.wantHit && len(findings) > 0 {
				t.Errorf("expected no finding but got %d", len(findings))
			}
		})
	}
}

func TestStripeKeyDetector(t *testing.T) {
	d := NewStripeKeyDetector()

	tests := []struct {
		name    string
		line    string
		wantHit bool
	}{
		{"live key", `STRIPE_KEY="sk_live_4eC39HqLyjWDarjtT1zdp7dc"`, true},
		{"test key", `stripe_key: pk_test_TYooMQauvdEDq54NiTphI7jx`, true},
		{"no match", `stripe is cool but no key here`, false},
		{"placeholder", `stripe_key = "sk_live_example_replace_me"`, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := d.Detect(tt.line, 1, "test.go")
			if tt.wantHit && len(findings) == 0 {
				t.Error("expected finding but got none")
			}
			if !tt.wantHit && len(findings) > 0 {
				t.Errorf("expected no finding but got %d", len(findings))
			}
		})
	}
}

func TestSlackTokenDetector(t *testing.T) {
	d := NewSlackTokenDetector()

	tests := []struct {
		name    string
		line    string
		wantHit bool
	}{
		{"bot token", `SLACK_TOKEN=xoxb-1234567890-1234567890-AbCdEfGhIjKl`, true},
		{"webhook", `https://hooks.slack.com/services/T12345678/B12345678/AbCdEfGhIjKlMnOpQrStUvWx`, true},
		{"no match", `slack is great`, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := d.Detect(tt.line, 1, "test.go")
			if tt.wantHit && len(findings) == 0 {
				t.Error("expected finding but got none")
			}
			if !tt.wantHit && len(findings) > 0 {
				t.Errorf("expected no finding but got %d", len(findings))
			}
		})
	}
}

func TestPrivateKeyDetector(t *testing.T) {
	d := NewPrivateKeyDetector()

	tests := []struct {
		name    string
		line    string
		wantHit bool
	}{
		{"RSA key", `-----BEGIN RSA PRIVATE KEY-----`, true},
		{"EC key", `-----BEGIN EC PRIVATE KEY-----`, true},
		{"generic", `-----BEGIN PRIVATE KEY-----`, true},
		{"no match", `this is not a key`, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := d.Detect(tt.line, 1, "test.pem")
			if tt.wantHit && len(findings) == 0 {
				t.Error("expected finding but got none")
			}
			if !tt.wantHit && len(findings) > 0 {
				t.Errorf("expected no finding but got %d", len(findings))
			}
		})
	}
}

func TestJWTDetector(t *testing.T) {
	d := NewJWTDetector()

	tests := []struct {
		name    string
		line    string
		wantHit bool
	}{
		{"jwt token", `token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"`, true},
		{"jwt secret", `jwt_secret: "mY5up3rS3cr3tK3yF0rS1gn1ng"`, true},
		{"no match", `we use JWT for auth`, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := d.Detect(tt.line, 1, "config.yaml")
			if tt.wantHit && len(findings) == 0 {
				t.Error("expected finding but got none")
			}
			if !tt.wantHit && len(findings) > 0 {
				t.Errorf("expected no finding but got %d", len(findings))
			}
		})
	}
}

func TestPasswordDetector(t *testing.T) {
	d := NewGenericPasswordDetector()

	tests := []struct {
		name    string
		line    string
		wantHit bool
	}{
		{"password assign", `password = "Tr0ub4dor&3"`, true},
		{"short password", `pwd="ab"`, false},
		{"placeholder", `password = "your_password_here"`, false},
		{"no match", `the word password in docs`, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := d.Detect(tt.line, 1, "config.py")
			if tt.wantHit && len(findings) == 0 {
				t.Error("expected finding but got none")
			}
			if !tt.wantHit && len(findings) > 0 {
				t.Errorf("expected no finding but got %d", len(findings))
			}
		})
	}
}

func TestConnectionStringDetector(t *testing.T) {
	d := NewConnectionStringDetector()

	tests := []struct {
		name    string
		line    string
		wantHit bool
	}{
		{"postgres with creds", `DATABASE_URL=postgresql://user:p4ssw0rd@localhost:5432/mydb`, true},
		{"mongodb", `MONGO_URI="mongodb://admin:secret@cluster.mongodb.net/db"`, true},
		{"no match", `postgres is a great database`, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := d.Detect(tt.line, 1, ".env")
			if tt.wantHit && len(findings) == 0 {
				t.Error("expected finding but got none")
			}
			if !tt.wantHit && len(findings) > 0 {
				t.Errorf("expected no finding but got %d", len(findings))
			}
		})
	}
}

func TestFalsePositiveFiltering(t *testing.T) {
	tests := []struct {
		line     string
		wantFP   bool
	}{
		{`API_KEY="your_api_key_here"`, true},
		{`token = "EXAMPLE_TOKEN"`, true},
		{`SECRET = "placeholder"`, true},
		{`SECRET = "xK9mP2nR7vQ3wJ8s"`, false},
	}

	for _, tt := range tests {
		got := isFalsePositive(tt.line)
		if got != tt.wantFP {
			t.Errorf("isFalsePositive(%q) = %v, want %v", tt.line, got, tt.wantFP)
		}
	}
}

func TestComputeConfidence(t *testing.T) {
	tests := []struct {
		regex   bool
		ctx     bool
		entropy int
		valid   bool
		min     int
		max     int
	}{
		{true, true, 80, true, 90, 100},
		{true, false, 0, false, 25, 35},
		{true, true, 60, false, 60, 75},
		{false, false, 0, false, 0, 0},
	}

	for i, tt := range tests {
		got := computeConfidence(tt.regex, tt.ctx, tt.entropy, tt.valid)
		if got < tt.min || got > tt.max {
			t.Errorf("test %d: computeConfidence = %d, want [%d, %d]",
				i, got, tt.min, tt.max)
		}
	}
}

func TestRegistryDetectAll(t *testing.T) {
	reg := NewRegistry(4.0)

	// Line with a known secret pattern.
	findings := reg.DetectAll(`AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"`, 1, ".env")
	if len(findings) == 0 {
		t.Error("expected at least one finding for AWS key")
	}

	// Harmless line.
	findings = reg.DetectAll("hello world", 1, "readme.md")
	if len(findings) != 0 {
		t.Errorf("expected no findings for harmless line, got %d", len(findings))
	}
}

func TestCustomDetector(t *testing.T) {
	pattern := models.DetectorPattern{
		Name:     "test-secret",
		Pattern:  `MYSECRET_[A-Z0-9]{10,}`,
		Severity: models.SeverityHigh,
	}

	d, err := NewCustomDetector(pattern)
	if err != nil {
		t.Fatalf("failed to create custom detector: %v", err)
	}

	findings := d.Detect(`api_key = "MYSECRET_ABCDEF1234"`, 1, "config.go")
	if len(findings) == 0 {
		t.Error("expected finding for custom pattern")
	}
}

func BenchmarkDetectAll(b *testing.B) {
	reg := NewRegistry(4.0)
	line := `AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE" # do not commit`

	for i := 0; i < b.N; i++ {
		reg.DetectAll(line, 1, "test.env")
	}
}

func BenchmarkDetectHarmless(b *testing.B) {
	reg := NewRegistry(4.0)
	line := `func main() { fmt.Println("Hello, World!") }`

	for i := 0; i < b.N; i++ {
		reg.DetectAll(line, 1, "main.go")
	}
}
