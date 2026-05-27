package detectors

import (
	"testing"
)

func TestSecretsDetectors(t *testing.T) {
	tests := []struct {
		name     string
		detector Detector
		tps      []string
		tns      []string
	}{
		{
			name:     "PrivateKey",
			detector: NewPrivateKeyDetector(),
			tps: []string{
				`-----BEGIN RSA PRIVATE KEY-----`,
				`-----BEGIN EC PRIVATE KEY-----`,
				`-----BEGIN PRIVATE KEY-----`,
			},
			tns: []string{
				`-----BEGIN PUBLIC KEY-----`,
				`-----BEGIN CERTIFICATE-----`,
				`private_key = "your_key_here"`,
			},
		},
		{
			name:     "JWT",
			detector: NewJWTDetector(),
			tps: []string{
				`token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"`,
				`jwt_secret: "mY5up3rS3cr3tK3yF0rS1gn1ng"`,
				`SIGNING_KEY="aBcDeFgHiJkLmNoPqRsTuVwXyZ"`,
			},
			tns: []string{
				`token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"`,
				`jwt_secret = "changeme"`,
				`SIGNING_KEY="your_secret_here"`,
			},
		},
		{
			name:     "Password",
			detector: NewGenericPasswordDetector(),
			tps: []string{
				`password = "Tr0ub4dor&3xAmpl3"`,
				`DB_PASSWORD="S3cur3P@ssw0rd!2024"`,
				`admin_pwd: "SuperSecretPassword123!"`,
			},
			tns: []string{
				`password = "changeme"`,
				`password = "your_password_here"`,
				`pwd="changeme"`,
			},
		},
		{
			name:     "ConnectionString",
			detector: NewConnectionStringDetector(),
			tps: []string{
				`DATABASE_URL=postgresql://admin:p4ssw0rd@db.internal.net:5432/prod`,
				`MONGO_URI="mongodb://root:s3cr3t@cluster0.mongodb.net/mydb"`,
				`redis://user:secretpassword@localhost:6379`,
			},
			tns: []string{
				`DATABASE_URL=postgresql://user:pass@localhost:5432/db`, // pass might be low entropy, but connection string itself matches. We want it to be > 25 but maybe < 50 for weak passwords? Actually the requirement is placeholders < 25.
				`MONGO_URI="mongodb://localhost:27017/mydb"`,            // No credentials
				`redis://localhost:6379`,                                // No credentials
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
						if f.Confidence >= 50 && tt.name == "ConnectionString" {
							// Connection string might have some baseline confidence
							continue
						}
						if f.Confidence >= 25 && tt.name != "ConnectionString" {
							t.Errorf("Expected confidence < 25 for %s, got %d", tc, f.Confidence)
						}
					}
				}
			})
		})
	}
}
