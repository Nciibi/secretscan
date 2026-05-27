package detectors

import (
	"testing"
)

func TestInfraDetectors(t *testing.T) {
	tests := []struct {
		name     string
		detector Detector
		tps      []string
		tns      []string
	}{
		{
			name:     "NPMToken",
			detector: NewNPMTokenDetector(),
			tps: []string{
				`NPM_TOKEN=npm_Abc123Def456Ghi789Jkl012Mno345Pqrs`,
				`//registry.npmjs.org/:_authToken=npm_abcdefghijklmnopqrstuvwxyz0123456789`,
				`token="npm_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"`,
			},
			tns: []string{
				`NPM_TOKEN=npm_your_token_here_xxxxxxxxxxxx`,
				`NPM_TOKEN=npm_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`,
				`NPM_TOKEN=npm_placeholder`,
			},
		},
		{
			name:     "PyPIToken",
			detector: NewPyPITokenDetector(),
			tps: []string{
				`PYPI_TOKEN=pypi-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ`,
				`password = pypi-1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ`,
				`export TWINE_PASSWORD=pypi-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfGhIjKlMnOpQrStUvWxYz`,
			},
			tns: []string{
				`PYPI_TOKEN=pypi-your_token_here_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`,
				`PYPI_TOKEN=pypi-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`,
				`PYPI_TOKEN=pypi-placeholder`,
			},
		},
		{
			name:     "DockerHubToken",
			detector: NewDockerHubTokenDetector(),
			tps: []string{
				`DOCKER_TOKEN=dckr_pat_abcdefghijklmnopqrstuvwxyz0`,
				`password: "dckr_pat_ABCDEFGHIJKLMNOPQRSTUVWXYZ1"`,
				`export DOCKER_PASSWORD=dckr_pat_0123456789abcdefghijklmnop`,
			},
			tns: []string{
				`DOCKER_TOKEN=dckr_pat_your_token_here_xxxxxxxxx`,
				`DOCKER_TOKEN=dckr_pat_xxxxxxxxxxxxxxxxxxxxxxxxxxx`,
				`DOCKER_TOKEN=dckr_pat_placeholder`,
			},
		},
		{
			name:     "CloudflareToken",
			detector: NewCloudflareTokenDetector(),
			tps: []string{
				`CLOUDFLARE_API_TOKEN=abcdefghijklmnopqrstuvwxyz0123456789ABCD`,
				`cloudflare_key: "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcd"`,
				`export CF_API_TOKEN=0123456789abcdefghijklmnopqrstuvwxyzABCD`,
			},
			tns: []string{
				`CLOUDFLARE_API_TOKEN=your_token_here_xxxxxxxxxxxxxxxxxxxx`,
				`CLOUDFLARE_API_TOKEN=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`,
				`CLOUDFLARE_API_TOKEN=placeholder`,
			},
		},
		{
			name:     "VaultToken",
			detector: NewVaultTokenDetector(),
			tps: []string{
				`VAULT_TOKEN=s.abcdefghijklmnopqrstuvwx`,
				`vault_token: "s.ABCDEFGHIJKLMNOPQRSTUVWX"`,
				`export VAULT_TOKEN=s.0123456789abcdefghijklmn`,
			},
			tns: []string{
				`VAULT_TOKEN=s.your_token_here_xxxxxx`,
				`VAULT_TOKEN=s.xxxxxxxxxxxxxxxxxxxxxxxx`,
				`VAULT_TOKEN=s.placeholder`,
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
