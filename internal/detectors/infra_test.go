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
				`NPM_TOKEN=npm_Abc123Def456Ghi789Jkl012Mno345Pqrstu`,
				`//registry.npmjs.org/:_authToken=npm_Vb9Xr2Lm7nQp4KwJ01Hs8Yd3Rc6Fg5Mn2Kp9`,
				`token="npm_Qr7Nj3Xp9Lm2Wd6Kf8Hb1Yv4Gs0Tc5Rn7Jp3"`,
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
				`PYPI_TOKEN=pypi-Vb9Xr2Lm7nQp4KwJ01Hs8Yd3Rc6Fg5Mn2Kp9Lm7nQp4KwJ01Hs8Yd3Rc`,
				`password = pypi-Qr7Nj3Xp9Lm2Wd6Kf8Hb1Yv4Gs0Tc5Rn7Jp3Wm6Xd9Lb2Kf8Hv4Gs0Tc5Rn7`,
				`export TWINE_PASSWORD=pypi-Wb4Nm8Jp3Rc6Fg5Mn2Kp9Lm7nQp4KwJ01Hs8Yd3Rc6Fg5Mn2Kp9Lm7n`,
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
				// 27 chars after dckr_pat_ prefix.
				`DOCKER_TOKEN=dckr_pat_Vb9Xr2Lm7nQp4KwJ01Hs8Yd3Rc6`,
				`password: "dckr_pat_Qr7Nj3Xp9Lm2Wd6Kf8Hb1Yv4Gs0"`,
				`export DOCKER_PASSWORD=dckr_pat_Wb4Nm8Jp3Rc6Fg5Mn2Kp9Lm7nQp`,
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
				`CLOUDFLARE_API_TOKEN=Vb9Xr2Lm7nQp4KwJ01Hs8Yd3Rc6Fg5Mn2Kp9Lm7n`,
				`cloudflare_key: "Qr7Nj3Xp9Lm2Wd6Kf8Hb1Yv4Gs0Tc5Rn7Jp3Wm6Xd"`,
				`export CF_API_TOKEN=Wb4Nm8Jp3Rc6Fg5Mn2Kp9Lm7nQp4KwJ01Hs8Yd3Rc`,
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
				`VAULT_TOKEN=s.Vb9Xr2Lm7nQp4KwJ01Hs8Yd3`,
				`vault_token: "s.Qr7Nj3Xp9Lm2Wd6Kf8Hb1Yv4"`,
				`export VAULT_TOKEN=s.Wb4Nm8Jp3Rc6Fg5Mn2Kp9Lm7`,
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
