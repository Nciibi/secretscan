// Package validate provides optional live validation of detected secrets.
// Validation only runs when explicitly requested via --validate flag.
// Each probe is lightweight and uses safe, unauthenticated API endpoints.
package validate

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/secretscan/secretscan/internal/models"
)

const httpTimeout = 5 * time.Second

// Validator performs optional live checks on detected secrets.
type Validator struct {
	client *http.Client
}

// New creates a Validator with a 5-second timeout.
func New() *Validator {
	return &Validator{
		client: &http.Client{Timeout: httpTimeout},
	}
}

// ValidateFindings runs live validation on each finding where possible.
// Findings are modified in place with their ValidationStatus updated.
func (v *Validator) ValidateFindings(findings []models.Finding) {
	for i := range findings {
		findings[i].Validation = v.probe(&findings[i])
	}
}

func (v *Validator) probe(f *models.Finding) models.ValidationStatus {
	switch {
	case f.Detector == "aws-key" && strings.HasPrefix(f.MatchedValue, "AKIA"):
		return v.probeAWS(f.MatchedValue)
	case f.Detector == "github-token":
		return v.probeGitHub(f.MatchedValue)
	case f.Detector == "stripe-key" && strings.HasPrefix(f.MatchedValue, "sk_live_"):
		return v.probeStripe(f.MatchedValue)
	default:
		return models.ValidationUnknown
	}
}

func (v *Validator) probeAWS(key string) models.ValidationStatus {
	url := "https://sts.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15"
	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return models.ValidationError
	}
	req.Header.Set("Authorization", fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/us-east-1/sts/aws4_request", key))

	resp, err := v.client.Do(req)
	if err != nil {
		return models.ValidationError
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case 200:
		return models.ValidationActive
	case 403:
		return models.ValidationInactive
	default:
		return models.ValidationError
	}
}

func (v *Validator) probeGitHub(token string) models.ValidationStatus {
	// Strip any surrounding non-token characters.
	token = strings.TrimSpace(token)
	req, err := http.NewRequest("GET", "https://api.github.com/", nil)
	if err != nil {
		return models.ValidationError
	}
	req.Header.Set("Authorization", "token "+token)
	req.Header.Set("User-Agent", "secretscan/1.0")

	resp, err := v.client.Do(req)
	if err != nil {
		return models.ValidationError
	}
	defer resp.Body.Close()

	if resp.Header.Get("X-RateLimit-Limit") != "" {
		return models.ValidationActive
	}
	if resp.StatusCode == 401 {
		return models.ValidationInactive
	}
	return models.ValidationUnknown
}

func (v *Validator) probeStripe(key string) models.ValidationStatus {
	req, err := http.NewRequest("GET", "https://api.stripe.com/v1/balance", nil)
	if err != nil {
		return models.ValidationError
	}
	req.Header.Set("Authorization", "Bearer "+key)

	resp, err := v.client.Do(req)
	if err != nil {
		return models.ValidationError
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case 200:
		return models.ValidationActive
	case 401:
		return models.ValidationInactive
	default:
		return models.ValidationError
	}
}
