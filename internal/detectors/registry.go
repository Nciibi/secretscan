package detectors

import "github.com/secretscan/secretscan/internal/models"

// Registry holds all active detectors for a scan.
type Registry struct {
	detectors []Detector
}

// NewRegistry creates a registry with all built-in detectors.
func NewRegistry(entropyThreshold float64) *Registry {
	r := &Registry{}
	r.detectors = []Detector{
		NewAWSKeyDetector(),
		NewGitHubTokenDetector(),
		NewOpenAIKeyDetector(),
		NewSlackTokenDetector(),
		NewStripeKeyDetector(),
		NewPrivateKeyDetector(),
		NewFirebaseDetector(),
		NewJWTDetector(),
		NewGenericPasswordDetector(),
		NewConnectionStringDetector(),
		NewGenericHighEntropyDetector(entropyThreshold),
	}
	return r
}

// AddCustom adds user-defined custom detectors.
func (r *Registry) AddCustom(patterns []models.DetectorPattern) error {
	for _, p := range patterns {
		d, err := NewCustomDetector(p)
		if err != nil {
			return err
		}
		r.detectors = append(r.detectors, d)
	}
	return nil
}

// DetectAll runs all detectors against a single line.
func (r *Registry) DetectAll(line string, lineNum int, filePath string) []models.Finding {
	var all []models.Finding
	for _, d := range r.detectors {
		findings := d.Detect(line, lineNum, filePath)
		all = append(all, findings...)
	}
	return all
}

// Names returns the names of all registered detectors.
func (r *Registry) Names() []string {
	names := make([]string, len(r.detectors))
	for i, d := range r.detectors {
		names[i] = d.Name()
	}
	return names
}
