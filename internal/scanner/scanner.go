// Package scanner provides the core scanning engine.
package scanner

import (
	"github.com/secretscan/secretscan/internal/models"
)

// Dedup removes duplicate findings based on their ID.
func Dedup(findings []models.Finding) []models.Finding {
	seen := make(map[string]bool)
	var unique []models.Finding
	for _, f := range findings {
		id := f.ID()
		if !seen[id] {
			seen[id] = true
			unique = append(unique, f)
		}
	}
	return unique
}
