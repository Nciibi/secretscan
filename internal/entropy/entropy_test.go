package entropy

import (
	"testing"
)

func TestShannon(t *testing.T) {
	tests := []struct {
		name  string
		input string
		min   float64
		max   float64
	}{
		{
			name:  "Low entropy - single char",
			input: "aaaaaaaaaaaaaaaaaaaa",
			min:   0.0,
			max:   0.5,
		},
		{
			name:  "Low entropy - simple word",
			input: "password123",
			min:   1.0,
			max:   3.5,
		},
		{
			name:  "Medium entropy - english phrase",
			input: "the quick brown fox jumps over the lazy dog",
			min:   3.5,
			max:   4.5,
		},
		{
			name:  "High entropy - random hex",
			input: "4eC39HqLyjWDarjtT1zdp7dc", // Example Stripe key
			min:   4.0,
			max:   5.5,
		},
		{
			name:  "High entropy - random base64",
			input: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0", // JWT header/payload
			min:   4.0,
			max:   6.0,
		},
		{
			name:  "Very High entropy - pure random chars",
			input: "mY5up3rS3cr3tK3yF0rS1gn1ng",
			min:   3.8,
			max:   6.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Shannon(tt.input)
			if got < tt.min || got > tt.max {
				t.Errorf("Shannon() = %v, want between %v and %v", got, tt.min, tt.max)
			}
		})
	}
}

func TestScore(t *testing.T) {
	tests := []struct {
		name  string
		input string
		min   int
		max   int
	}{
		{
			name:  "Low score - single char",
			input: "aaaaaaaaaaaaaaaaaaaa",
			min:   0,
			max:   20, // Actually should be 0 because entropy is ~0, normalized to 0-100 range.
		},
		{
			name:  "High score - random hex",
			input: "4eC39HqLyjWDarjtT1zdp7dc", // Example Stripe key
			min:   40,
			max:   100,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Score(tt.input)
			if got < tt.min || got > tt.max {
				t.Errorf("Score() = %v, want between %v and %v", got, tt.min, tt.max)
			}
		})
	}
}
