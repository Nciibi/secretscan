// Package entropy provides Shannon entropy calculation for string analysis.
// High-entropy strings are more likely to be secrets (random API keys, tokens, etc.).
package entropy

import (
	"math"
	"strings"
	"unicode"
)

// Shannon calculates the Shannon entropy of a string.
// Returns a value between 0 (no randomness) and ~log2(charset) (maximum randomness).
func Shannon(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	freq := make(map[rune]int)
	for _, r := range s {
		freq[r]++
	}

	length := float64(len([]rune(s)))
	entropy := 0.0
	for _, count := range freq {
		p := float64(count) / length
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}

// IsHighEntropy checks whether a string exceeds the given entropy threshold.
func IsHighEntropy(s string, threshold float64) bool {
	return Shannon(s) >= threshold
}

// HexEntropy calculates entropy specifically for hex character substrings.
func HexEntropy(s string) float64 {
	hex := filterChars(s, func(r rune) bool {
		return (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')
	})
	if len(hex) < 8 {
		return 0
	}
	return Shannon(hex)
}

// Base64Entropy calculates entropy specifically for base64 character substrings.
func Base64Entropy(s string) float64 {
	b64 := filterChars(s, func(r rune) bool {
		return unicode.IsLetter(r) || unicode.IsDigit(r) || r == '+' || r == '/' || r == '='
	})
	if len(b64) < 8 {
		return 0
	}
	return Shannon(b64)
}

// Score returns a normalized entropy score from 0 to 100.
// This makes it easier to combine with other confidence signals.
func Score(s string) int {
	e := Shannon(s)
	// Typical high-entropy secrets have entropy 4.0–6.0.
	// Normalize to 0–100 where 3.0 = 0 and 6.0 = 100.
	if e <= 3.0 {
		return 0
	}
	if e >= 6.0 {
		return 100
	}
	return int(((e - 3.0) / 3.0) * 100)
}

// ContainsHighEntropyWord checks if any whitespace-delimited word in the string
// exceeds the threshold. Returns the word and its entropy if found.
func ContainsHighEntropyWord(s string, threshold float64, minLength int) (string, float64, bool) {
	words := strings.Fields(s)
	for _, w := range words {
		if len(w) < minLength {
			continue
		}
		e := Shannon(w)
		if e >= threshold {
			return w, e, true
		}
	}
	return "", 0, false
}

func filterChars(s string, pred func(rune) bool) string {
	var b strings.Builder
	for _, r := range s {
		if pred(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}
