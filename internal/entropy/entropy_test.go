package entropy

import (
	"math"
	"testing"
)

func TestShannon(t *testing.T) {
	tests := []struct {
		name  string
		input string
		minE  float64
		maxE  float64
	}{
		{"empty string", "", 0, 0},
		{"single char", "a", 0, 0},
		{"repeated chars", "aaaaaaa", 0, 0.01},
		{"low entropy", "aabb", 0.9, 1.1},
		{"moderate entropy", "abcdefgh", 2.9, 3.1},
		{"high entropy hex", "a1b2c3d4e5f6a7b8", 3.5, 4.1},
		{"high entropy random", "K8xPq2mN7vR3jW9s", 3.8, 4.2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := Shannon(tt.input)
			if e < tt.minE || e > tt.maxE {
				t.Errorf("Shannon(%q) = %f, want between %f and %f",
					tt.input, e, tt.minE, tt.maxE)
			}
		})
	}
}

func TestShannonEmpty(t *testing.T) {
	if e := Shannon(""); e != 0 {
		t.Errorf("expected 0, got %f", e)
	}
}

func TestIsHighEntropy(t *testing.T) {
	if IsHighEntropy("aaaa", 3.0) {
		t.Error("low entropy string should not be flagged")
	}
	if !IsHighEntropy("K8xPq2mN7vR3jW9sT4uY6", 3.5) {
		t.Error("high entropy string should be flagged")
	}
}

func TestScore(t *testing.T) {
	tests := []struct {
		input string
		minS  int
		maxS  int
	}{
		{"aaa", 0, 0},
		{"abcdef", 0, 10},
		{"K8xPq2mN7vR3jW9sT4uY6aB5cD", 20, 60},
	}

	for _, tt := range tests {
		s := Score(tt.input)
		if s < tt.minS || s > tt.maxS {
			t.Errorf("Score(%q) = %d, want between %d and %d",
				tt.input, s, tt.minS, tt.maxS)
		}
	}
}

func TestHexEntropy(t *testing.T) {
	// Short hex should return 0.
	if e := HexEntropy("abc"); e != 0 {
		t.Errorf("short hex should be 0, got %f", e)
	}
	// Long hex should have measurable entropy.
	e := HexEntropy("a1b2c3d4e5f6a7b8c9d0")
	if e < 2.0 {
		t.Errorf("expected hex entropy > 2.0, got %f", e)
	}
}

func TestBase64Entropy(t *testing.T) {
	if e := Base64Entropy("ab"); e != 0 {
		t.Errorf("short base64 should be 0, got %f", e)
	}
	e := Base64Entropy("SGVsbG8gV29ybGQhIFRoaXMgaXM=")
	if e < 2.0 {
		t.Errorf("expected base64 entropy > 2.0, got %f", e)
	}
}

func TestContainsHighEntropyWord(t *testing.T) {
	line := "token = K8xPq2mN7vR3jW9sT4uY6aB5cD"
	word, e, found := ContainsHighEntropyWord(line, 3.5, 10)
	if !found {
		t.Error("expected to find high entropy word")
	}
	if word == "" || e < 3.5 {
		t.Errorf("unexpected word=%q entropy=%f", word, e)
	}
}

func BenchmarkShannon(b *testing.B) {
	s := "K8xPq2mN7vR3jW9sT4uY6aB5cD0eF1gH2iJ3kL4"
	for i := 0; i < b.N; i++ {
		Shannon(s)
	}
}

func BenchmarkScore(b *testing.B) {
	s := "K8xPq2mN7vR3jW9sT4uY6aB5cD0eF1gH2iJ3kL4"
	for i := 0; i < b.N; i++ {
		Score(s)
	}
}

func almostEqual(a, b, epsilon float64) bool {
	return math.Abs(a-b) < epsilon
}
