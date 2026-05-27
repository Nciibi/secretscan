// Benchmark tool for secretscan detector precision and recall.
//
// Reads true_positives.yaml and false_positives.yaml from the testdata directory,
// runs all detectors against each input, and prints a precision/recall report.
//
// Usage: go run ./cmd/benchmark
package main

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/secretscan/secretscan/internal/detectors"
	"gopkg.in/yaml.v3"
)

type truePositive struct {
	Detector      string `yaml:"detector"`
	Input         string `yaml:"input"`
	MinConfidence int    `yaml:"min_confidence"`
}

type falsePositive struct {
	Input         string `yaml:"input"`
	MaxConfidence int    `yaml:"max_confidence"`
}

func main() {
	registry := detectors.NewRegistry(4.0)

	// Load true positives.
	tpData, err := os.ReadFile("internal/detectors/testdata/true_positives.yaml")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading true_positives.yaml: %v\n", err)
		os.Exit(1)
	}
	var tps []truePositive
	if err := yaml.Unmarshal(tpData, &tps); err != nil {
		fmt.Fprintf(os.Stderr, "error parsing true_positives.yaml: %v\n", err)
		os.Exit(1)
	}

	// Load false positives.
	fpData, err := os.ReadFile("internal/detectors/testdata/false_positives.yaml")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading false_positives.yaml: %v\n", err)
		os.Exit(1)
	}
	var fps []falsePositive
	if err := yaml.Unmarshal(fpData, &fps); err != nil {
		fmt.Fprintf(os.Stderr, "error parsing false_positives.yaml: %v\n", err)
		os.Exit(1)
	}

	// Aggregate per-detector stats.
	type stats struct {
		tp int // correctly detected
		fn int // missed (should have detected)
		fp int // falsely detected
	}
	detectorStats := make(map[string]*stats)

	// Ensure all detector names exist in stats map.
	for _, name := range registry.Names() {
		detectorStats[name] = &stats{}
	}

	// Run true positives.
	for _, tc := range tps {
		findings := registry.DetectAll(tc.Input, 1, "benchmark.txt")
		detected := false
		for _, f := range findings {
			if f.Detector == tc.Detector && f.Confidence >= tc.MinConfidence {
				detected = true
				break
			}
		}
		s := detectorStats[tc.Detector]
		if s == nil {
			s = &stats{}
			detectorStats[tc.Detector] = s
		}
		if detected {
			s.tp++
		} else {
			s.fn++
		}
	}

	// Run false positives (test against ALL detectors).
	for _, tc := range fps {
		findings := registry.DetectAll(tc.Input, 1, "benchmark.txt")
		for _, f := range findings {
			if f.Confidence > tc.MaxConfidence {
				s := detectorStats[f.Detector]
				if s == nil {
					s = &stats{}
					detectorStats[f.Detector] = s
				}
				s.fp++
				fmt.Printf("FP: %s triggered on '%s' with confidence %d\n", f.Detector, tc.Input, f.Confidence)
			}
		}
	}

	// Print report.
	fmt.Println()
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println("  secretscan Detector Precision/Recall Benchmark")
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println()

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "Detector\tTP\tFP\tFN\tPrecision\tRecall\n")
	fmt.Fprintf(w, "--------\t--\t--\t--\t---------\t------\n")

	allPass := true
	for _, name := range registry.Names() {
		s := detectorStats[name]
		if s == nil || (s.tp == 0 && s.fn == 0 && s.fp == 0) {
			continue
		}

		precision := 100.0
		if s.tp+s.fp > 0 {
			precision = float64(s.tp) / float64(s.tp+s.fp) * 100
		}
		recall := 100.0
		if s.tp+s.fn > 0 {
			recall = float64(s.tp) / float64(s.tp+s.fn) * 100
		}

		status := "✅"
		if precision < 80 || recall < 90 {
			status = "❌"
			allPass = false
		}

		fmt.Fprintf(w, "%s %s\t%d\t%d\t%d\t%.1f%%\t%.1f%%\n",
			status, name, s.tp, s.fp, s.fn, precision, recall)
	}
	w.Flush()

	fmt.Println()
	if allPass {
		fmt.Println("✅ All detectors meet threshold: precision >= 80%, recall >= 90%")
	} else {
		fmt.Println("❌ Some detectors need tuning (precision < 80% or recall < 90%)")
		os.Exit(1)
	}
}
