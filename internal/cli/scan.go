package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/spf13/cobra"

	"github.com/secretscan/secretscan/internal/config"
	"github.com/secretscan/secretscan/internal/detectors"
	"github.com/secretscan/secretscan/internal/ignore"
	"github.com/secretscan/secretscan/internal/models"
	"github.com/secretscan/secretscan/internal/report"
	"github.com/secretscan/secretscan/internal/scanner"
	"github.com/secretscan/secretscan/internal/scanner/files"
)

var scanCmd = &cobra.Command{
	Use:   "scan [path]",
	Short: "Scan a directory for secrets",
	Long: `Recursively scan a directory for leaked secrets in source code,
config files, environment files, and other text files.

Example:
  secretscan scan .
  secretscan scan ./src --output json
  secretscan scan /path/to/project -o sarif > results.sarif`,
	Args: cobra.ExactArgs(1),
	RunE: runScan,
}

func runScan(cmd *cobra.Command, args []string) error {
	start := time.Now()
	scanPath := args[0]

	// Load config.
	cfg, err := config.Load(flagConfig)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading config: %v\n", err)
		os.Exit(ExitError)
	}
	applyFlags(cfg)

	// Set up ignore matcher.
	matcher := ignore.New()
	ignoreFile := cfg.IgnoreFile
	if flagIgnore != "" {
		ignoreFile = flagIgnore
	}
	if err := matcher.LoadFile(ignoreFile); err != nil {
		fmt.Fprintf(os.Stderr, "warning: error loading ignore file: %v\n", err)
	}
	for _, p := range cfg.ExcludePaths {
		matcher.AddPattern(p)
	}

	// Set up detectors.
	registry := detectors.NewRegistry(cfg.EntropyThreshold)
	if len(cfg.CustomPatterns) > 0 {
		if err := registry.AddCustom(cfg.CustomPatterns); err != nil {
			fmt.Fprintf(os.Stderr, "error loading custom patterns: %v\n", err)
			os.Exit(ExitError)
		}
	}

	// Set up context with cancellation.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	go func() {
		<-sigCh
		fmt.Fprintln(os.Stderr, "\ninterrupted, stopping scan...")
		cancel()
	}()

	// Run scan.
	fileScanner := files.New(cfg, registry, matcher)
	findings, scannedFiles, err := fileScanner.Scan(ctx, scanPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scan error: %v\n", err)
		os.Exit(ExitError)
	}

	// Deduplicate.
	findings = scanner.Dedup(findings)

	// Build result.
	result := models.ScanResult{
		Findings:     findings,
		ScannedFiles: scannedFiles,
		Duration:     time.Since(start).Round(time.Millisecond).String(),
		ScanPath:     scanPath,
		ScanMode:     "filesystem",
	}

	// Write report.
	writer := report.NewWriter(os.Stdout, cfg.OutputFormat)
	if err := writer.Write(result); err != nil {
		fmt.Fprintf(os.Stderr, "error writing report: %v\n", err)
		os.Exit(ExitError)
	}

	if result.HasFindings() {
		os.Exit(ExitFindings)
	}
	return nil
}

func applyFlags(cfg *config.Config) {
	if flagOutput != "" && flagOutput != "text" {
		cfg.OutputFormat = flagOutput
	}
	if flagWorkers > 0 {
		cfg.MaxWorkers = flagWorkers
	}
	if flagMaxSize > 0 {
		cfg.MaxFileSize = flagMaxSize
	}
	if flagEntropy > 0 {
		cfg.EntropyThreshold = flagEntropy
	}
	if flagVerbose {
		cfg.Verbose = true
	}
}
