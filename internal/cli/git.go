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
	gitscanner "github.com/secretscan/secretscan/internal/scanner/git"
)

var gitCmd = &cobra.Command{
	Use:   "git [path]",
	Short: "Scan Git history for secrets",
	Long: `Scan the Git commit history of a repository for secrets that
were committed in the past, even if they have been removed.

This scans diffs between commits and detects secrets in added lines.

Example:
  secretscan git .
  secretscan git ./my-repo --output json`,
	Args: cobra.ExactArgs(1),
	RunE: runGit,
}

var flagIncludeFS bool

func init() {
	gitCmd.Flags().BoolVar(&flagIncludeFS, "include-filesystem", false,
		"also scan the current filesystem in addition to git history")
}

func runGit(cmd *cobra.Command, args []string) error {
	start := time.Now()
	scanPath := args[0]

	cfg, err := config.Load(flagConfig)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading config: %v\n", err)
		os.Exit(ExitError)
	}
	applyFlags(cfg)

	registry := detectors.NewRegistry(cfg.EntropyThreshold)
	if len(cfg.CustomPatterns) > 0 {
		if err := registry.AddCustom(cfg.CustomPatterns); err != nil {
			fmt.Fprintf(os.Stderr, "error loading custom patterns: %v\n", err)
			os.Exit(ExitError)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	go func() {
		<-sigCh
		fmt.Fprintln(os.Stderr, "\ninterrupted, stopping scan...")
		cancel()
	}()

	var allFindings []models.Finding
	var scannedFiles, scannedCommits int

	// Git history scan.
	gs := gitscanner.New(cfg, registry)
	gitFindings, commits, err := gs.Scan(ctx, scanPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "git scan error: %v\n", err)
		os.Exit(ExitError)
	}
	allFindings = append(allFindings, gitFindings...)
	scannedCommits = commits

	// Optionally include filesystem scan.
	if flagIncludeFS {
		matcher := ignore.New()
		ignoreFile := cfg.IgnoreFile
		if flagIgnore != "" {
			ignoreFile = flagIgnore
		}
		matcher.LoadFile(ignoreFile)
		for _, p := range cfg.ExcludePaths {
			matcher.AddPattern(p)
		}

		fs := files.New(cfg, registry, matcher)
		fsFindings, files, err := fs.Scan(ctx, scanPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "filesystem scan error: %v\n", err)
		} else {
			allFindings = append(allFindings, fsFindings...)
			scannedFiles = files
		}
	}

	allFindings = scanner.Dedup(allFindings)

	scanMode := "git-history"
	if flagIncludeFS {
		scanMode = "git-history+filesystem"
	}

	result := models.ScanResult{
		Findings:       allFindings,
		ScannedFiles:   scannedFiles,
		ScannedCommits: scannedCommits,
		Duration:       time.Since(start).Round(time.Millisecond).String(),
		ScanPath:       scanPath,
		ScanMode:       scanMode,
	}

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
