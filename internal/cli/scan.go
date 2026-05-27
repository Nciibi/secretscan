package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/spf13/cobra"

	"github.com/secretscan/secretscan/internal/baseline"
	"github.com/secretscan/secretscan/internal/config"
	"github.com/secretscan/secretscan/internal/detectors"
	"github.com/secretscan/secretscan/internal/ignore"
	"github.com/secretscan/secretscan/internal/models"
	"github.com/secretscan/secretscan/internal/report"
	"github.com/secretscan/secretscan/internal/scanner"
	"github.com/secretscan/secretscan/internal/scanner/files"
	"github.com/secretscan/secretscan/internal/validate"
)

var (
	flagUpdateBaseline bool
	flagNoBaseline     bool
	flagSince          string
)

var scanCmd = &cobra.Command{
	Use:   "scan [path]",
	Short: "Scan a directory for secrets",
	Long: `Recursively scan a directory for leaked secrets in source code,
config files, environment files, and other text files.

Examples:
  secretscan scan .
  secretscan scan ./src --output json
  secretscan scan . --validate
  secretscan scan . --since main
  secretscan scan . --update-baseline
  secretscan scan /path/to/project -o sarif > results.sarif`,
	Args: cobra.ExactArgs(1),
	RunE: runScan,
}

func init() {
	scanCmd.Flags().BoolVar(&flagUpdateBaseline, "update-baseline", false,
		"write current findings to .secretscan-baseline.json")
	scanCmd.Flags().BoolVar(&flagNoBaseline, "no-baseline", false,
		"ignore existing baseline file")
	scanCmd.Flags().StringVar(&flagSince, "since", "",
		"scan only files changed since the given git ref (e.g. HEAD, main, abc1234)")
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

	// Incremental scanning: resolve changed files if --since is set.
	var changedFiles []string
	if flagSince != "" {
		var resolveErr error
		changedFiles, resolveErr = resolveChangedFiles(scanPath, flagSince)
		if resolveErr != nil {
			fmt.Fprintf(os.Stderr, "warning: cannot resolve --since %q: %v (falling back to full scan)\n", flagSince, resolveErr)
			changedFiles = nil
		}
	}

	// Run scan.
	fileScanner := files.New(cfg, registry, matcher)
	var findings []models.Finding
	var scannedFiles int

	if len(changedFiles) > 0 {
		findings, scannedFiles, err = fileScanner.ScanFiles(ctx, scanPath, changedFiles)
	} else {
		findings, scannedFiles, err = fileScanner.Scan(ctx, scanPath)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "scan error: %v\n", err)
		os.Exit(ExitError)
	}

	// Deduplicate.
	findings = scanner.Dedup(findings)

	// Baseline handling.
	suppressed := 0
	if flagUpdateBaseline {
		if err := baseline.Save("", findings); err != nil {
			fmt.Fprintf(os.Stderr, "error saving baseline: %v\n", err)
			os.Exit(ExitError)
		}
		fmt.Fprintf(os.Stderr, "✅ Baseline updated with %d findings in %s\n", len(findings), baseline.DefaultFile)
	}
	if !flagNoBaseline && !flagUpdateBaseline {
		bl, err := baseline.Load("")
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: error loading baseline: %v\n", err)
		}
		if bl != nil {
			findings, suppressed = baseline.Filter(findings, bl)
		}
	}

	// Validation.
	if flagValidate {
		v := validate.New()
		v.ValidateFindings(findings)
	}

	// Build result.
	result := models.ScanResult{
		Findings:     findings,
		ScannedFiles: scannedFiles,
		Duration:     time.Since(start).Round(time.Millisecond).String(),
		ScanPath:     scanPath,
		ScanMode:     "filesystem",
		Suppressed:   suppressed,
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

// resolveChangedFiles uses go-git to find files changed between HEAD and the given ref.
func resolveChangedFiles(repoPath, sinceRef string) ([]string, error) {
	repo, err := git.PlainOpen(repoPath)
	if err != nil {
		return nil, fmt.Errorf("not a git repository: %w", err)
	}

	// Resolve the since reference.
	sinceHash, err := repo.ResolveRevision(plumbing.Revision(sinceRef))
	if err != nil {
		return nil, fmt.Errorf("cannot resolve ref %q: %w", sinceRef, err)
	}

	sinceCommit, err := repo.CommitObject(*sinceHash)
	if err != nil {
		return nil, fmt.Errorf("cannot get commit for %q: %w", sinceRef, err)
	}
	sinceTree, err := sinceCommit.Tree()
	if err != nil {
		return nil, fmt.Errorf("cannot get tree: %w", err)
	}

	// Get HEAD.
	headRef, err := repo.Head()
	if err != nil {
		return nil, fmt.Errorf("cannot get HEAD: %w", err)
	}
	headCommit, err := repo.CommitObject(headRef.Hash())
	if err != nil {
		return nil, fmt.Errorf("cannot get HEAD commit: %w", err)
	}
	headTree, err := headCommit.Tree()
	if err != nil {
		return nil, fmt.Errorf("cannot get HEAD tree: %w", err)
	}

	// Compute diff.
	changes, err := sinceTree.Diff(headTree)
	if err != nil {
		return nil, fmt.Errorf("cannot compute diff: %w", err)
	}

	seen := make(map[string]bool)
	var files []string
	for _, change := range changes {
		name := change.To.Name
		if name == "" {
			name = change.From.Name
		}
		if name != "" && !seen[name] {
			seen[name] = true
			files = append(files, name)
		}
	}
	return files, nil
}
