// Package cli implements the secretscan command-line interface using Cobra.
package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

const version = "1.0.0"

// Exit codes.
const (
	ExitClean   = 0
	ExitFindings = 1
	ExitError   = 2
)

// Execute runs the root command.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(ExitError)
	}
}

var (
	flagOutput    string
	flagConfig    string
	flagIgnore    string
	flagWorkers   int
	flagVerbose   bool
	flagMaxSize   int64
	flagEntropy   float64
)

var rootCmd = &cobra.Command{
	Use:   "secretscan",
	Short: "A fast local secret leak scanner for developer repositories",
	Long: `secretscan scans your local code, config files, environment files, and Git
history for accidentally committed secrets like API keys, tokens, private keys,
and high-entropy strings.

It uses multi-signal detection (regex + context + entropy + validation) to 
minimize false positives while catching real secret leaks.`,
	SilenceUsage:  true,
	SilenceErrors: true,
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&flagOutput, "output", "o", "text",
		"output format: text, json, sarif")
	rootCmd.PersistentFlags().StringVarP(&flagConfig, "config", "c", "",
		"path to config file (default: .secretscan.yaml)")
	rootCmd.PersistentFlags().StringVar(&flagIgnore, "ignore-file", "",
		"path to ignore file (default: .secretignore)")
	rootCmd.PersistentFlags().IntVarP(&flagWorkers, "workers", "w", 0,
		"number of concurrent workers (default: 8)")
	rootCmd.PersistentFlags().BoolVarP(&flagVerbose, "verbose", "v", false,
		"enable verbose output")
	rootCmd.PersistentFlags().Int64Var(&flagMaxSize, "max-size", 0,
		"maximum file size in bytes (default: 10MB)")
	rootCmd.PersistentFlags().Float64Var(&flagEntropy, "entropy", 0,
		"entropy threshold (default: 4.0)")

	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(gitCmd)
	rootCmd.AddCommand(initCmd)
	rootCmd.AddCommand(versionCmd)
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version of secretscan",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("secretscan v%s\n", version)
	},
}
