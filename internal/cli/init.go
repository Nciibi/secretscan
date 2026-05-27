package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/secretscan/secretscan/internal/config"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize secretscan config in the current directory",
	Long: `Creates a default .secretscan.yaml config file and .secretignore
file in the current directory.

Example:
  secretscan init`,
	RunE: func(cmd *cobra.Command, args []string) error {
		dir := "."

		if err := config.GenerateDefault(dir); err != nil {
			return fmt.Errorf("failed to create config: %w", err)
		}
		fmt.Println("✅ Created .secretscan.yaml")

		if err := config.GenerateIgnoreFile(dir); err != nil {
			return fmt.Errorf("failed to create ignore file: %w", err)
		}
		fmt.Println("✅ Created .secretignore")

		fmt.Println("\nEdit these files to customize scanning behavior.")
		fmt.Println("Run 'secretscan scan .' to start scanning.")
		return nil
	},
}
