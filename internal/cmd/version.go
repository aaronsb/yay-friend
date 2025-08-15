package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	
	"github.com/aaronsb/yay-friend/internal/version"
)

// newVersionCmd creates the version command
func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Show version information",
		Long:  "Display the version, commit hash, and build information for yay-friend",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Printf("yay-friend %s\n", version.String())
			return nil
		},
	}
}