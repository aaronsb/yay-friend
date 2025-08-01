package cmd

import (
	"context"
)

// RunYayStyleCommand handles yay-style commands directly without cobra
func RunYayStyleCommand(ctx context.Context, args []string) error {
	// This is essentially the same as runInstall, but called directly
	return runInstall(ctx, args)
}