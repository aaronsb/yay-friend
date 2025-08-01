package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/aaronsb/yay-friend/internal/cmd"
)

func main() {
	// Set up context with signal handling
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Handle the yay-style interface directly
	if len(os.Args) > 1 {
		firstArg := os.Args[1]
		// Known subcommands that should use cobra
		knownCommands := []string{"analyze", "config", "provider", "test", "help", "completion", "--help", "-h"}
		
		isKnownCommand := false
		for _, cmdName := range knownCommands {
			if firstArg == cmdName {
				isKnownCommand = true
				break
			}
		}
		
		// If it's not a known subcommand, handle it as a yay-style command
		if !isKnownCommand {
			// This is a yay-style command (packages, -S packages, etc.)
			if err := handleYayStyleCommand(ctx, os.Args[1:]); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
			return
		}
	}

	// Execute the cobra command for subcommands
	if err := cmd.Execute(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// handleYayStyleCommand handles yay-style commands directly
func handleYayStyleCommand(ctx context.Context, args []string) error {
	// Import the necessary functions
	return cmd.RunYayStyleCommand(ctx, args)
}