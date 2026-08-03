package cmd

import (
	"context"
	"strings"
)

// RunYayStyleCommand handles yay-style commands directly without cobra.
//
// Because main.go routes yay-style invocations here (bypassing cobra's flag
// parsing), yay-friend's own flags mixed into the command line would otherwise
// leak through to yay. We extract them here, set the corresponding globals, and
// pass only the remaining arguments on to yay.
func RunYayStyleCommand(ctx context.Context, args []string) error {
	passthrough := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--skip-analysis":
			skipAnalysis = true
		case arg == "--no-spinner":
			noSpinner = true
		case arg == "--no-color":
			noColor = true
		case arg == "-v" || arg == "--verbose":
			verbose = true
		case arg == "--provider":
			if i+1 < len(args) {
				provider = args[i+1]
				i++ // consume the value
			}
		case strings.HasPrefix(arg, "--provider="):
			provider = strings.TrimPrefix(arg, "--provider=")
		default:
			passthrough = append(passthrough, arg)
		}
	}

	// cobra.OnInitialize does not fire on this path, so the setup it normally
	// performs has to happen explicitly. Without this, --no-color and the
	// ui.use_colors config key are parsed and then ignored on what is the most
	// common way to invoke yay-friend.
	initConfig()

	return runInstall(ctx, passthrough)
}
