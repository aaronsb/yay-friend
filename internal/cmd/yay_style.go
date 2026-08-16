package cmd

import (
	"context"
)

// RunYayStyleCommand handles yay-style commands directly without cobra.
//
// Because main.go routes yay-style invocations here (bypassing cobra's flag
// parsing), yay-friend's own flags mixed into the command line would otherwise
// leak through to yay. We extract them here, set the corresponding globals, and
// pass only the remaining arguments on to yay.
//
// The list of what counts as ours lives in args.go, shared with the cobra
// registration, because keeping a second copy here is what let --noconfirm be a
// flag on one path and a package name on the other.
func RunYayStyleCommand(ctx context.Context, args []string) error {
	passthrough, err := consumeOwnFlags(args)
	if err != nil {
		return err
	}

	// cobra.OnInitialize does not fire on this path, so the setup it normally
	// performs has to happen explicitly. Without this, --no-color and the
	// ui.use_colors config key are parsed and then ignored on what is the most
	// common way to invoke yay-friend.
	initConfig()

	return runInstall(ctx, passthrough)
}
