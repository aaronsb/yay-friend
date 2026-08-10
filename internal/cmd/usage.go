package cmd

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"
)

// usageError marks a failure that is about how the command was called, rather
// than about the world it was called in.
//
// The distinction earns its keep on the commands whose stdout is a machine's
// input. Cobra prints usage for every RunE error by default, and prints it to
// the command's own output writer — so an analysis that failed because the
// model was unreachable would answer with a flag list, on the stream a caller
// is parsing as JSON. Those commands silence that and route the one case where
// usage genuinely helps back through here, onto stderr.
type usageError struct{ error }

// withUsage runs fn, printing usage on stderr if it fails for a usage reason.
func withUsage(cmd *cobra.Command, fn func() error) error {
	err := fn()
	var usage usageError
	if errors.As(err, &usage) {
		fmt.Fprintln(cmd.ErrOrStderr(), cmd.UsageString())
	}
	return err
}
