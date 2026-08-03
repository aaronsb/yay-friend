package ui

import (
	"os"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
	"golang.org/x/term"
)

// colorEnabled is consulted by nothing directly; it exists so Configure can
// report what it decided. lipgloss holds the actual switch.
var colorEnabled = true

// Configure sets colour output once, at startup.
//
// Precedence, most specific first:
//
//	--no-color          explicit for this invocation
//	NO_COLOR            the cross-tool convention (any non-empty value)
//	config ui.use_colors
//	stdout is a TTY     the fallback
//
// The config key existed and was read by nothing before this: it was written to
// every user's config.yaml, printed by `config show`, and had no effect.
//
// This gates emoji too, via Enabled. Terminals that cannot render colour are
// frequently the same ones that render emoji as replacement boxes, and gookit's
// NO_COLOR handling -- which this replaces -- never covered the emoji sprinkled
// through the output.
func Configure(noColorFlag bool, cfgUseColors bool) {
	switch {
	case noColorFlag:
		colorEnabled = false
	case os.Getenv("NO_COLOR") != "":
		colorEnabled = false
	case !cfgUseColors:
		colorEnabled = false
	default:
		colorEnabled = isTTY()
	}

	if !colorEnabled {
		lipgloss.SetColorProfile(termenv.Ascii)
	}
}

// Enabled reports whether decorated output is on. Callers use it to drop emoji
// and other glyphs a plain terminal would mangle.
func Enabled() bool { return colorEnabled }

// isTTY reports whether stdout is an interactive terminal.
//
// This deliberately uses term.IsTerminal rather than checking os.ModeCharDevice:
// /dev/null is a character device, so the mode check answered "yes, a terminal"
// for `yay-friend -S pkg > /dev/null`.
func isTTY() bool {
	return term.IsTerminal(int(os.Stdout.Fd()))
}
