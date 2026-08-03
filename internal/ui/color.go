package ui

import (
	"os"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
	"golang.org/x/term"
)

// colorEnabled records what Configure decided. lipgloss holds the actual switch;
// this exists so the decision is inspectable in a debugger and in tests.
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
// gookit's NO_COLOR handling, which this replaces, covered escape sequences but
// not the emoji that were scattered through the output. Those are gone rather
// than gated: the entropy ramp and the :: marker carry the status they used to,
// and a switch guarding glyphs nobody wants is a switch with nothing behind it.
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

// isTTY reports whether stdout is an interactive terminal.
//
// This deliberately uses term.IsTerminal rather than checking os.ModeCharDevice:
// /dev/null is a character device, so the mode check answered "yes, a terminal"
// for `yay-friend -S pkg > /dev/null`.
func isTTY() bool {
	return term.IsTerminal(int(os.Stdout.Fd()))
}
