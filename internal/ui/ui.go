// Package ui owns every byte yay-friend prints. Two rules hold it together, and
// both are load-bearing rather than decorative.
//
// 1. Hue means entropy. Nothing else gets a hue.
//
// Entropy is the one continuous quantity this tool measures, so a reader who
// learns the scale once can read it everywhere. Structure, labels and metadata
// are achromatic -- dim, normal, bold. A colour applied to anything else is
// noise competing with the only signal that matters.
//
// 2. `::` in cyan is yay-friend's own voice, and nothing else may use it.
//
// yay-friend's output interleaves with yay's, with pacman's, and with build
// output from the very package under analysis. A hostile PKGBUILD can echo
// "All packages passed security analysis" and, without a reserved marker, that
// line is indistinguishable from ours. The prefix is a trust boundary: if it
// carries `::`, yay-friend said it.
package ui

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"golang.org/x/term"

	"github.com/aaronsb/yay-friend/internal/types"
)

// Out is where rendered output goes. Swappable for tests.
var Out io.Writer = os.Stdout

// Err is where warnings go, separately from Out. It is its own writer because
// the two streams part company on the machine-readable commands: `grade` and
// `analyze --json` move Out to stderr so stdout carries only the JSON, and a
// warning still has to land somewhere a test can read it. Defaults to stderr,
// which is where a warning belongs when nothing has been redirected.
var Err io.Writer = os.Stderr

const (
	minWidth = 40
	maxWidth = 72
)

// Entropy marks. Block heights read as a scale in the order they are declared,
// so the ramp survives with colour stripped -- which emoji traffic lights do
// not: they collapse to "some coloured circle" in monochrome, and the two ends
// of a five-point scale become indistinguishable.
//
// Each mark is one cell wide, so columns align regardless of terminal font.
var marks = [...]string{
	types.EntropyMinimal:  "▁",
	types.EntropyLow:      "▃",
	types.EntropyModerate: "▅",
	types.EntropyHigh:     "▇",
	types.EntropyCritical: "█",
}

// Adaptive colours: MODERATE yellow is close to invisible on a light
// background, and HIGH orange needs a darker shade there to stay legible
// against white. lipgloss picks per the terminal's reported background, and
// degrades TrueColor -> 256 -> ANSI -> none on its own.
var entropyColors = [...]lipgloss.TerminalColor{
	types.EntropyMinimal:  lipgloss.AdaptiveColor{Light: "#3B7A57", Dark: "#4E9A6A"},
	types.EntropyLow:      lipgloss.AdaptiveColor{Light: "#2E8B57", Dark: "#5FD75F"},
	types.EntropyModerate: lipgloss.AdaptiveColor{Light: "#B8860B", Dark: "#FFD75F"},
	types.EntropyHigh:     lipgloss.AdaptiveColor{Light: "#C05621", Dark: "#FF8700"},
	types.EntropyCritical: lipgloss.AdaptiveColor{Light: "#B00020", Dark: "#FF5F5F"},
}

var (
	dimStyle   = lipgloss.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "#6C6C6C", Dark: "#8A8A8A"})
	boldStyle  = lipgloss.NewStyle().Bold(true)
	voiceStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.AdaptiveColor{Light: "#00629B", Dark: "#5FD7FF"})
)

// entropyStyle returns the style for a level, bold at the extremes so the ramp
// still separates when a terminal collapses similar hues.
func entropyStyle(l types.SecurityEntropy) lipgloss.Style {
	s := lipgloss.NewStyle().Foreground(colorFor(l))
	if l == types.EntropyCritical {
		s = s.Bold(true)
	}
	if l == types.EntropyMinimal {
		s = s.Faint(true)
	}
	return s
}

func colorFor(l types.SecurityEntropy) lipgloss.TerminalColor {
	if int(l) < 0 || int(l) >= len(entropyColors) {
		return lipgloss.AdaptiveColor{Light: "#6C6C6C", Dark: "#8A8A8A"}
	}
	return entropyColors[l]
}

func markFor(l types.SecurityEntropy) string {
	if int(l) < 0 || int(l) >= len(marks) {
		return "?"
	}
	return marks[l]
}

// Mark renders an entropy level as its bar plus name, e.g. "▅ MODERATE".
func Mark(l types.SecurityEntropy) string {
	return entropyStyle(l).Render(markFor(l) + " " + l.String())
}

// Legend renders the full ramp, for help output and first runs.
func Legend() string {
	var b strings.Builder
	for l := types.EntropyMinimal; l <= types.EntropyCritical; l++ {
		fmt.Fprintf(&b, "  %s\n", Mark(l))
	}
	return b.String()
}

// width returns the usable render width, clamped so long lines stay readable on
// a maximised terminal and do not wrap on a narrow one.
func width() int {
	w, _, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil || w <= 0 {
		return maxWidth
	}
	if w > maxWidth {
		return maxWidth
	}
	if w < minWidth {
		return minWidth
	}
	return w
}

// Rule renders a titled horizontal rule: "── title ──────────".
// An empty title gives a plain rule. This is the only divider in the program;
// it replaces five hand-rolled variants of strings.Repeat.
func Rule(title string) string {
	w := width()
	if title == "" {
		return dimStyle.Render(strings.Repeat("─", w))
	}

	// Reserve "── " on the left, a space and at least three dashes on the right,
	// then truncate the title to whatever remains. Clamping only the tail would
	// let a long title push the line past w -- a 66-char title at width 72 gave
	// a 73-cell rule.
	const leadWidth, minTail = 3, 3
	budget := w - leadWidth - 1 - minTail
	if budget < 1 {
		budget = 1
	}
	if lipgloss.Width(title) > budget {
		title = truncate(title, budget)
	}

	tail := w - leadWidth - lipgloss.Width(title) - 1
	if tail < minTail {
		tail = minTail
	}
	return dimStyle.Render("── ") + boldStyle.Render(title) + " " +
		dimStyle.Render(strings.Repeat("─", tail))
}

// truncate cuts s to at most n cells, marking the cut with an ellipsis when
// there is room for one.
func truncate(s string, n int) string {
	if lipgloss.Width(s) <= n {
		return s
	}
	if n <= 1 {
		return string([]rune(s)[:n])
	}
	runes := []rune(s)
	out := make([]rune, 0, n)
	for _, r := range runes {
		if lipgloss.Width(string(append(out, r)))+1 > n {
			break
		}
		out = append(out, r)
	}
	return string(out) + "…"
}

// Say prints a line in yay-friend's own voice. See rule 2 in the package
// comment: this prefix is the only way to tell our output from the output of
// the thing being analysed.
func Say(format string, a ...any) {
	fmt.Fprintln(Out, voiceStyle.Render("::")+" "+fmt.Sprintf(format, a...))
}

// Ask prints a prompt in yay-friend's voice and leaves the cursor on the same
// line, so the user types their answer next to the question.
//
// This is separate from Say because Say ends the line. Routing the install
// confirmation through Say put the cursor underneath the question -- on the
// gate that asks whether to install a package with security concerns.
func Ask(format string, a ...any) {
	fmt.Fprint(Out, voiceStyle.Render("::")+" "+fmt.Sprintf(format, a...))
}

// Warn is Say for things that went wrong but are not fatal. It keeps the same
// voice prefix -- a warning from yay-friend must still be attributable to
// yay-friend -- and goes to stderr.
func Warn(format string, a ...any) {
	fmt.Fprintln(Err, voiceStyle.Render("::")+" "+
		entropyStyle(types.EntropyModerate).Render("warning")+" "+fmt.Sprintf(format, a...))
}

const labelWidth = 15

// Field prints one "label   value" row with a dim, fixed-width label so values
// align down the column.
func Field(label, value string) {
	fmt.Fprintf(Out, "  %s %s\n", dimStyle.Render(pad(label, labelWidth)), value)
}

// Bullet prints an indented list item.
func Bullet(format string, a ...any) {
	fmt.Fprintf(Out, "  %s %s\n", dimStyle.Render("•"), fmt.Sprintf(format, a...))
}

// Blank prints a single empty line.
func Blank() { fmt.Fprintln(Out) }

func pad(s string, n int) string {
	if w := lipgloss.Width(s); w < n {
		return s + strings.Repeat(" ", n-w)
	}
	return s
}

// Voice returns the bare `::` marker for callers that must build their own line
// -- the spinner repaints with \r and cannot go through Say.
func Voice() string { return voiceStyle.Render("::") }
