package ui

import (
	"bytes"
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"

	"github.com/aaronsb/yay-friend/internal/types"
)

// plain forces colour off so assertions compare text, not escape sequences.
func plain(t *testing.T) *bytes.Buffer {
	t.Helper()
	prev := Out
	lipgloss.SetColorProfile(termenv.Ascii)
	buf := &bytes.Buffer{}
	Out = buf
	t.Cleanup(func() { Out = prev })
	return buf
}

// TestMarksAreDistinct is the property that made the bar ramp worth choosing
// over emoji chips: all five levels stay distinguishable with colour stripped.
// The icons this replaced mapped MINIMAL and LOW both to a green circle and
// HIGH and CRITICAL both to a red one, rendering a five-point scale at three
// points of resolution.
func TestMarksAreDistinct(t *testing.T) {
	plain(t)
	seen := map[string]types.SecurityEntropy{}
	for l := types.EntropyMinimal; l <= types.EntropyCritical; l++ {
		m := markFor(l)
		if prev, dup := seen[m]; dup {
			t.Errorf("mark %q used for both %s and %s", m, prev, l)
		}
		seen[m] = l
	}
	if len(seen) != 5 {
		t.Errorf("got %d distinct marks, want 5", len(seen))
	}
}

// TestMarksAreSingleWidth: a two-cell glyph shifts every column after it, which
// is what made the emoji variant misalign across terminals.
func TestMarksAreSingleWidth(t *testing.T) {
	plain(t)
	for l := types.EntropyMinimal; l <= types.EntropyCritical; l++ {
		if w := lipgloss.Width(markFor(l)); w != 1 {
			t.Errorf("%s mark %q is %d cells wide, want 1", l, markFor(l), w)
		}
	}
}

func TestMarkCarriesLevelName(t *testing.T) {
	plain(t)
	for l := types.EntropyMinimal; l <= types.EntropyCritical; l++ {
		if got := Mark(l); !strings.Contains(got, l.String()) {
			t.Errorf("Mark(%s) = %q, missing level name", l, got)
		}
	}
}

// TestMarkOutOfRange: SecurityEntropy is an int, and a malformed cached
// analysis or a provider returning garbage can carry a value outside the ramp.
// That must not panic on an array index.
func TestMarkOutOfRange(t *testing.T) {
	plain(t)
	for _, l := range []types.SecurityEntropy{-1, 99} {
		if got := Mark(l); got == "" {
			t.Errorf("Mark(%d) returned empty", l)
		}
	}
}

func TestRuleFitsWidth(t *testing.T) {
	plain(t)
	for _, title := range []string{"", "pkg", "a-very-long-package-name-that-runs-on-and-on-and-on"} {
		got := Rule(title)
		if w := lipgloss.Width(got); w > maxWidth {
			t.Errorf("Rule(%q) is %d cells, exceeds maxWidth %d", title, w, maxWidth)
		}
		if title != "" && !strings.Contains(got, title) {
			t.Errorf("Rule(%q) lost its title: %q", title, got)
		}
	}
}

// TestVoicePrefix guards the trust boundary. Every line yay-friend speaks must
// carry the marker, because its output interleaves with output from the package
// being analysed.
func TestVoicePrefix(t *testing.T) {
	buf := plain(t)
	Say("hello %s", "world")
	got := buf.String()
	if !strings.HasPrefix(got, ":: ") {
		t.Errorf("Say output %q does not start with the voice marker", got)
	}
	if !strings.Contains(got, "hello world") {
		t.Errorf("Say dropped its message: %q", got)
	}
}

func TestRenderAnalysisIncludesEssentials(t *testing.T) {
	buf := plain(t)
	RenderAnalysis(&types.SecurityAnalysis{
		PackageName:         "demo-pkg",
		OverallLevel:        types.EntropyModerate,
		PredictabilityScore: 0.62,
		EntropyFactors:      []string{"precompiled binary"},
		Summary:             "A summary line.",
		Findings: []types.SecurityFinding{{
			Type:        "opaque-blob",
			Entropy:     types.EntropyHigh,
			Description: "base64 payload piped to sh",
			LineNumber:  42,
		}},
	}, false)

	for _, want := range []string{
		"demo-pkg", "MODERATE", "0.62", "precompiled binary",
		"A summary line.", "opaque-blob", "HIGH", "line 42",
	} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("rendered analysis missing %q\n---\n%s", want, buf.String())
		}
	}
}

// TestRenderAnalysisNoFindings: the empty case must say so rather than render a
// bare heading with nothing under it.
func TestRenderAnalysisNoFindings(t *testing.T) {
	buf := plain(t)
	RenderAnalysis(&types.SecurityAnalysis{
		PackageName:  "clean-pkg",
		OverallLevel: types.EntropyMinimal,
	}, false)
	if !strings.Contains(buf.String(), "no findings") {
		t.Errorf("clean analysis should say so:\n%s", buf.String())
	}
}

// TestNoColorStripsEscapes: with colour off, output must contain no ANSI escape
// sequences at all -- including from the entropy ramp, which is the only thing
// permitted to emit colour in the first place.
func TestNoColorStripsEscapes(t *testing.T) {
	buf := plain(t)
	Say("plain line")
	RenderAnalysis(&types.SecurityAnalysis{
		PackageName:  "x",
		OverallLevel: types.EntropyCritical,
		Findings:     []types.SecurityFinding{{Type: "t", Entropy: types.EntropyHigh}},
	}, true)
	if strings.Contains(buf.String(), "\x1b[") {
		t.Errorf("colour disabled but output carries ANSI escapes:\n%q", buf.String())
	}
}

func TestSummarizeElides(t *testing.T) {
	plain(t)
	got := summarize([]string{"a", "b", "c", "d", "e"}, 3)
	if !strings.Contains(got, "a, b, c") || !strings.Contains(got, "+2 more") {
		t.Errorf("summarize = %q", got)
	}
	if got := summarize([]string{"a", "b"}, 3); got != "a, b" {
		t.Errorf("short list should not be elided, got %q", got)
	}
}
