package ui

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"

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

// TestRuleFitsWidth asserts against the width actually in use, and includes
// titles longer than the line. An earlier version clamped only the tail, so a
// 66-cell title at width 72 produced a 73-cell rule; asserting against the
// maxWidth constant with a short title could not see it.
func TestRuleFitsWidth(t *testing.T) {
	plain(t)
	w := width()
	for _, title := range []string{
		"",
		"pkg",
		"a-very-long-package-name-that-runs-on-and-on-and-on",
		strings.Repeat("x", w-6),
		strings.Repeat("x", w),
		strings.Repeat("x", w*2),
		strings.Repeat("🌪", w), // wide runes: cell count != rune count
	} {
		got := Rule(title)
		if gw := lipgloss.Width(got); gw != w {
			t.Errorf("Rule(len %d title) is %d cells, want exactly %d", lipgloss.Width(title), gw, w)
		}
	}
	if got := Rule("pkg"); !strings.Contains(got, "pkg") {
		t.Errorf("Rule lost a title that fits: %q", got)
	}
}

// TestAskLeavesCursorInline: Say ends the line, Ask must not. The install
// confirmation is the gate that asks whether to proceed despite security
// concerns, and it reads wrong with the cursor on the next line.
func TestAskLeavesCursorInline(t *testing.T) {
	buf := plain(t)
	Ask("continue? [y/N]: ")
	if got := buf.String(); strings.HasSuffix(got, "\n") {
		t.Errorf("Ask output ends with a newline: %q", got)
	}
	buf.Reset()
	Say("done")
	if got := buf.String(); !strings.HasSuffix(got, "\n") {
		t.Errorf("Say output should end with a newline: %q", got)
	}
}

// TestNoFieldSilentlyDropped fills every displayed field with a unique sentinel
// and asserts each one reaches the output, at both detail levels.
//
// This exists because the change that introduced this package collapsed two
// renderers into one. For a security tool, a field that quietly stops being
// displayed is a defect with no symptom: the user simply never sees a finding
// that might have changed their decision.
func TestNoFieldSilentlyDropped(t *testing.T) {
	analysis := &types.SecurityAnalysis{
		PackageName:         "SENTINEL_PKGNAME",
		OverallLevel:        types.EntropyHigh,
		PredictabilityScore: 0.77,
		EntropyFactors:      []string{"SENTINEL_FACTOR"},
		Summary:             "SENTINEL_SUMMARY",
		Recommendation:      "SENTINEL_RECOMMENDATION",
		Provider:            "SENTINEL_PROVIDER",
		EducationalSummary:  "SENTINEL_EDUCATION",
		SecurityLessons:     []string{"SENTINEL_LESSON"},
		AnalyzedAt:          time.Date(2026, 8, 3, 14, 27, 2, 0, time.UTC),
		Findings: []types.SecurityFinding{{
			Type:         "SENTINEL_TYPE",
			Entropy:      types.EntropyCritical,
			Description:  "SENTINEL_DESCRIPTION",
			Context:      "SENTINEL_CONTEXT",
			Suggestion:   "SENTINEL_SUGGESTION",
			EntropyNotes: "SENTINEL_NOTES",
			LineNumber:   4242,
		}},
	}

	always := []string{
		"SENTINEL_PKGNAME", "SENTINEL_FACTOR", "SENTINEL_SUMMARY",
		"SENTINEL_RECOMMENDATION", "SENTINEL_EDUCATION", "SENTINEL_LESSON",
		"SENTINEL_TYPE", "SENTINEL_DESCRIPTION", "SENTINEL_CONTEXT",
		"SENTINEL_SUGGESTION", "SENTINEL_NOTES", "4242", "0.77",
		"HIGH", "CRITICAL",
	}

	for _, detailed := range []bool{false, true} {
		t.Run(fmt.Sprintf("detailed=%v", detailed), func(t *testing.T) {
			buf := plain(t)
			RenderAnalysis(analysis, detailed)
			out := buf.String()
			want := always
			if detailed {
				want = append(append([]string{}, always...), "SENTINEL_PROVIDER", "2026-08-03")
			}
			for _, w := range want {
				if !strings.Contains(out, w) {
					t.Errorf("field %q never reached the output\n---\n%s", w, out)
				}
			}
		})
	}
}

// TestCollectedFieldsRendered is the same invariant for the pre-analysis view.
func TestCollectedFieldsRendered(t *testing.T) {
	buf := plain(t)
	RenderCollected(&types.PackageInfo{
		Name: "SENTINEL_NAME", Version: "SENTINEL_VERSION",
		Maintainer:   "SENTINEL_MAINTAINER",
		PKGBUILD:     "a\nb\nc",
		Dependencies: []string{"SENTINEL_DEP"},
		MakeDepends:  []string{"SENTINEL_MAKEDEP"},
		OptDepends:   []string{"SENTINEL_OPTDEP"},
		Votes:        412, Popularity: 8.213,
		FirstSubmitted: "SENTINEL_SUBMITTED", LastUpdated: "SENTINEL_UPDATED",
		AdditionalFiles: map[string]string{"SENTINEL_FILE": ""},
	})
	for _, w := range []string{
		"SENTINEL_NAME", "SENTINEL_VERSION", "SENTINEL_MAINTAINER",
		"SENTINEL_DEP", "SENTINEL_MAKEDEP", "SENTINEL_SUBMITTED",
		"SENTINEL_UPDATED", "SENTINEL_FILE", "412", "8.213",
	} {
		if !strings.Contains(buf.String(), w) {
			t.Errorf("collected field %q missing\n---\n%s", w, buf.String())
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
