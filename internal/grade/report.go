// Package grade translates a yay-friend security analysis into a
// pacrat-grade/v1 report.
//
// pacrat (https://github.com/aaronsb/pacrat) gates AUR package updates on a
// grade produced by any program that speaks its contract. The contract is
// deliberately narrow: a grader answers "how alarming is this tree, on a scale
// it declares", and nothing else. PROCEED / WARN / BLOCK is pacrat's data,
// derived from that number by the host's own thresholds — so nothing in this
// package recommends, gates, or approves. yay-friend's own recommendation rides
// along in meta, where it is advisory and cannot move a verdict.
//
// This package is yay-friend's side of that boundary, and the whole of it: the
// contract is a JSON shape, so translating to it is a marshalling concern and
// belongs nowhere near the analyzer. What was previously done outside this repo
// by contrib/graders/yay-friend-grade — a jq program in pacrat's tree — now
// happens here, and the numbers it produces are identical by construction (see
// the mapping notes on FromAnalysis).
package grade

import (
	"fmt"
	"strings"
	"unicode"

	"github.com/aaronsb/yay-friend/internal/types"
	"github.com/aaronsb/yay-friend/internal/version"
)

const (
	// Contract is compared byte for byte by pacrat. A report written to a
	// contract it does not know is not read at all.
	Contract = "pacrat-grade/v1"

	// Grader names the producer. Informational: pacrat files a grading under
	// the name in its own config and only mentions this one if they differ.
	Grader = "yay-friend"

	// ScaleMin and ScaleMax are yay-friend's entropy scale, which happens to be
	// pacrat's default. Declared explicitly all the same: it costs one line and
	// it makes a later change to the output visible instead of silent.
	ScaleMin = 0
	ScaleMax = int(types.EntropyCritical)

	// maxFindings bounds the advisory list. pacrat shows the five worst and
	// counts the rest, so a hundred annotations buy nothing and a grading is
	// supposed to be a few kilobytes of JSON.
	maxFindings = 25

	// maxTitle and maxNote bound two strings that pass through a file an
	// attacker may have written. pacrat neuters control characters and flattens
	// each string onto one line before display; a grader that leans on its
	// reader to sanitize is a grader that breaks the next reader.
	maxTitle = 240
	maxNote  = 200
)

// Report is a pacrat-grade/v1 grading.
type Report struct {
	Contract string    `json:"contract"`
	Grader   string    `json:"grader"`
	Subject  Subject   `json:"subject"`
	Grade    int       `json:"grade"`
	Scale    Scale     `json:"scale"`
	Findings []Finding `json:"findings"`
	Meta     Meta      `json:"meta"`
}

// Subject is what was graded. package and commit are echoed back exactly as
// pacrat spelled them: pacrat compares them against its own idea of the subject
// and discards a grading of anything else.
type Subject struct {
	Package string `json:"package"`
	Commit  string `json:"commit"`
	Version string `json:"version,omitempty"`
}

// Scale is the range Grade lives on.
type Scale struct {
	Min int `json:"min"`
	Max int `json:"max"`
}

// Finding is one thing a human should look at. Advisory: findings never move
// the grade, the grade moves the verdict.
type Finding struct {
	Level int    `json:"level"`
	Title string `json:"title"`
	Span  string `json:"span,omitempty"`
}

// Meta is opaque to pacrat and preserved verbatim, with one convention: Note is
// printed under the result, so yay-friend's one-line summary goes there.
type Meta struct {
	Cached           bool   `json:"cached"`
	Provider         string `json:"provider,omitempty"`
	Note             string `json:"note,omitempty"`
	Recommendation   string `json:"recommendation,omitempty"`
	YayFriendVersion string `json:"yay_friend_version,omitempty"`
}

// FromAnalysis builds a grading of subj from a yay-friend analysis.
//
// The mapping is fixed by what the contrib adapter already did, so that a host
// running the old shim and a host running this subcommand read the same numbers
// off the same tree:
//
//   - grade is overall entropy as an integer, refused rather than squeezed into
//     range. Clamping a negative to 0 would turn a broken analysis into a
//     PROCEED, and clamping a 70 to 4 would invent a BLOCK nobody reported;
//     both are the approximation the contract says to decline.
//   - a finding's level is its entropy, clamped instead. Finding levels are
//     advisory and do not move the grade, so a level outside 0-255 would be
//     rejected by pacrat's parser and cost a whole grading over one annotation.
//   - a finding's span is PKGBUILD:<line> when the analyzer reported a line, and
//     absent otherwise. yay-friend does not record which file a finding came
//     from, so the adapter's per-file span was already always the PKGBUILD.
//
// cached says whether the analysis was replayed from yay-friend's own cache
// rather than produced by a model on this run.
func FromAnalysis(subj Subject, a *types.SecurityAnalysis, cached bool) (*Report, error) {
	if a == nil {
		return nil, fmt.Errorf("no analysis to grade")
	}
	entropy := int(a.OverallEntropy)
	if entropy < ScaleMin || entropy > ScaleMax {
		return nil, fmt.Errorf("overall entropy is %d, which is not a %d-%d level",
			entropy, ScaleMin, ScaleMax)
	}

	findings := a.Findings
	if len(findings) > maxFindings {
		findings = findings[:maxFindings]
	}
	// Non-nil so an analysis with nothing to report marshals as [] rather than
	// null. Both parse, but the contract's default is an empty list and a reader
	// looking at the JSON should see one.
	out := make([]Finding, 0, len(findings))
	for _, f := range findings {
		out = append(out, Finding{
			Level: clamp(int(f.Entropy)),
			Title: title(f),
			Span:  span(f),
		})
	}

	return &Report{
		Contract: Contract,
		Grader:   Grader,
		Subject:  subj,
		Grade:    entropy,
		Scale:    Scale{Min: ScaleMin, Max: ScaleMax},
		Findings: out,
		Meta: Meta{
			Cached:           cached,
			Provider:         oneline(a.Provider),
			Note:             truncate(oneline(a.Summary), maxNote),
			Recommendation:   oneline(a.Recommendation),
			YayFriendVersion: oneline(version.Version),
		},
	}, nil
}

func title(f types.SecurityFinding) string {
	parts := make([]string, 0, 2)
	for _, s := range []string{oneline(f.Type), oneline(f.Description)} {
		if s != "" {
			parts = append(parts, s)
		}
	}
	t := truncate(strings.Join(parts, ": "), maxTitle)
	if t == "" {
		return "(no description)"
	}
	return t
}

func span(f types.SecurityFinding) string {
	if f.LineNumber <= 0 {
		return ""
	}
	return fmt.Sprintf("PKGBUILD:%d", f.LineNumber)
}

func clamp(level int) int {
	if level < ScaleMin {
		return ScaleMin
	}
	if level > ScaleMax {
		return ScaleMax
	}
	return level
}

// oneline flattens s onto a single line and strips the control characters that
// would let a hostile PKGBUILD forge a line of pacrat's own report. Whitespace
// collapses first, so a newline becomes a space rather than welding two words
// together when the remaining controls are removed.
func oneline(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	space := false
	for _, r := range s {
		switch {
		case unicode.IsSpace(r):
			space = true
		case r < 0x20 || r == 0x7f:
			// Dropped outright: these are the forging characters, and they
			// separate nothing.
		default:
			if space && b.Len() > 0 {
				b.WriteRune(' ')
			}
			space = false
			b.WriteRune(r)
		}
	}
	return b.String()
}

// truncate cuts s to at most n runes, marking the cut with an ellipsis.
func truncate(s string, n int) string {
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	return string(runes[:n-1]) + "…"
}
