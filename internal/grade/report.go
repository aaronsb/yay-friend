// Package grade turns a yay-friend security analysis into structured output: a
// small JSON report meant to be read by another program rather than by a person.
//
// The contract is deliberately narrow. yay-friend answers one question — "how
// alarming is this tree, on a scale it declares" — and nothing else. What to do
// about that number is the calling program's decision, made with its own
// thresholds, so nothing in this package recommends, gates, or approves.
// yay-friend's own recommendation rides along in meta, where it is advisory and
// cannot move a verdict.
//
// That separation is what makes yay-friend referenceable: any host that wants a
// second opinion on a package can call it, without yay-friend needing to know
// what the host intends to do with the answer. pacrat
// (https://github.com/aaronsb/pacrat), which manages packages on pacman/AUR
// machines, is the reference consumer and the source of the wire format's name;
// it is not the only possible one, and nothing here is written to assume it.
//
// Translating to a JSON shape is a marshalling concern and belongs nowhere near
// the analyzer, so this package is the whole of that boundary. It replaces a jq
// program that used to live outside this repo, and produces identical numbers by
// construction (see the mapping notes on FromAnalysis).
package grade

import (
	"fmt"
	"strings"
	"unicode"

	"github.com/aaronsb/yay-friend/internal/types"
	"github.com/aaronsb/yay-friend/internal/version"
)

const (
	// Contract identifies the wire format, and a reader compares it byte for
	// byte: a report written to a contract it does not know is not read at all.
	//
	// The value keeps pacrat's spelling because pacrat shipped first and is the
	// reference consumer. That makes it a compatibility constant, not a
	// statement about who may call this -- renaming it would break every
	// existing reader to describe the same bytes.
	Contract = "pacrat-grade/v1"

	// Grader names the producer. Informational: a host generally files a grading
	// under the name in its own config and only mentions this one if they differ.
	Grader = "yay-friend"

	// ScaleMin and ScaleMax are yay-friend's entropy scale. Declared in the
	// report rather than assumed by the reader: a grade means nothing without
	// the range it sits on, and stating it makes a later change to the output
	// visible instead of silent.
	ScaleMin = 0
	ScaleMax = int(types.EntropyCritical)

	// maxFindings bounds the advisory list. A reader typically shows the worst
	// few and counts the rest, so a hundred annotations buy nothing and this is
	// supposed to be a few kilobytes of JSON.
	maxFindings = 25

	// maxTitle and maxNote bound two strings that pass through a file an
	// attacker may have written. They are sanitized here, on the way out: a
	// producer that leans on its reader to do it works only for readers that
	// happen to, and breaks the next one.
	maxTitle = 240
	maxNote  = 200
)

// Report is one grading, in the structured output format.
type Report struct {
	Contract string    `json:"contract"`
	Grader   string    `json:"grader"`
	Subject  Subject   `json:"subject"`
	Grade    int       `json:"grade"`
	Scale    Scale     `json:"scale"`
	Findings []Finding `json:"findings"`
	Meta     Meta      `json:"meta"`
}

// Subject is what was graded. package and commit are echoed back exactly as the
// caller spelled them, so the caller can check the grading is about the tree it
// asked about and discard one that answers a different question.
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

// Meta is opaque to the reader and preserved verbatim, with one convention:
// Note is meant for display under the result, so yay-friend's one-line summary
// goes there.
type Meta struct {
	Cached           bool   `json:"cached"`
	Provider         string `json:"provider,omitempty"`
	Note             string `json:"note,omitempty"`
	Recommendation   string `json:"recommendation,omitempty"`
	YayFriendVersion string `json:"yay_friend_version,omitempty"`
}

// FromAnalysis builds a grading of subj from a yay-friend analysis.
//
// The mapping is fixed by what the earlier external adapter did, so that a host
// running the old shim and a host running this subcommand read the same numbers
// off the same tree:
//
//   - grade is overall entropy as an integer, refused rather than squeezed into
//     range. Clamping a negative to 0 would turn a broken analysis into a
//     PROCEED, and clamping a 70 to 4 would invent a BLOCK nobody reported;
//     both are the approximation the contract says to decline.
//   - a finding's level is its entropy, clamped instead. Finding levels are
//     advisory and do not move the grade, so a level outside 0-255 would be
//     rejected by a strict parser and cost a whole grading over one annotation.
//   - a finding's span is PKGBUILD:<line> when the analyzer reported a line, and
//     absent otherwise. yay-friend does not record which file a finding came
//     from, so the adapter's per-file span was already always the PKGBUILD.
//
// cached says whether the analysis was replayed from yay-friend's own cache
// rather than produced by a model on this run. producedBy names the
// yay-friend version that produced the analysis — the cache entry's on a
// replay, empty for "this build" — because that is what the adapter reported
// under the same key, and a version that silently changed referent would
// disagree with it on every replayed hit.
func FromAnalysis(subj Subject, a *types.SecurityAnalysis, cached bool, producedBy string) (*Report, error) {
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
			Cached:         cached,
			Provider:       oneline(a.Provider),
			Note:           truncate(oneline(a.Summary), maxNote),
			Recommendation: oneline(a.Recommendation),
			YayFriendVersion: oneline(func() string {
				if producedBy != "" {
					return producedBy
				}
				return version.Version
			}()),
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
// would let a hostile PKGBUILD forge a line of the caller's own output. Whitespace
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
