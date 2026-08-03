package ui

import (
	"fmt"
	"strings"

	"github.com/aaronsb/yay-friend/internal/types"
)

// RenderAnalysis prints a security analysis.
//
// This is the only renderer. Before it, `yay-friend -S pkg` and
// `yay-friend analyze pkg` printed the same data through two separate
// functions, and they had drifted: the install path coloured its findings while
// the analyze path ran them through a getColoredLevel that returned the plain
// string, with a comment promising colour "when we implement the TUI".
//
// detailed controls whether provider and timestamp are shown; the analyze
// command wants them, an install in flight does not.
func RenderAnalysis(a *types.SecurityAnalysis, detailed bool) {
	Blank()
	fmt.Fprintln(Out, Rule(a.PackageName))

	Field("entropy", Mark(a.OverallLevel))
	if a.PredictabilityScore > 0 {
		Field("predictability", fmt.Sprintf("%.2f", a.PredictabilityScore))
	}
	if len(a.EntropyFactors) > 0 {
		Field("factors", strings.Join(a.EntropyFactors, ", "))
	}
	if detailed {
		if a.Provider != "" {
			Field("provider", dimStyle.Render(a.Provider))
		}
		if !a.AnalyzedAt.IsZero() {
			Field("analyzed", dimStyle.Render(a.AnalyzedAt.Format("2006-01-02 15:04:05")))
		}
	}

	if a.Summary != "" {
		Blank()
		fmt.Fprintln(Out, indent(a.Summary, "  "))
	}

	if a.Recommendation != "" {
		Blank()
		Field("recommend", a.Recommendation)
	}

	renderFindings(a.Findings)
	renderEducation(a)
}

func renderFindings(findings []types.SecurityFinding) {
	if len(findings) == 0 {
		Blank()
		fmt.Fprintln(Out, "  "+entropyStyle(types.EntropyMinimal).Render("▁")+" no findings")
		return
	}

	Blank()
	fmt.Fprintln(Out, Rule("findings"))
	for i, f := range findings {
		Blank()
		loc := ""
		if f.LineNumber > 0 {
			loc = dimStyle.Render(fmt.Sprintf("  line %d", f.LineNumber))
		}
		fmt.Fprintf(Out, "  %s %s  %s%s\n",
			dimStyle.Render(fmt.Sprintf("%d.", i+1)),
			Mark(f.Entropy),
			boldStyle.Render(f.Type),
			loc)

		if f.Description != "" {
			fmt.Fprintln(Out, indent(f.Description, "     "))
		}
		if f.Context != "" {
			fmt.Fprintf(Out, "     %s %s\n", dimStyle.Render("code"), f.Context)
		}
		if f.EntropyNotes != "" {
			fmt.Fprintf(Out, "     %s %s\n", dimStyle.Render("why "), f.EntropyNotes)
		}
		if f.Suggestion != "" {
			fmt.Fprintf(Out, "     %s %s\n", dimStyle.Render("do  "), f.Suggestion)
		}
	}
}

func renderEducation(a *types.SecurityAnalysis) {
	if a.EducationalSummary == "" && len(a.SecurityLessons) == 0 {
		return
	}
	Blank()
	fmt.Fprintln(Out, Rule("what to learn from this"))
	if a.EducationalSummary != "" {
		Blank()
		fmt.Fprintln(Out, indent(a.EducationalSummary, "  "))
	}
	if len(a.SecurityLessons) > 0 {
		Blank()
		for i, lesson := range a.SecurityLessons {
			fmt.Fprintf(Out, "  %s %s\n", dimStyle.Render(fmt.Sprintf("%d.", i+1)), lesson)
		}
	}
}

// RenderCollected shows what was gathered before analysis runs, so a slow AI
// call is not the first thing the user sees.
func RenderCollected(p *types.PackageInfo) {
	Blank()
	fmt.Fprintln(Out, Rule("collected for analysis"))

	Field("pkgbuild", fmt.Sprintf("%d lines of shell", len(strings.Split(p.PKGBUILD, "\n"))))
	Field("package", fmt.Sprintf("%s %s", p.Name, dimStyle.Render(p.Version)))
	if p.Maintainer != "" {
		Field("maintainer", p.Maintainer)
	}
	if len(p.Dependencies) > 0 {
		Field("runtime deps", summarize(p.Dependencies, 3))
	}
	if len(p.MakeDepends) > 0 {
		Field("build deps", summarize(p.MakeDepends, 3))
	}
	if len(p.OptDepends) > 0 {
		Field("optional deps", fmt.Sprintf("%d", len(p.OptDepends)))
	}
	if p.FirstSubmitted != "" && p.LastUpdated != "" {
		Field("aur history", dimStyle.Render(fmt.Sprintf("submitted %s, updated %s", p.FirstSubmitted, p.LastUpdated)))
	}
	if p.Votes > 0 || p.Popularity > 0 {
		Field("community", fmt.Sprintf("%d votes, %.3f popularity", p.Votes, p.Popularity))
	}
	if len(p.AdditionalFiles) > 0 {
		names := make([]string, 0, len(p.AdditionalFiles))
		for n := range p.AdditionalFiles {
			names = append(names, n)
		}
		Field("extra files", summarize(names, 4))
	}
}

// summarize joins up to max items, noting how many were elided.
func summarize(items []string, max int) string {
	if len(items) <= max {
		return strings.Join(items, ", ")
	}
	return fmt.Sprintf("%s %s",
		strings.Join(items[:max], ", "),
		dimStyle.Render(fmt.Sprintf("(+%d more)", len(items)-max)))
}

// indent prefixes every line of s, so wrapped prose stays inside the column.
func indent(s, prefix string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i, l := range lines {
		lines[i] = prefix + l
	}
	return strings.Join(lines, "\n")
}
