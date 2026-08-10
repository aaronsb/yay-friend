package grade

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/aaronsb/yay-friend/internal/types"
	"github.com/aaronsb/yay-friend/internal/version"
)

// helloAnalysis is the analysis behind the cache entry the contrib adapter's
// test suite grades (pacrat's contrib/graders/test-yay-friend-grade.sh). The
// expectations below are that suite's expectations: a host running the shim and
// a host running `yay-friend grade` must read the same numbers off the same
// tree, and this is where the two mappings are held together.
func helloAnalysis() *types.SecurityAnalysis {
	return &types.SecurityAnalysis{
		PackageName:    "hello",
		OverallEntropy: types.EntropyLow,
		OverallLevel:   types.EntropyLow,
		Findings: []types.SecurityFinding{
			{
				Type:        "source_analysis",
				Entropy:     types.EntropyModerate,
				Severity:    types.EntropyModerate,
				Description: "Source downloaded from official GNU FTP\n  server",
				LineNumber:  12,
				Context:     "source=(https://ftp.gnu.org/gnu/hello/$pkgname-$pkgver.tar.gz)",
				Suggestion:  "Legitimate source location",
			},
			{
				Type:        "maintainer_trust",
				Entropy:     types.EntropyLow,
				Severity:    types.EntropyLow,
				Description: "Package has low popularity but is actively maintained",
			},
		},
		Summary:        "Clean package.",
		Recommendation: "PROCEED",
		Provider:       "claude",
	}
}

func helloSubject() Subject {
	return Subject{
		Package: "hello",
		Commit:  "51cec6333515471681ec8aa00943145d420311fa",
		Version: "2.12.1-1",
	}
}

func TestFromAnalysisMatchesTheAdapterMapping(t *testing.T) {
	report, err := FromAnalysis(helloSubject(), helloAnalysis(), true)
	if err != nil {
		t.Fatalf("FromAnalysis: %v", err)
	}

	if report.Contract != "pacrat-grade/v1" {
		t.Errorf("contract = %q, want pacrat-grade/v1", report.Contract)
	}
	if report.Grader != "yay-friend" {
		t.Errorf("grader = %q, want yay-friend", report.Grader)
	}
	if report.Grade != 1 {
		t.Errorf("grade = %d, want 1", report.Grade)
	}
	if report.Scale != (Scale{Min: 0, Max: 4}) {
		t.Errorf("scale = %+v, want {0 4}", report.Scale)
	}
	if report.Subject != helloSubject() {
		t.Errorf("subject = %+v, want %+v", report.Subject, helloSubject())
	}

	want := []Finding{
		{
			Level: 2,
			Title: "source_analysis: Source downloaded from official GNU FTP server",
			Span:  "PKGBUILD:12",
		},
		{
			Level: 1,
			Title: "maintainer_trust: Package has low popularity but is actively maintained",
		},
	}
	if len(report.Findings) != len(want) {
		t.Fatalf("got %d findings, want %d", len(report.Findings), len(want))
	}
	for i := range want {
		if report.Findings[i] != want[i] {
			t.Errorf("finding %d = %+v, want %+v", i, report.Findings[i], want[i])
		}
	}

	wantMeta := Meta{
		Cached:           true,
		Provider:         "claude",
		Note:             "Clean package.",
		Recommendation:   "PROCEED",
		YayFriendVersion: version.Version,
	}
	if report.Meta != wantMeta {
		t.Errorf("meta = %+v, want %+v", report.Meta, wantMeta)
	}
}

// An overall entropy the report cannot place on 0-4 is refused, never squeezed
// into range: clamping a negative to 0 would turn a broken analysis into a
// PROCEED, and clamping a 70 to 4 would invent a BLOCK nobody reported.
func TestFromAnalysisRefusesEntropyOutsideTheScale(t *testing.T) {
	for _, entropy := range []types.SecurityEntropy{-1, 5, 70, 256} {
		analysis := helloAnalysis()
		analysis.OverallEntropy = entropy

		report, err := FromAnalysis(helloSubject(), analysis, false)
		if err == nil {
			t.Errorf("entropy %d: expected a refusal, got grade %d", entropy, report.Grade)
		}
		if report != nil {
			t.Errorf("entropy %d: a refusal must not produce a partial grading", entropy)
		}
	}
}

func TestFromAnalysisRefusesANilAnalysis(t *testing.T) {
	if _, err := FromAnalysis(helloSubject(), nil, false); err == nil {
		t.Error("expected a refusal for a nil analysis")
	}
}

// A finding level, by contrast, is advisory and is clamped: pacrat's parser
// takes 0-255 and rejects the whole grading outside it, so a broken annotation
// must not be allowed to cost the grade.
func TestFromAnalysisClampsFindingLevels(t *testing.T) {
	analysis := helloAnalysis()
	analysis.Findings[0].Entropy = 4000
	analysis.Findings[1].Entropy = -7

	report, err := FromAnalysis(helloSubject(), analysis, false)
	if err != nil {
		t.Fatalf("a wild finding level must not cost the grading: %v", err)
	}
	if report.Grade != 1 {
		t.Errorf("grade = %d, want 1 (findings do not move the grade)", report.Grade)
	}
	if got := []int{report.Findings[0].Level, report.Findings[1].Level}; got[0] != 4 || got[1] != 0 {
		t.Errorf("levels = %v, want [4 0]", got)
	}
}

// Every string here is printed on pacrat's own report, having just passed
// through a file an attacker may have written. A newline in a title would let a
// grader forge a line of that report.
func TestFromAnalysisFlattensAndStripsTitles(t *testing.T) {
	analysis := helloAnalysis()
	analysis.Findings[0].Description = "before\x1b[31m\x07mid\x7fafter"

	report, err := FromAnalysis(helloSubject(), analysis, false)
	if err != nil {
		t.Fatalf("control characters should not fail the grading: %v", err)
	}

	got := report.Findings[0].Title
	if want := "source_analysis: before[31mmidafter"; got != want {
		t.Errorf("title = %q, want %q", got, want)
	}
	for _, r := range got {
		if r < 0x20 || r == 0x7f {
			t.Errorf("title %q still carries control character %q", got, r)
		}
	}
}

func TestFromAnalysisDescribesAFindingWithNoText(t *testing.T) {
	analysis := helloAnalysis()
	analysis.Findings = []types.SecurityFinding{{Entropy: types.EntropyHigh}}

	report, err := FromAnalysis(helloSubject(), analysis, false)
	if err != nil {
		t.Fatalf("FromAnalysis: %v", err)
	}
	if report.Findings[0].Title != "(no description)" {
		t.Errorf("title = %q, want (no description)", report.Findings[0].Title)
	}
	if report.Findings[0].Span != "" {
		t.Errorf("span = %q, want none for a finding with no line", report.Findings[0].Span)
	}
}

func TestFromAnalysisCapsFindings(t *testing.T) {
	analysis := helloAnalysis()
	analysis.Findings = nil
	for i := 0; i < 60; i++ {
		analysis.Findings = append(analysis.Findings, types.SecurityFinding{
			Type:        "source_analysis",
			Entropy:     types.EntropyModerate,
			Description: fmt.Sprintf("finding %d", i),
		})
	}

	report, err := FromAnalysis(helloSubject(), analysis, false)
	if err != nil {
		t.Fatalf("a long findings list should still grade: %v", err)
	}
	if len(report.Findings) != maxFindings {
		t.Errorf("got %d findings, want %d", len(report.Findings), maxFindings)
	}
}

func TestFromAnalysisTruncatesLongText(t *testing.T) {
	analysis := helloAnalysis()
	analysis.Findings[0].Type = ""
	analysis.Findings[0].Description = strings.Repeat("x", 500)
	analysis.Summary = strings.Repeat("y", 500)

	report, err := FromAnalysis(helloSubject(), analysis, false)
	if err != nil {
		t.Fatalf("FromAnalysis: %v", err)
	}
	if n := len([]rune(report.Findings[0].Title)); n != maxTitle {
		t.Errorf("title is %d runes, want %d", n, maxTitle)
	}
	if !strings.HasSuffix(report.Findings[0].Title, "…") {
		t.Error("a truncated title should say so")
	}
	if n := len([]rune(report.Meta.Note)); n != maxNote {
		t.Errorf("note is %d runes, want %d", n, maxNote)
	}
}

// An analysis with nothing to report marshals its findings as [] rather than
// null. Both parse, but the contract's default is an empty list.
func TestReportWithNoFindingsMarshalsAnEmptyList(t *testing.T) {
	analysis := helloAnalysis()
	analysis.Findings = nil

	report, err := FromAnalysis(helloSubject(), analysis, false)
	if err != nil {
		t.Fatalf("FromAnalysis: %v", err)
	}
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !strings.Contains(string(data), `"findings":[]`) {
		t.Errorf("findings should marshal as []: %s", data)
	}
}

// contractReport mirrors pacrat-grade/v1 as pacrat reads it, with every field a
// pointer or an interface so "absent" and "present but wrong type" are
// distinguishable. Decoding through it is the check that what we emit is what
// the contract describes, rather than what our own structs happen to say.
type contractReport struct {
	Contract *string `json:"contract"`
	Grader   *string `json:"grader"`
	Subject  *struct {
		Package *string `json:"package"`
		Commit  *string `json:"commit"`
		Version *string `json:"version"`
	} `json:"subject"`
	Grade *json.Number `json:"grade"`
	Scale *struct {
		Min *json.Number `json:"min"`
		Max *json.Number `json:"max"`
	} `json:"scale"`
	Findings []struct {
		Level *json.Number `json:"level"`
		Title *string      `json:"title"`
		Span  *string      `json:"span"`
	} `json:"findings"`
	Meta map[string]any `json:"meta"`
}

func TestReportConformsToTheContract(t *testing.T) {
	analysis := helloAnalysis()
	analysis.OverallEntropy = types.EntropyCritical

	report, err := FromAnalysis(helloSubject(), analysis, true)
	if err != nil {
		t.Fatalf("FromAnalysis: %v", err)
	}
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var got contractReport
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("the grading does not decode as pacrat-grade/v1: %v", err)
	}

	if got.Contract == nil || *got.Contract != "pacrat-grade/v1" {
		t.Fatalf("contract = %v, want pacrat-grade/v1", got.Contract)
	}
	if got.Grader == nil || *got.Grader == "" {
		t.Error("grader is required and must be non-empty")
	}
	if got.Subject == nil {
		t.Fatal("subject is required")
	}
	if got.Subject.Package == nil || *got.Subject.Package == "" {
		t.Error("subject.package is required and must be non-empty")
	}
	if got.Subject.Commit == nil || *got.Subject.Commit == "" {
		t.Error("subject.commit is required and must be non-empty")
	}
	if got.Grade == nil {
		t.Fatal("grade is required")
	}
	if got.Scale == nil || got.Scale.Min == nil || got.Scale.Max == nil {
		t.Fatal("scale was declared, so both bounds must be present")
	}

	min := mustU8(t, "scale.min", *got.Scale.Min)
	max := mustU8(t, "scale.max", *got.Scale.Max)
	if min >= max {
		t.Errorf("scale %d-%d is degenerate", min, max)
	}
	grade := mustU8(t, "grade", *got.Grade)
	if grade < min || grade > max {
		t.Errorf("grade %d is outside the declared scale %d-%d", grade, min, max)
	}

	for i, f := range got.Findings {
		if f.Level != nil {
			mustU8(t, fmt.Sprintf("findings[%d].level", i), *f.Level)
		}
		if f.Title != nil && strings.ContainsAny(*f.Title, "\r\n") {
			t.Errorf("findings[%d].title spans more than one line", i)
		}
	}

	// meta is opaque to pacrat, with one convention: meta.note is printed under
	// the result.
	if note, ok := got.Meta["note"].(string); !ok || note == "" {
		t.Errorf("meta.note = %v, want the analyzer's one-line summary", got.Meta["note"])
	}
	if cached, ok := got.Meta["cached"].(bool); !ok || !cached {
		t.Errorf("meta.cached = %v, want true", got.Meta["cached"])
	}
}

// mustU8 enforces the contract's one arithmetic rule: every number in a grading
// is an integer in 0-255, and a fractional or out-of-range one fails to parse
// rather than being clamped.
func mustU8(t *testing.T, field string, n json.Number) int {
	t.Helper()
	i, err := n.Int64()
	if err != nil {
		t.Fatalf("%s = %s, which is not an integer", field, n)
	}
	if i < 0 || i > 255 {
		t.Fatalf("%s = %d, which is not a u8", field, i)
	}
	return int(i)
}
