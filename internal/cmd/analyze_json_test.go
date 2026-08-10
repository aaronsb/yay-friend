package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/aaronsb/yay-friend/internal/types"
	"github.com/aaronsb/yay-friend/internal/ui"
	"github.com/aaronsb/yay-friend/internal/version"
)

// analyzeHarness runs `yay-friend analyze --file` against a staged tree with a
// provider that never calls a model, capturing the two streams apart.
func analyzeHarness(t *testing.T) (*fakeProvider, string, gradeRunner) {
	t.Helper()

	home := t.TempDir()
	t.Setenv("XDG_DATA_HOME", home+"/data")
	t.Setenv("XDG_CONFIG_HOME", home+"/config")

	fake := &fakeProvider{analysis: richAnalysis()}
	restoreProvider := resolveProvider
	resolveProvider = func(ctx context.Context, cfg *types.Config) (types.AIProvider, error) {
		return fake, nil
	}
	out := ui.Out
	t.Cleanup(func() {
		resolveProvider = restoreProvider
		ui.Out = out
		fileFlag = ""
	})

	run := func(args ...string) (string, string, error) {
		cmd := newAnalyzeCmd()
		var stdout, stderr bytes.Buffer
		cmd.SetOut(&stdout)
		cmd.SetErr(&stderr)
		cmd.SetArgs(append([]string{}, args...))
		err := cmd.Execute()
		return stdout.String(), stderr.String(), err
	}

	return fake, writeTree(t, home), run
}

// richAnalysis carries the fields that exist in yay-friend's own shape and have
// no home in a grading contract. They are the reason --json exists.
func richAnalysis() *types.SecurityAnalysis {
	a := cleanAnalysis()
	a.PredictabilityScore = 0.92
	a.EntropyFactors = []string{"single upstream source", "no install-time network"}
	a.EducationalSummary = "Checksum-pinned sources are what a boring package looks like."
	a.SecurityLessons = []string{"SKIP on a VCS source is normal", "read .install hooks first"}
	a.Findings[0].Suggestion = "No action needed"
	a.Findings[0].EntropyNotes = "expected, best-practice packaging"
	return a
}

func TestAnalyzeJSONWritesOneCleanObjectToStdout(t *testing.T) {
	_, tree, run := analyzeHarness(t)

	stdout, stderr, err := run("--file", tree, "--json")
	if err != nil {
		t.Fatalf("analyze --json failed: %v\n%s", err, stderr)
	}

	if !strings.HasPrefix(stdout, "{") || !strings.HasSuffix(stdout, "}\n") {
		t.Errorf("stdout is not exactly one JSON object:\n%s", stdout)
	}
	if strings.Contains(stdout, "\x1b") {
		t.Error("stdout carries ANSI escapes")
	}

	decoder := json.NewDecoder(strings.NewReader(stdout))
	var first json.RawMessage
	if err := decoder.Decode(&first); err != nil {
		t.Fatalf("stdout does not decode: %v", err)
	}
	if decoder.More() {
		t.Error("stdout carries more than one JSON value")
	}

	// The narration is not gone, it moved. A human watching a --json run
	// should still see what was collected.
	if !strings.Contains(stderr, "collected for analysis") {
		t.Errorf("progress should still reach stderr, got: %s", stderr)
	}
}

func TestAnalyzeJSONCarriesTheWholeAnalysis(t *testing.T) {
	_, tree, run := analyzeHarness(t)

	stdout, stderr, err := run("--file", tree, "--json")
	if err != nil {
		t.Fatalf("analyze --json failed: %v\n%s", err, stderr)
	}

	var report analysisReport
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatalf("stdout is not an analysis report: %v", err)
	}

	if report.YayFriendVersion != version.Version {
		t.Errorf("yay_friend_version = %q, want %q", report.YayFriendVersion, version.Version)
	}
	if report.Source != sourceLocal {
		t.Errorf("source = %q, want %q", report.Source, sourceLocal)
	}
	if report.Cached {
		t.Error("a local analysis is not cached")
	}
	if report.Package.Name != "hello" || report.Package.Version != "2.12.1" {
		t.Errorf("package = %+v, want hello 2.12.1", report.Package)
	}
	if got := report.Package.Files; len(got) != 2 || got[0] != "hello.install" || got[1] != "hello.sh" {
		t.Errorf("files = %v, want the companion files that were read, sorted", got)
	}

	want := entropyReport{Value: int(types.EntropyLow), Name: "LOW", Min: 0, Max: 4}
	if report.Entropy != want {
		t.Errorf("entropy = %+v, want %+v", report.Entropy, want)
	}

	// The fields that make this shape richer than a grading, and the reason a
	// caller might prefer it to `yay-friend grade`.
	if report.Analysis.EducationalSummary == "" {
		t.Error("the educational summary was dropped")
	}
	if len(report.Analysis.SecurityLessons) == 0 {
		t.Error("the security lessons were dropped")
	}
	if report.Analysis.PredictabilityScore == 0 {
		t.Error("the predictability score was dropped")
	}
	if report.Analysis.Findings[0].Suggestion == "" || report.Analysis.Findings[0].EntropyNotes == "" {
		t.Error("per-finding suggestion and notes were dropped")
	}
}

// The teaching contrast: this is yay-friend's own shape, not pacrat's. A host
// that wants a grading runs `yay-friend grade`; a host that wants everything
// runs this and shapes it itself.
func TestAnalyzeJSONIsNotAGradingContract(t *testing.T) {
	_, tree, run := analyzeHarness(t)

	stdout, _, err := run("--file", tree, "--json")
	if err != nil {
		t.Fatalf("analyze --json failed: %v", err)
	}

	var raw map[string]any
	if err := json.Unmarshal([]byte(stdout), &raw); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"contract", "grader", "subject", "grade", "scale"} {
		if _, ok := raw[key]; ok {
			t.Errorf("--json output declares %q; it must not pass for a grading", key)
		}
	}
}

func TestAnalyzeWithoutJSONRendersToStdout(t *testing.T) {
	_, tree, run := analyzeHarness(t)

	stdout, _, err := run("--file", tree)
	if err != nil {
		t.Fatalf("analyze failed: %v", err)
	}
	if strings.HasPrefix(strings.TrimSpace(stdout), "{") {
		t.Error("without --json the analysis should be rendered, not marshalled")
	}
	if !strings.Contains(stdout, "no findings") && !strings.Contains(stdout, "source_analysis") {
		t.Errorf("the rendered report is missing its findings:\n%s", stdout)
	}
}

func TestAnalyzeJSONFailureWritesNothingToStdout(t *testing.T) {
	fake, tree, run := analyzeHarness(t)
	fake.err = errFakeProvider

	stdout, _, err := run("--file", tree, "--json")
	if err == nil {
		t.Fatal("a failing provider must not produce a report")
	}
	if stdout != "" {
		t.Errorf("stdout carried %q", stdout)
	}
}
