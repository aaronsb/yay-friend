package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/aaronsb/yay-friend/internal/cache"
	"github.com/aaronsb/yay-friend/internal/grade"
	"github.com/aaronsb/yay-friend/internal/types"
	"github.com/aaronsb/yay-friend/internal/ui"
)

const (
	testCommit  = "51cec6333515471681ec8aa00943145d420311fa"
	otherCommit = "a7c5e8780f8ab4249a1f5d90e9a910ff01c9f99f"
)

// fakeProvider stands in for an AI provider and counts how often it was asked
// to analyze anything. Nothing in this file may reach a real model: a test that
// costs money is a test nobody runs.
type fakeProvider struct {
	calls    int
	seen     types.PackageInfo
	analysis *types.SecurityAnalysis
	err      error
}

func (f *fakeProvider) Name() string          { return "fake" }
func (f *fakeProvider) IsAuthenticated() bool { return true }

func (f *fakeProvider) Authenticate(ctx context.Context) error { return nil }

func (f *fakeProvider) AnalyzePKGBUILD(ctx context.Context, pkgInfo types.PackageInfo) (*types.SecurityAnalysis, error) {
	f.calls++
	f.seen = pkgInfo
	if f.err != nil {
		return nil, f.err
	}
	return f.analysis, nil
}

func (f *fakeProvider) GetCapabilities() types.ProviderCapabilities {
	return types.ProviderCapabilities{SupportsCodeAnalysis: true}
}

func cleanAnalysis() *types.SecurityAnalysis {
	return &types.SecurityAnalysis{
		PackageName:    "hello",
		OverallEntropy: types.EntropyLow,
		OverallLevel:   types.EntropyLow,
		Findings: []types.SecurityFinding{{
			Type:        "source_analysis",
			Entropy:     types.EntropyMinimal,
			Description: "every source is checksum-pinned",
			LineNumber:  7,
		}},
		Summary:        "Clean package.",
		Recommendation: "PROCEED",
		Provider:       "fake",
	}
}

const testPKGBUILD = `# Maintainer: someone <someone@example.invalid>
pkgname=hello
pkgver=2.12.1
pkgrel=1
pkgdesc='Prints a greeting'
arch=('any')
install=hello.install
source=('hello.sh')
sha256sums=('SKIP')

package() {
  install -Dm755 "$srcdir/hello.sh" "$pkgdir/usr/bin/hello"
}
`

// writeTree stages the kind of directory pacrat hands a grader: a PKGBUILD, the
// .SRCINFO the version is read from, and the companion files the PKGBUILD
// references.
func writeTree(t *testing.T, dir string) string {
	t.Helper()
	tree := filepath.Join(dir, "tree")
	if err := os.MkdirAll(tree, 0755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"PKGBUILD": testPKGBUILD,
		// arch is required for this to parse as a .SRCINFO at all; without it the
		// version silently comes from the PKGBUILD fallback instead, and this
		// fixture stops exercising the path it is here for.
		".SRCINFO":      "pkgbase = hello\n\tpkgver = 2.12.1\n\tpkgrel = 1\n\tarch = x86_64\n\npkgname = hello\n",
		"hello.install": "post_install() {\n  echo hello\n}\n",
		"hello.sh":      "#!/bin/sh\necho hello\n",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(tree, name), []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}
	return tree
}

// runGradeCmd runs `yay-friend grade` with the two streams captured apart:
// stdout must be the grading and nothing else, so a diagnostic leaking into it
// has to be something a test can see.
type gradeRunner func(args ...string) (stdout, stderr string, err error)

func gradeHarness(t *testing.T) (*fakeProvider, string, gradeRunner) {
	t.Helper()

	// Every XDG root moves into the test's own directory: the real cache and
	// the real config are never read and never written.
	home := t.TempDir()
	t.Setenv("XDG_DATA_HOME", filepath.Join(home, "data"))
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "config"))
	// Both spellings, or one left set in the ambient environment decides a test.
	for _, name := range []string{"PACKAGE", "TREE", "COMMIT"} {
		t.Setenv("YAY_FRIEND_"+name, "")
		t.Setenv("PACRAT_"+name, "")
	}

	fake := &fakeProvider{analysis: cleanAnalysis()}
	restore := resolveProvider
	resolveProvider = func(ctx context.Context, cfg *types.Config) (types.AIProvider, error) {
		return fake, nil
	}
	out := ui.Out
	t.Cleanup(func() {
		resolveProvider = restore
		ui.Out = out
	})

	run := func(args ...string) (string, string, error) {
		cmd := newGradeCmd()
		var stdout, stderr bytes.Buffer
		cmd.SetOut(&stdout)
		cmd.SetErr(&stderr)
		// Non-nil even when empty: cobra falls back to os.Args for a nil arg
		// slice, and os.Args under `go test` is full of -test.* flags.
		cmd.SetArgs(append([]string{}, args...))
		err := cmd.Execute()
		return stdout.String(), stderr.String(), err
	}

	return fake, writeTree(t, home), run
}

func decodeGrading(t *testing.T, stdout string) grade.Report {
	t.Helper()
	var report grade.Report
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatalf("stdout is not a grading: %v\n%s", err, stdout)
	}
	if report.Contract != grade.Contract {
		t.Errorf("contract = %q, want %q", report.Contract, grade.Contract)
	}
	return report
}

func TestGradeTakesItsSubjectFromTheEnvironment(t *testing.T) {
	_, tree, run := gradeHarness(t)
	t.Setenv("YAY_FRIEND_PACKAGE", "hello")
	t.Setenv("YAY_FRIEND_TREE", tree)
	t.Setenv("YAY_FRIEND_COMMIT", testCommit)

	stdout, stderr, err := run()
	if err != nil {
		t.Fatalf("grade failed: %v\n%s", err, stderr)
	}

	report := decodeGrading(t, stdout)
	want := grade.Subject{Package: "hello", Commit: testCommit, Version: "2.12.1-1"}
	if report.Subject != want {
		t.Errorf("subject = %+v, want %+v", report.Subject, want)
	}
}

func TestGradeFlagsBeatTheEnvironment(t *testing.T) {
	_, tree, run := gradeHarness(t)
	t.Setenv("YAY_FRIEND_PACKAGE", "from-env")
	t.Setenv("YAY_FRIEND_TREE", "/nonexistent")
	t.Setenv("YAY_FRIEND_COMMIT", otherCommit)

	stdout, stderr, err := run("--package", "hello", "--tree", tree, "--commit", testCommit)
	if err != nil {
		t.Fatalf("grade failed: %v\n%s", err, stderr)
	}

	report := decodeGrading(t, stdout)
	if report.Subject.Package != "hello" || report.Subject.Commit != testCommit {
		t.Errorf("subject = %+v, want the flags to win", report.Subject)
	}
}

// One half from the environment, the other from a flag: the two sources are
// merged per field, not chosen between.
func TestGradeMixesFlagsAndEnvironmentPerField(t *testing.T) {
	_, tree, run := gradeHarness(t)
	t.Setenv("YAY_FRIEND_PACKAGE", "hello")
	t.Setenv("YAY_FRIEND_TREE", tree)

	stdout, stderr, err := run("--commit", testCommit)
	if err != nil {
		t.Fatalf("grade failed: %v\n%s", err, stderr)
	}
	report := decodeGrading(t, stdout)
	if report.Subject.Package != "hello" || report.Subject.Commit != testCommit {
		t.Errorf("subject = %+v, want hello@%s", report.Subject, testCommit)
	}
}

func TestGradeWithoutASubjectIsAUsageError(t *testing.T) {
	_, tree, run := gradeHarness(t)

	cases := []struct {
		name string
		args []string
		want string
	}{
		{"nothing at all", nil, "YAY_FRIEND_PACKAGE"},
		{"no tree", []string{"--package", "hello", "--commit", testCommit}, "YAY_FRIEND_TREE"},
		{"no commit", []string{"--package", "hello", "--tree", tree}, "YAY_FRIEND_COMMIT"},
		{"not a package name", []string{"--package", "../etc", "--tree", tree, "--commit", testCommit}, "not a package name"},
		{"not hex", []string{"--package", "hello", "--tree", tree, "--commit", "nothex"}, "not a commit hash"},
		{"too short", []string{"--package", "hello", "--tree", tree, "--commit", "abc123"}, "too short"},
		{"too long", []string{"--package", "hello", "--tree", tree, "--commit", strings.Repeat("0", 65)}, "longer than"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stdout, stderr, err := run(tc.args...)
			if err == nil {
				t.Fatalf("expected a refusal, got: %s", stdout)
			}
			if stdout != "" {
				t.Errorf("a refusal must write nothing to stdout, got: %s", stdout)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
			if !strings.Contains(stderr, "Usage:") {
				t.Errorf("a usage error should print usage, got: %s", stderr)
			}
		})
	}
}

// The cache hit is the path pacrat's update loop actually takes, and it must
// not need a provider at all: a hit is a file read, and demanding a reachable
// model for it would fail a question that was already answered.
func TestGradeCacheHitDoesNotCallTheProvider(t *testing.T) {
	fake, tree, run := gradeHarness(t)

	cacheManager, err := cache.NewCacheManager()
	if err != nil {
		t.Fatal(err)
	}
	seeded := cleanAnalysis()
	seeded.OverallEntropy = types.EntropyHigh
	if err := cacheManager.SaveAnalysis("hello", testCommit, seeded); err != nil {
		t.Fatal(err)
	}

	stdout, stderr, err := run("--package", "hello", "--tree", tree, "--commit", testCommit)
	if err != nil {
		t.Fatalf("grade failed: %v\n%s", err, stderr)
	}

	if fake.calls != 0 {
		t.Errorf("provider was called %d times on a cache hit", fake.calls)
	}
	report := decodeGrading(t, stdout)
	if report.Grade != int(types.EntropyHigh) {
		t.Errorf("grade = %d, want the cached %d", report.Grade, types.EntropyHigh)
	}
	if !report.Meta.Cached {
		t.Error("meta.cached should be true for a replayed grading")
	}
}

func TestGradeCacheMissAnalysesOnceAndReplaysAfter(t *testing.T) {
	fake, tree, run := gradeHarness(t)
	args := []string{"--package", "hello", "--tree", tree, "--commit", testCommit}

	stdout, stderr, err := run(args...)
	if err != nil {
		t.Fatalf("grade failed: %v\n%s", err, stderr)
	}
	if fake.calls != 1 {
		t.Fatalf("provider was called %d times, want 1", fake.calls)
	}
	if report := decodeGrading(t, stdout); report.Meta.Cached {
		t.Error("meta.cached should be false for a freshly analyzed grading")
	}

	// Filed under the commit, in lowercase, where the next ask will find it.
	entry := filepath.Join(os.Getenv("XDG_DATA_HOME"), "yay-friend", "cache", "hello", testCommit+".json")
	if _, err := os.Stat(entry); err != nil {
		t.Errorf("the analysis was not cached at %s: %v", entry, err)
	}

	stdout, stderr, err = run(args...)
	if err != nil {
		t.Fatalf("second grade failed: %v\n%s", err, stderr)
	}
	if fake.calls != 1 {
		t.Errorf("provider was called %d times over two runs, want 1", fake.calls)
	}
	if report := decodeGrading(t, stdout); !report.Meta.Cached {
		t.Error("the second run should replay the cached grading")
	}
}

// Hex case is not meaningful, and pacrat compares commits case-insensitively.
// An uppercase request must find the entry sitting right there rather than
// spending a model call discovering it.
func TestGradeUppercaseCommitStillHitsTheCache(t *testing.T) {
	fake, tree, run := gradeHarness(t)

	cacheManager, err := cache.NewCacheManager()
	if err != nil {
		t.Fatal(err)
	}
	if err := cacheManager.SaveAnalysis("hello", testCommit, cleanAnalysis()); err != nil {
		t.Fatal(err)
	}

	upper := strings.ToUpper(testCommit)
	stdout, stderr, err := run("--package", "hello", "--tree", tree, "--commit", upper)
	if err != nil {
		t.Fatalf("grade failed: %v\n%s", err, stderr)
	}
	if fake.calls != 0 {
		t.Errorf("an uppercase request ran an analysis instead of hitting the cache")
	}
	if report := decodeGrading(t, stdout); report.Subject.Commit != upper {
		t.Errorf("subject.commit = %q, want the commit as it was asked for", report.Subject.Commit)
	}
}

// The tree is the bytes under judgement: the PKGBUILD pacrat staged, plus the
// companion files it references — not a fresh fetch of whatever the AUR is
// serving now.
func TestGradeReadsTheTreeItWasHanded(t *testing.T) {
	fake, tree, run := gradeHarness(t)

	if _, stderr, err := run("--package", "hello", "--tree", tree, "--commit", testCommit); err != nil {
		t.Fatalf("grade failed: %v\n%s", err, stderr)
	}

	if fake.seen.PKGBUILD != testPKGBUILD {
		t.Error("the analyzer did not receive the staged PKGBUILD")
	}
	if !strings.Contains(fake.seen.InstallScript, "post_install") {
		t.Errorf("the .install hook was not collected: %q", fake.seen.InstallScript)
	}
	if _, ok := fake.seen.AdditionalFiles["hello.sh"]; !ok {
		t.Errorf("a local source= file was not collected: %v", fake.seen.AdditionalFiles)
	}
	if fake.seen.CommitHash != testCommit {
		t.Errorf("commit = %q, want the one we were asked about", fake.seen.CommitHash)
	}
}

// The subject's package name wins over the tree's. A PKGBUILD is untrusted
// input, and letting it name itself would be letting it pick which cache entry
// the grading lands in.
func TestGradeNamesTheSubjectPacratAskedAbout(t *testing.T) {
	fake, tree, run := gradeHarness(t)
	if err := os.WriteFile(filepath.Join(tree, "PKGBUILD"),
		[]byte("pkgname=somethingelse\npkgver=1\npkgrel=1\n"), 0644); err != nil {
		t.Fatal(err)
	}

	stdout, stderr, err := run("--package", "hello", "--tree", tree, "--commit", testCommit)
	if err != nil {
		t.Fatalf("grade failed: %v\n%s", err, stderr)
	}
	if fake.seen.Name != "hello" {
		t.Errorf("the analyzer was told the package is %q", fake.seen.Name)
	}
	if report := decodeGrading(t, stdout); report.Subject.Package != "hello" {
		t.Errorf("subject.package = %q, want hello", report.Subject.Package)
	}
}

// Any failure is a nonzero exit with the reason on stderr and no JSON at all.
// pacrat reads a failed grader as UNGRADED, which holds; a half-report is worse
// than none.
func TestGradeFailuresWriteNothingToStdout(t *testing.T) {
	t.Run("provider error", func(t *testing.T) {
		fake, tree, run := gradeHarness(t)
		fake.err = errFakeProvider

		stdout, _, err := run("--package", "hello", "--tree", tree, "--commit", testCommit)
		if err == nil {
			t.Fatal("a failing provider must not produce a grading")
		}
		if stdout != "" {
			t.Errorf("stdout carried %q", stdout)
		}
	})

	t.Run("no provider configured", func(t *testing.T) {
		_, tree, run := gradeHarness(t)
		resolveProvider = func(ctx context.Context, cfg *types.Config) (types.AIProvider, error) {
			return nil, errFakeProvider
		}

		stdout, _, err := run("--package", "hello", "--tree", tree, "--commit", testCommit)
		if err == nil {
			t.Fatal("an unavailable provider must not produce a grading")
		}
		if stdout != "" {
			t.Errorf("stdout carried %q", stdout)
		}
	})

	t.Run("unreadable tree", func(t *testing.T) {
		_, _, run := gradeHarness(t)

		stdout, _, err := run("--package", "hello", "--tree", "/nonexistent/tree", "--commit", testCommit)
		if err == nil {
			t.Fatal("an unreadable tree must not produce a grading")
		}
		if stdout != "" {
			t.Errorf("stdout carried %q", stdout)
		}
	})

	t.Run("tree with no PKGBUILD", func(t *testing.T) {
		_, _, run := gradeHarness(t)
		empty := t.TempDir()

		stdout, _, err := run("--package", "hello", "--tree", empty, "--commit", testCommit)
		if err == nil {
			t.Fatal("a tree with no PKGBUILD must not produce a grading")
		}
		if stdout != "" {
			t.Errorf("stdout carried %q", stdout)
		}
	})

	t.Run("an entropy off the scale", func(t *testing.T) {
		fake, tree, run := gradeHarness(t)
		fake.analysis.OverallEntropy = 70

		stdout, _, err := run("--package", "hello", "--tree", tree, "--commit", testCommit)
		if err == nil {
			t.Fatal("an unplaceable entropy must be refused, not clamped")
		}
		if stdout != "" {
			t.Errorf("stdout carried %q", stdout)
		}
	})
}

// A host's setup probe reads the help to decide whether the installed binary
// speaks the contract natively -- pacrat's interview greps for exactly this
// string. Renaming the feature to "structured output" removed it from the help
// once already; the contract name has to stay printed even though the prose
// around it no longer leads with pacrat.
func TestGradeHelpExitsZero(t *testing.T) {
	_, _, run := gradeHarness(t)

	stdout, stderr, err := run("--help")
	if err != nil {
		t.Fatalf("grade --help must exit 0, got %v", err)
	}
	if !strings.Contains(stdout+stderr, "pacrat-grade/v1") {
		t.Error("the help should name the contract it speaks")
	}
}

func TestGradeIsRegisteredOnTheRootCommand(t *testing.T) {
	var found *cobra.Command
	for _, c := range rootCmd.Commands() {
		if c.Name() == "grade" {
			found = c
		}
	}
	if found == nil {
		t.Fatal("grade is not a subcommand of yay-friend")
	}
}

func TestGradeStdoutIsOneJSONObjectAndNothingElse(t *testing.T) {
	_, tree, run := gradeHarness(t)

	stdout, _, err := run("--package", "hello", "--tree", tree, "--commit", testCommit)
	if err != nil {
		t.Fatalf("grade failed: %v", err)
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
}

var errFakeProvider = errorString("provider unavailable")

type errorString string

func (e errorString) Error() string { return string(e) }

// A FIFO named PKGBUILD used to hang grade in open() forever — past SIGTERM,
// since main's signal context replaces die-on-signal with a cancel no file
// read observes. readRegular refuses anything irregular before opening it.
func TestAFIFONamedPKGBUILDIsRefusedNotHung(t *testing.T) {
	_, tree, run := gradeHarness(t)
	if err := os.Remove(filepath.Join(tree, "PKGBUILD")); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(tree, "PKGBUILD"), 0644); err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})
	var stdout string
	var err error
	go func() {
		stdout, _, err = run("--package", "hello", "--tree", tree, "--commit", testCommit)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("grade hung on a FIFO PKGBUILD")
	}
	if err == nil {
		t.Fatal("a FIFO PKGBUILD graded successfully")
	}
	if stdout != "" {
		t.Errorf("a failure wrote to stdout: %q", stdout)
	}
}

// TestSubjectFromEitherEnvironmentSpelling pins the compatibility promise made
// when the feature was renamed to structured output. YAY_FRIEND_* is the name a
// host should set; PACRAT_* is still read because pacrat shipped against it and
// exports it for every grader run. An install that works today has to keep
// working, so both are exercised rather than described.
func TestSubjectFromEitherEnvironmentSpelling(t *testing.T) {
	for _, prefix := range []string{"YAY_FRIEND", "PACRAT"} {
		t.Run(prefix, func(t *testing.T) {
			_, tree, run := gradeHarness(t)
			t.Setenv(prefix+"_PACKAGE", "hello")
			t.Setenv(prefix+"_TREE", tree)
			t.Setenv(prefix+"_COMMIT", testCommit)

			stdout, stderr, err := run()
			if err != nil {
				t.Fatalf("grade failed: %v\n%s", err, stderr)
			}
			report := decodeGrading(t, stdout)
			want := grade.Subject{Package: "hello", Commit: testCommit, Version: "2.12.1-1"}
			if report.Subject != want {
				t.Errorf("subject = %+v, want %+v", report.Subject, want)
			}
		})
	}
}

// TestCanonicalEnvironmentNameWins covers a host that sets both, which is what a
// migrating one does mid-flight.
func TestCanonicalEnvironmentNameWins(t *testing.T) {
	_, tree, run := gradeHarness(t)
	t.Setenv("YAY_FRIEND_PACKAGE", "hello")
	t.Setenv("YAY_FRIEND_TREE", tree)
	t.Setenv("YAY_FRIEND_COMMIT", testCommit)
	t.Setenv("PACRAT_PACKAGE", "stale")
	t.Setenv("PACRAT_TREE", "/nonexistent")
	t.Setenv("PACRAT_COMMIT", otherCommit)

	stdout, stderr, err := run()
	if err != nil {
		t.Fatalf("grade failed: %v\n%s", err, stderr)
	}
	report := decodeGrading(t, stdout)
	if report.Subject.Package != "hello" || report.Subject.Commit != testCommit {
		t.Errorf("subject = %+v, want the YAY_FRIEND_* values to win", report.Subject)
	}
}

// TestContractIsUnchangedByTheRename is the whole point of keeping the wire
// value: the report a reader parses must be byte-identical to what it parsed
// before the feature was renamed.
func TestContractIsUnchangedByTheRename(t *testing.T) {
	if grade.Contract != "pacrat-grade/v1" {
		t.Errorf("contract = %q, want %q: renaming it breaks every existing reader",
			grade.Contract, "pacrat-grade/v1")
	}
}
