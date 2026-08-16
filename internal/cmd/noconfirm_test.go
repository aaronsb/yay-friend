package cmd

import (
	"io"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/aaronsb/yay-friend/internal/types"
	"github.com/aaronsb/yay-friend/internal/ui"
	"github.com/aaronsb/yay-friend/internal/yay"
)

// thresholds builds a config that blocks at block and warns at warn.
func thresholds(block, warn types.SecurityLevel) *types.Config {
	cfg := &types.Config{}
	cfg.SecurityThresholds.BlockLevel = block
	cfg.SecurityThresholds.WarnLevel = warn
	return cfg
}

func analysisAt(level types.SecurityLevel) *types.SecurityAnalysis {
	return &types.SecurityAnalysis{
		PackageName:  "some-package",
		OverallLevel: level,
		Summary:      "test",
	}
}

// withNoConfirm sets the package-level flag for one test and restores it.
func withNoConfirm(t *testing.T, v bool) {
	t.Helper()
	prev := noConfirm
	noConfirm = v
	t.Cleanup(func() { noConfirm = prev })
}

// quietUI sends rendered output nowhere, so a test reads as its assertions.
func quietUI(t *testing.T) {
	t.Helper()
	prevOut, prevErr := ui.Out, ui.Err
	ui.Out, ui.Err = io.Discard, io.Discard
	t.Cleanup(func() { ui.Out, ui.Err = prevOut, prevErr })
}

// closedStdin stands in for a pipe with nothing on it. A prompt that reaches
// this gets EOF rather than hanging the test, and the empty answer it reads is
// treated as "no" -- so a test asserting that --noconfirm proceeds is really
// asserting no prompt happened at all.
func closedStdin(t *testing.T) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	w.Close()
	prev := os.Stdin
	os.Stdin = r
	t.Cleanup(func() {
		os.Stdin = prev
		r.Close()
	})
}

// TestNoConfirmNeverBypassesTheBlockThreshold is the property that matters most
// here. A convenience flag that can talk its way past the block level would make
// the analysis decorative, so the block check must be unreachable from it.
func TestNoConfirmNeverBypassesTheBlockThreshold(t *testing.T) {
	quietUI(t)
	closedStdin(t)
	withNoConfirm(t, true)

	cfg := thresholds(types.SecurityHigh, types.SecurityMedium)

	for _, level := range []types.SecurityLevel{types.SecurityHigh, types.SecurityCritical} {
		err := handleAnalysisResult(analysisAt(level), cfg)
		if err == nil {
			t.Errorf("%s: --noconfirm walked past the block threshold", level)
			continue
		}
		if !strings.Contains(err.Error(), "blocked by security policy") {
			t.Errorf("%s: error = %v, want a block-policy refusal", level, err)
		}
	}
}

// TestNoConfirmProceedsPastAWarning is the flag's actual job. Reaching the
// prompt would read the closed stdin, get "", and cancel -- so a nil error here
// means no prompt was reached.
func TestNoConfirmProceedsPastAWarning(t *testing.T) {
	quietUI(t)
	closedStdin(t)
	withNoConfirm(t, true)

	cfg := thresholds(types.SecurityHigh, types.SecurityMedium)

	if err := handleAnalysisResult(analysisAt(types.SecurityMedium), cfg); err != nil {
		t.Errorf("--noconfirm did not clear a warning: %v", err)
	}
}

// TestWithoutNoConfirmAWarningStillAsks guards the default. The same call that
// passes above must stop when the flag is absent.
func TestWithoutNoConfirmAWarningStillAsks(t *testing.T) {
	quietUI(t)
	closedStdin(t)
	withNoConfirm(t, false)

	cfg := thresholds(types.SecurityHigh, types.SecurityMedium)

	err := handleAnalysisResult(analysisAt(types.SecurityMedium), cfg)
	if err == nil {
		t.Fatal("a warning-level package installed without being confirmed")
	}
	if !strings.Contains(err.Error(), "cancelled by user") {
		t.Errorf("error = %v, want a cancellation", err)
	}
}

// TestCleanPackageNeedsNoConfirmation covers the common path: below the warn
// threshold, nothing is asked either way.
func TestCleanPackageNeedsNoConfirmation(t *testing.T) {
	quietUI(t)
	closedStdin(t)
	withNoConfirm(t, false)

	cfg := thresholds(types.SecurityHigh, types.SecurityMedium)

	if err := handleAnalysisResult(analysisAt(types.SecuritySafe), cfg); err != nil {
		t.Errorf("a clean package was not approved: %v", err)
	}
}

// TestNoConfirmReachesYay guards the pass-through. Before --noconfirm was
// declared here, cobra never saw it and yay did; declaring it consumed it, so it
// has to be handed back or suppressing yay-friend's prompts would start yay's.
func TestNoConfirmReachesYay(t *testing.T) {
	operation, err := yay.ParseYayCommand([]string{"-S", "--needed", "some-package"})
	if err != nil {
		t.Fatal(err)
	}

	got := withNoConfirmFlag(operation.Flags, true)
	if !slices.Contains(got, "--noconfirm") {
		t.Errorf("flags = %v, want --noconfirm forwarded to yay", got)
	}
	if !slices.Contains(got, "--needed") {
		t.Errorf("flags = %v, want the user's own flags kept", got)
	}
}

// TestNoConfirmIsNotDuplicated covers the flag arriving from both directions.
func TestNoConfirmIsNotDuplicated(t *testing.T) {
	got := withNoConfirmFlag([]string{"--noconfirm"}, true)
	if len(got) != 1 {
		t.Errorf("flags = %v, want --noconfirm passed once", got)
	}
}

// TestWithoutNoConfirmYayIsUntouched keeps the flag from leaking into ordinary
// runs, where yay's own prompts are the user's to answer.
func TestWithoutNoConfirmYayIsUntouched(t *testing.T) {
	got := withNoConfirmFlag([]string{"--needed"}, false)
	if slices.Contains(got, "--noconfirm") {
		t.Errorf("flags = %v, want no --noconfirm added", got)
	}
}
