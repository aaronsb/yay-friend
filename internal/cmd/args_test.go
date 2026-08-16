package cmd

import (
	"reflect"
	"slices"
	"testing"

	"github.com/spf13/pflag"
)

// resetOpts clears every yay-friend option between cases, since they are
// package-level globals shared with the running command.
func resetOpts(t *testing.T) {
	t.Helper()
	saveB := map[string]bool{}
	for _, o := range boolOpts() {
		saveB[o.name] = *o.target
		*o.target = false
	}
	saveS := map[string]string{}
	for _, o := range stringOpts() {
		saveS[o.name] = *o.target
		*o.target = ""
	}
	t.Cleanup(func() {
		for _, o := range boolOpts() {
			*o.target = saveB[o.name]
		}
		for _, o := range stringOpts() {
			*o.target = saveS[o.name]
		}
	})
}

// TestEveryCobraFlagIsUnderstoodByTheYayStyleParser is the guard for the defect
// that produced this file. --noconfirm was registered with cobra and unknown to
// the yay-style parser, so on the path main.go actually uses it was not a flag
// at all -- it fell through to ParseYayCommand and became a package name. Any
// option added to one entry point and not the other fails here.
// It walks the real rootCmd rather than a probe command, so a flag registered
// directly on it -- bypassing the shared table -- is caught too. Persistent
// flags only: rootCmd.Flags() carries the yay-compatible -S/-R/-Q set, which is
// declared for help text and is meant to reach yay untouched.
func TestEveryCobraFlagIsUnderstoodByTheYayStyleParser(t *testing.T) {
	resetOpts(t)

	rootCmd.PersistentFlags().VisitAll(func(f *pflag.Flag) {
		arg := "--" + f.Name
		value := []string{arg}
		if f.Value.Type() != "bool" {
			value = append(value, "some-value")
		}

		if rest := consumeOwnFlags(value); len(rest) != 0 {
			t.Errorf("%s is registered with cobra but the yay-style parser passed it through as %v"+
				" -- on the yay-style path it would be read as a package name", arg, rest)
		}
	})
}

func TestConsumeOwnFlagsForwardsYayFlagsAndPackages(t *testing.T) {
	resetOpts(t)

	// The yay flags here are real ones yay-friend has never heard of. Guessing at
	// any of them, or dropping them, breaks the passthrough contract.
	args := []string{"-S", "--needed", "pkg1", "--answerdiff", "None", "pkg2"}
	want := []string{"-S", "--needed", "pkg1", "--answerdiff", "None", "pkg2"}

	if got := consumeOwnFlags(args); !reflect.DeepEqual(got, want) {
		t.Errorf("consumeOwnFlags() = %v, want %v unchanged", got, want)
	}
}

// TestConsumeOwnFlagsSplitsMixedCommandLine covers ours and yay's interleaved,
// which is how anyone actually types it.
func TestConsumeOwnFlagsSplitsMixedCommandLine(t *testing.T) {
	resetOpts(t)

	rest := consumeOwnFlags([]string{
		"-S", "--noconfirm", "pkg", "--needed", "--provider", "qwen", "-v",
	})

	if !noConfirm {
		t.Error("--noconfirm was not consumed")
	}
	if !verbose {
		t.Error("-v was not consumed")
	}
	if provider != "qwen" {
		t.Errorf("provider = %q, want %q", provider, "qwen")
	}
	if want := []string{"-S", "pkg", "--needed"}; !reflect.DeepEqual(rest, want) {
		t.Errorf("rest = %v, want %v", rest, want)
	}
}

// TestProviderValueIsNotLeftBehind guards the failure mode where an option's
// value survives as a stray argument and is then read as a package name.
func TestProviderValueIsNotLeftBehind(t *testing.T) {
	resetOpts(t)

	for _, form := range [][]string{
		{"--provider", "qwen", "pkg"},
		{"--provider=qwen", "pkg"},
	} {
		provider = ""
		rest := consumeOwnFlags(form)
		if provider != "qwen" {
			t.Errorf("%v: provider = %q, want %q", form, provider, "qwen")
		}
		if want := []string{"pkg"}; !reflect.DeepEqual(rest, want) {
			t.Errorf("%v: rest = %v, want %v", form, rest, want)
		}
	}
}

// TestCombinedPacmanFlagIsForwardedWhole covers the token pflag cannot handle:
// -Syu is one operation to pacman and three shorthand flags to pflag, which also
// swallows the package name after it.
func TestCombinedPacmanFlagIsForwardedWhole(t *testing.T) {
	resetOpts(t)

	rest := consumeOwnFlags([]string{"-Syu", "pkg1"})
	if want := []string{"-Syu", "pkg1"}; !reflect.DeepEqual(rest, want) {
		t.Errorf("rest = %v, want %v", rest, want)
	}
}

// TestShorthandDoesNotSwallowLookalikes keeps -v from matching anything that
// merely starts with it.
func TestShorthandDoesNotSwallowLookalikes(t *testing.T) {
	resetOpts(t)

	rest := consumeOwnFlags([]string{"-vv", "--verbosity"})
	if verbose {
		t.Error("-vv or --verbosity was treated as -v")
	}
	if !slices.Contains(rest, "-vv") || !slices.Contains(rest, "--verbosity") {
		t.Errorf("rest = %v, want both forwarded to yay", rest)
	}
}
