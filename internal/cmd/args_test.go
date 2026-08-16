package cmd

import (
	"reflect"
	"slices"
	"strings"
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

// TestEveryCobraFlagIsAccountedForByTheYayStyleParser is the guard for the
// defect that produced this file. --noconfirm was registered with cobra and
// unknown to the yay-style parser, so on the path main.go actually uses it was
// not a flag at all -- it fell through to ParseYayCommand and became a package
// name.
//
// Every persistent flag must be deliberately one thing or the other: consumed
// by the yay-style parser, or listed in cobraOnlyStringOpts and forwarded to
// yay. Both directions are asserted, so an option cannot go missing from the
// tables and cannot be quietly stolen from pacman either -- which is what
// happened to --config, an option pacman has too.
//
// It walks the real rootCmd rather than a probe command, so a flag registered
// directly on it -- bypassing the shared tables -- is caught. Persistent flags
// only: rootCmd.Flags() carries the yay-compatible -S/-R/-Q set, declared for
// help text and meant to reach yay untouched.
func TestEveryCobraFlagIsAccountedForByTheYayStyleParser(t *testing.T) {
	resetOpts(t)

	forwarded := map[string]bool{}
	for _, o := range cobraOnlyStringOpts() {
		forwarded[o.name] = true
	}

	rootCmd.PersistentFlags().VisitAll(func(f *pflag.Flag) {
		arg := "--" + f.Name
		value := []string{arg}
		if f.Value.Type() != "bool" {
			value = append(value, "some-value")
		}

		rest, err := consumeOwnFlags(value)
		if err != nil {
			t.Errorf("%s: %v", arg, err)
			return
		}

		if forwarded[f.Name] {
			if !reflect.DeepEqual(rest, value) {
				t.Errorf("%s is declared cobra-only, so the yay-style parser must forward it"+
					" untouched; got %v, want %v", arg, rest, value)
			}
			return
		}
		if len(rest) != 0 {
			t.Errorf("%s is registered with cobra but the yay-style parser passed it through as %v"+
				" -- on the yay-style path it would be read as a package name."+
				" Add it to the tables in args.go, or to cobraOnlyStringOpts if it belongs to pacman", arg, rest)
		}
	})
}

// TestConfigIsLeftToPacmanOnAYayStyleCommandLine pins the reason --config is
// cobra-only. It is a pacman option (`pacman --config <path>`), so consuming it
// here made `yay-friend -S --config /etc/pacman.conf foo` read pacman.conf as
// yay-friend's own YAML and abort.
func TestConfigIsLeftToPacmanOnAYayStyleCommandLine(t *testing.T) {
	resetOpts(t)

	args := []string{"-S", "--config", "/etc/pacman.conf", "foo"}
	rest, err := consumeOwnFlags(args)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(rest, args) {
		t.Errorf("rest = %v, want %v forwarded to yay", rest, args)
	}
	if cfgFile != "" {
		t.Errorf("cfgFile = %q, want empty: pacman's --config is not yay-friend's", cfgFile)
	}
}

// TestMissingOptionValueIsAnError covers the typo that used to pass silently:
// the option vanished, and the run continued against the configured default
// rather than the provider that was asked for.
func TestMissingOptionValueIsAnError(t *testing.T) {
	resetOpts(t)

	if _, err := consumeOwnFlags([]string{"-S", "pkg", "--provider"}); err == nil {
		t.Fatal("a value-less --provider was accepted")
	} else if !strings.Contains(err.Error(), "needs an argument") {
		t.Errorf("error = %v, want it to say the flag needs an argument", err)
	}
}

func TestConsumeOwnFlagsForwardsYayFlagsAndPackages(t *testing.T) {
	resetOpts(t)

	// The yay flags here are real ones yay-friend has never heard of. Guessing at
	// any of them, or dropping them, breaks the passthrough contract.
	args := []string{"-S", "--needed", "pkg1", "--answerdiff", "None", "pkg2"}
	want := []string{"-S", "--needed", "pkg1", "--answerdiff", "None", "pkg2"}

	got, err := consumeOwnFlags(args)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("consumeOwnFlags() = %v, want %v unchanged", got, want)
	}
}

// TestConsumeOwnFlagsSplitsMixedCommandLine covers ours and yay's interleaved,
// which is how anyone actually types it.
func TestConsumeOwnFlagsSplitsMixedCommandLine(t *testing.T) {
	resetOpts(t)

	rest, err := consumeOwnFlags([]string{
		"-S", "--noconfirm", "pkg", "--needed", "--provider", "qwen", "-v",
	})
	if err != nil {
		t.Fatal(err)
	}

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
		rest, err := consumeOwnFlags(form)
		if err != nil {
			t.Fatal(err)
		}
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

	rest, err := consumeOwnFlags([]string{"-Syu", "pkg1"})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"-Syu", "pkg1"}; !reflect.DeepEqual(rest, want) {
		t.Errorf("rest = %v, want %v", rest, want)
	}
}

// TestShorthandDoesNotSwallowLookalikes keeps -v from matching anything that
// merely starts with it.
func TestShorthandDoesNotSwallowLookalikes(t *testing.T) {
	resetOpts(t)

	rest, err := consumeOwnFlags([]string{"-vv", "--verbosity"})
	if err != nil {
		t.Fatal(err)
	}
	if verbose {
		t.Error("-vv or --verbosity was treated as -v")
	}
	if !slices.Contains(rest, "-vv") || !slices.Contains(rest, "--verbosity") {
		t.Errorf("rest = %v, want both forwarded to yay", rest)
	}
}
