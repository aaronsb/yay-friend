package cmd

import (
	"strings"

	"github.com/spf13/cobra"
)

// yay-friend has two entry points. Subcommands (analyze, grade, cache) go
// through cobra; anything else is a yay-style command line that main.go hands
// straight to RunYayStyleCommand, because cobra cannot parse it -- `-Syu` is one
// token to pacman and three shorthand flags to pflag, and pflag drops the
// unknown flags (`--needed`, `--answerdiff None`) that must reach yay verbatim.
//
// So the yay-style path parses its own arguments. What it must not do is decide
// for itself which options exist: an option registered with cobra and missing
// here is not an unknown option, it is a package name, and `yay-friend pkg
// --noconfirm` went looking for a package called "--noconfirm" for exactly that
// reason. Both entry points are therefore driven from the tables below, so an
// option cannot exist for one and not the other.

// boolOpt is a yay-friend option that takes no value.
type boolOpt struct {
	name      string
	shorthand string
	target    *bool
	usage     string
}

// stringOpt is a yay-friend option that takes a value.
type stringOpt struct {
	name   string
	target *string
	usage  string
}

func boolOpts() []boolOpt {
	return []boolOpt{
		{"verbose", "v", &verbose, "verbose output"},
		{"skip-analysis", "", &skipAnalysis, "skip security analysis and proceed directly to yay"},
		{"no-spinner", "", &noSpinner, "disable spinner animations (useful for scripts/automation)"},
		{"no-color", "", &noColor, "disable colored output (NO_COLOR is also honored)"},
		{"noconfirm", "", &noConfirm, "never prompt; proceed past warnings, but still refuse anything the block threshold catches"},
	}
}

func stringOpts() []stringOpt {
	return []stringOpt{
		{"config", &cfgFile, "config file (default is ${XDG_CONFIG_HOME:-$HOME/.config}/yay-friend/config.yaml)"},
		{"provider", &provider, "AI provider to use (claude, qwen, copilot, goose)"},
	}
}

// registerOwnFlags declares yay-friend's options on a cobra command.
func registerOwnFlags(cmd *cobra.Command) {
	flags := cmd.PersistentFlags()
	for _, o := range boolOpts() {
		flags.BoolVarP(o.target, o.name, o.shorthand, false, o.usage)
	}
	for _, o := range stringOpts() {
		flags.StringVar(o.target, o.name, "", o.usage)
	}
}

// consumeOwnFlags sets yay-friend's options from args and returns everything
// else in order: yay's own flags and the package names, untouched.
//
// Anything unrecognised is forwarded rather than interpreted. That is the whole
// contract of a passthrough wrapper -- yay grows flags on its own schedule, and
// guessing at one is worse than handing it over.
func consumeOwnFlags(args []string) []string {
	bools := map[string]*bool{}
	for _, o := range boolOpts() {
		bools["--"+o.name] = o.target
		if o.shorthand != "" {
			bools["-"+o.shorthand] = o.target
		}
	}
	strs := map[string]*string{}
	for _, o := range stringOpts() {
		strs["--"+o.name] = o.target
	}

	rest := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		arg := args[i]

		if target, ok := bools[arg]; ok {
			*target = true
			continue
		}
		if target, ok := strs[arg]; ok {
			// `--provider claude`: the value is the next argument, and must not
			// be left behind to be read as a package name.
			if i+1 < len(args) {
				*target = args[i+1]
				i++
			}
			continue
		}
		if name, value, found := strings.Cut(arg, "="); found {
			if target, ok := strs[name]; ok {
				*target = value
				continue
			}
		}

		rest = append(rest, arg)
	}
	return rest
}
