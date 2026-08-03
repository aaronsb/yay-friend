// Package pkgbuild reads the metadata declarations out of a PKGBUILD.
//
// A PKGBUILD is bash, so it is parsed as bash rather than pattern-matched. The
// regex approach this replaces was unanchored, which meant `_pkgname=` matched a
// request for `pkgname=`, and `makedepends=(` matched a request for `depends=(`.
// Both misfire on real packages: of 36 PKGBUILDs sampled from a live yay cache,
// four declared makedepends before depends and so reported build dependencies
// when asked for runtime dependencies.
//
// Only top-level assignments are read. Assignments inside function bodies
// (pkgver(), build(), package_*()) are deliberately ignored: those run at build
// time against a tree we have not fetched, so any value read from them would be
// a guess. Nothing here executes, expands globs, or resolves command
// substitution -- it reads declarations.
package pkgbuild

import (
	"fmt"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// Vars holds the top-level declarations of a single PKGBUILD.
type Vars struct {
	scalars    map[string]string
	arrays     map[string][]string
	maintainer string
}

// Parse reads the top-level declarations from PKGBUILD source.
//
// Assignments are processed in source order and each is expanded against the
// variables declared before it, so the near-universal
// `_pkgname=foo` / `pkgname=${_pkgname}-bin` idiom resolves.
func Parse(src string) (*Vars, error) {
	v := &Vars{
		scalars: map[string]string{},
		arrays:  map[string][]string{},
	}

	f, err := syntax.NewParser().Parse(strings.NewReader(src), "PKGBUILD")
	if err != nil {
		return nil, fmt.Errorf("parse PKGBUILD: %w", err)
	}

	for _, stmt := range f.Stmts {
		call, ok := stmt.Cmd.(*syntax.CallExpr)
		if !ok || len(call.Args) > 0 {
			continue // a command, not a bare assignment
		}
		for _, a := range call.Assigns {
			if a.Name == nil {
				continue
			}
			switch {
			case a.Array != nil:
				vals := make([]string, 0, len(a.Array.Elems))
				for _, el := range a.Array.Elems {
					if el.Value != nil {
						vals = append(vals, v.word(el.Value))
					}
				}
				v.arrays[a.Name.Value] = vals
			case a.Value != nil:
				v.scalars[a.Name.Value] = v.word(a.Value)
			}
		}
	}

	v.maintainer = findMaintainer(src)
	return v, nil
}

// Str returns a scalar declaration, or "" if absent.
func (v *Vars) Str(name string) string { return v.scalars[name] }

// Slice returns an array declaration, or nil if absent.
func (v *Vars) Slice(name string) []string { return v.arrays[name] }

// Name returns the package name. Split packages declare pkgname as an array
// (`pkgname=('conan')`), in which case the first entry is the primary name; the
// regex this replaces returned the literal text "('conan')" for that shape.
// Falls back to pkgbase, which split packages set alongside the array.
func (v *Vars) Name() string {
	if s := v.scalars["pkgname"]; s != "" {
		return s
	}
	if arr := v.arrays["pkgname"]; len(arr) > 0 {
		return arr[0]
	}
	return v.scalars["pkgbase"]
}

// remoteSchemes are the source= prefixes that denote something fetched rather
// than something shipped alongside the PKGBUILD.
var remoteSchemes = []string{
	"http://", "https://", "ftp://", "ftps://",
	"git+", "git://", "svn+", "hg+", "bzr+",
}

// LocalSources returns the source= entries that name a file shipped next to the
// PKGBUILD, rather than something downloaded. An entry may be written as
// `renamed::url`, in which case what matters is whether the right-hand side is
// remote.
//
// Because parameter expansion is already resolved, an entry written as
// `google-chrome-$_channel.sh` is returned as `google-chrome-stable.sh` -- the
// case the previous implementation special-cased by substituting `$_channel` by
// hand.
func (v *Vars) LocalSources() []string {
	var out []string
	for _, entry := range v.arrays["source"] {
		target := entry
		if _, after, found := strings.Cut(entry, "::"); found {
			target = after
		}
		if isRemote(target) {
			continue
		}
		if target != "" {
			out = append(out, target)
		}
	}
	return out
}

func isRemote(s string) bool {
	for _, scheme := range remoteSchemes {
		if strings.HasPrefix(s, scheme) {
			return true
		}
	}
	return false
}

// Install returns the install script filename declared by `install=`, or "".
//
// Split packages may instead set install= inside a package_*() function, which
// is not read here; see the package comment for why function bodies are skipped.
func (v *Vars) Install() string { return v.scalars["install"] }

// Maintainer returns the `# Maintainer:` comment value, or "Unknown".
// This is a packaging convention expressed in a comment, not shell syntax, so it
// is read from the source text rather than the syntax tree.
func (v *Vars) Maintainer() string { return v.maintainer }

func findMaintainer(src string) string {
	for _, line := range strings.Split(src, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "#") {
			continue
		}
		rest := strings.TrimSpace(strings.TrimPrefix(line, "#"))
		if len(rest) < len("Maintainer:") {
			continue
		}
		if strings.EqualFold(rest[:len("Maintainer:")], "Maintainer:") {
			if m := strings.TrimSpace(rest[len("Maintainer:"):]); m != "" {
				return m
			}
		}
	}
	return "Unknown"
}

// word renders a word to the string a shell would produce, resolving quotes and
// any parameter expansion naming a variable declared earlier in the file.
func (v *Vars) word(w *syntax.Word) string {
	var sb strings.Builder
	for _, part := range w.Parts {
		sb.WriteString(v.part(part))
	}
	return sb.String()
}

func (v *Vars) part(part syntax.WordPart) string {
	switch p := part.(type) {
	case *syntax.Lit:
		return p.Value
	case *syntax.SglQuoted:
		return p.Value
	case *syntax.DblQuoted:
		var sb strings.Builder
		for _, inner := range p.Parts {
			sb.WriteString(v.part(inner))
		}
		return sb.String()
	case *syntax.ParamExp:
		// Plain ${foo} / $foo referring to something already declared. Anything
		// with an operator (${foo%bar}, ${foo[1]}) is left as source: resolving
		// it would mean implementing shell expansion semantics.
		if p.Param != nil && p.Exp == nil && p.Index == nil && !p.Length && !p.Excl {
			if val, ok := v.scalars[p.Param.Value]; ok {
				return val
			}
		}
		return raw(part)
	default:
		// CmdSubst, ArithmExp, ProcSubst, ExtGlob: values only a build can know.
		// Returned as source so a caller can distinguish "computed" from "absent"
		// rather than seeing a silently empty string.
		return raw(part)
	}
}

func raw(node syntax.Node) string {
	var sb strings.Builder
	if err := syntax.NewPrinter().Print(&sb, node); err != nil {
		return ""
	}
	return sb.String()
}
