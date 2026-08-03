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
	"sort"
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
			name := a.Name.Value
			switch {
			case a.Array != nil:
				var vals []string
				for _, el := range a.Array.Elems {
					if el.Value == nil {
						continue
					}
					text := v.word(el.Value)
					// An unquoted expansion word-splits in bash:
					// `depends=($_deps)` with _deps='a b' is two entries.
					// Quoted text never splits, and a literal cannot contain
					// whitespace -- the parser would already have split it.
					if unquoted(el.Value) && strings.ContainsAny(text, " \t\n") {
						vals = append(vals, strings.Fields(text)...)
						continue
					}
					vals = append(vals, text)
				}
				// `depends+=(...)` extends the declaration; treating it as a
				// plain assignment would silently drop everything declared
				// before it, including source+= entries naming files that must
				// reach the analyzer.
				if a.Append {
					v.arrays[name] = append(v.arrays[name], vals...)
				} else {
					v.arrays[name] = vals
					delete(v.scalars, name) // a later array declaration wins
				}
			case a.Value != nil:
				val := v.word(a.Value)
				if a.Append {
					v.scalars[name] += val
				} else {
					v.scalars[name] = val
					delete(v.arrays, name)
				}
			}
		}
	}

	v.maintainer = findMaintainer(src)
	return v, nil
}

// Str returns a scalar declaration, or "" if absent.
func (v *Vars) Str(name string) string { return v.scalars[name] }

// Slice returns an array declaration, or nil if absent. A declaration written
// in scalar form (`depends=glibc`, which makepkg reads as a one-element list)
// is returned as a single element.
func (v *Vars) Slice(name string) []string {
	if arr, ok := v.arrays[name]; ok {
		return arr
	}
	if s, ok := v.scalars[name]; ok && s != "" {
		return []string{s}
	}
	return nil
}

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
// Entries are restricted to plain filenames. makepkg requires a local source to
// sit beside the PKGBUILD, so anything carrying a path component is malformed --
// and honouring it would let a hostile PKGBUILD name `../../../.ssh/id_rsa` and
// have its contents collected for analysis.
func (v *Vars) LocalSources() []string {
	var out []string
	seen := map[string]bool{}
	for _, entry := range v.sourceEntries() {
		target := entry
		if _, after, found := strings.Cut(entry, "::"); found {
			target = after
		}
		// `local://foo.patch` names a file beside the PKGBUILD (simavr uses it).
		target = strings.TrimPrefix(target, "local://")
		if target == "" || isRemote(target) {
			continue
		}
		// An entry still carrying a `$` did not resolve -- a command
		// substitution, or a reference to something set at build time. It names
		// no file we can identify, so it is not one.
		if strings.Contains(target, "$") {
			continue
		}
		if strings.ContainsAny(target, `/\`) || target == "." || target == ".." {
			continue
		}
		if !seen[target] {
			seen[target] = true
			out = append(out, target)
		}
	}
	return out
}

// sourceEntries returns source= plus every architecture-specific source_<arch>=
// declaration. Eight of the 36 PKGBUILDs sampled while writing this package put
// their real sources in source_x86_64 and leave source= empty or absent.
func (v *Vars) sourceEntries() []string {
	entries := append([]string(nil), v.Slice("source")...)

	archKeys := make([]string, 0, len(v.arrays))
	for name := range v.arrays {
		if strings.HasPrefix(name, "source_") {
			archKeys = append(archKeys, name)
		}
	}
	sort.Strings(archKeys) // map iteration order is not deterministic
	for _, k := range archKeys {
		entries = append(entries, v.arrays[k]...)
	}
	return entries
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
func (v *Vars) Maintainer() string {
	if v.maintainer == "" {
		return "Unknown"
	}
	return v.maintainer
}

func findMaintainer(src string) string {
	for _, line := range strings.Split(src, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "#") {
			continue
		}
		// TrimLeft, not TrimPrefix: `# # Maintainer: ...` occurs in the wild
		// (llama.cpp-vulkan), and stripping only one # loses the maintainer.
		rest := strings.TrimSpace(strings.TrimLeft(line, "# \t"))
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
		// Only a plain $foo / ${foo} is resolved. Anything carrying an operator
		// (${foo/a/b}, ${foo:0:1}, ${foo%bar}) is left as source text, because
		// returning the *unmodified* value would be a plausible wrong answer --
		// the same failure class this package exists to remove.
		if isSimpleParam(p) {
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

// isSimpleParam reports whether a parameter expansion is a bare $name/${name}
// with no operator attached. It mirrors the unexported (*syntax.ParamExp).simple
// in mvdan.cc/sh; every field that type checks must be checked here, so if the
// library gains an operator field this predicate needs the same addition.
func isSimpleParam(p *syntax.ParamExp) bool {
	return p.Param != nil && p.Flags == nil &&
		!p.Excl && !p.Length && !p.Width && !p.IsSet &&
		p.NestedParam == nil && p.Index == nil &&
		len(p.Modifiers) == 0 && p.Slice == nil &&
		p.Repl == nil && p.Names == 0 && p.Exp == nil
}

// unquoted reports whether a word contains no quoted section, and so is subject
// to word splitting when it expands.
func unquoted(w *syntax.Word) bool {
	for _, part := range w.Parts {
		switch part.(type) {
		case *syntax.SglQuoted, *syntax.DblQuoted:
			return false
		}
	}
	return true
}

func raw(node syntax.Node) string {
	var sb strings.Builder
	if err := syntax.NewPrinter().Print(&sb, node); err != nil {
		return ""
	}
	return sb.String()
}
