package pkgbuild

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// TestShadowedPrefixes guards the defect that motivated this package: the
// previous regex extraction was unanchored, so a request for `pkgname` matched
// `_pkgname=` and a request for `depends` matched `makedepends=`. Every case
// here returned the wrong value before the AST rewrite.
func TestShadowedPrefixes(t *testing.T) {
	const src = `# Maintainer: Someone <a@b.c>
_pkgname=foo
pkgname=foo-bin
_pkgver=9.9.9
pkgver=1.2.3
makedepends=('git' 'cmake')
depends=('glibc' 'gtk3')
checkdepends=('pytest')
`
	v, err := Parse(src)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if got, want := v.Name(), "foo-bin"; got != want {
		t.Errorf("Name() = %q, want %q (regex returned %q: _pkgname shadowed pkgname)", got, want, "foo")
	}
	if got, want := v.Str("pkgver"), "1.2.3"; got != want {
		t.Errorf("pkgver = %q, want %q (regex returned %q: _pkgver shadowed pkgver)", got, want, "9.9.9")
	}
	if got, want := v.Slice("depends"), []string{"glibc", "gtk3"}; !reflect.DeepEqual(got, want) {
		t.Errorf("depends = %v, want %v (regex returned makedepends, declared first)", got, want)
	}
	if got, want := v.Slice("makedepends"), []string{"git", "cmake"}; !reflect.DeepEqual(got, want) {
		t.Errorf("makedepends = %v, want %v", got, want)
	}
}

// TestSplitPackageName covers pkgname declared as an array, which the regex
// returned as the literal text "('conan')".
func TestSplitPackageName(t *testing.T) {
	for _, tc := range []struct {
		name, src, want string
	}{
		{"single-element array", "pkgname=('conan')\n", "conan"},
		{"multi-element array", "pkgname=(\n  'gcloud'\n  'gcloud-extra'\n)\n", "gcloud"},
		{"pkgbase fallback", "pkgbase='google-cloud-cli'\npkgname=()\n", "google-cloud-cli"},
		{"plain scalar", "pkgname=hello\n", "hello"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v, err := Parse(tc.src)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if got := v.Name(); got != tc.want {
				t.Errorf("Name() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestExpansion covers the variable resolution that replaces the hardcoded
// `$_channel` -> "stable" substitution in the previous implementation.
func TestExpansion(t *testing.T) {
	const src = `_channel=stable
pkgname=google-chrome
pkgver=1.0
url="https://github.com/example/$pkgname"
source=('eula_text.html'
        "google-chrome-$_channel.sh"
        "${pkgname}-${pkgver}.tar.gz::https://dl.example.com/${pkgname}_${pkgver}.tar.gz")
`
	v, err := Parse(src)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if got, want := v.Str("url"), "https://github.com/example/google-chrome"; got != want {
		t.Errorf("url = %q, want %q", got, want)
	}

	want := []string{
		"eula_text.html",
		"google-chrome-stable.sh",
		"google-chrome-1.0.tar.gz::https://dl.example.com/google-chrome_1.0.tar.gz",
	}
	if got := v.Slice("source"); !reflect.DeepEqual(got, want) {
		t.Errorf("source = %v, want %v", got, want)
	}

	// Only the two entries that are not downloads.
	wantLocal := []string{"eula_text.html", "google-chrome-stable.sh"}
	if got := v.LocalSources(); !reflect.DeepEqual(got, wantLocal) {
		t.Errorf("LocalSources() = %v, want %v", got, wantLocal)
	}
}

// TestComputedValuesArePreserved checks that a value only a build can determine
// comes back as its source text rather than an empty string, so a caller can
// tell "computed at build time" apart from "not declared".
func TestComputedValuesArePreserved(t *testing.T) {
	v, err := Parse("pkgver=$(git describe --tags)\npkgrel=1\n")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got := v.Str("pkgver"); got != "$(git describe --tags)" {
		t.Errorf("pkgver = %q, want the raw command substitution", got)
	}
	if got := v.Str("pkgrel"); got != "1" {
		t.Errorf("pkgrel = %q, want %q", got, "1")
	}
}

// TestFunctionBodiesIgnored covers the deliberate scoping choice: a pkgver()
// body assigning pkgver must not override the top-level declaration.
func TestFunctionBodiesIgnored(t *testing.T) {
	const src = `pkgname=thing-git
pkgver=r100.abcdef
pkgver() {
  cd "$srcdir/thing"
  pkgver=r999.deadbeef
  printf "r%s.%s" "$(git rev-list --count HEAD)" "$(git rev-parse --short HEAD)"
}
build() {
  depends=('should-not-appear')
}
`
	v, err := Parse(src)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got, want := v.Str("pkgver"), "r100.abcdef"; got != want {
		t.Errorf("pkgver = %q, want %q (function body must not win)", got, want)
	}
	if got := v.Slice("depends"); got != nil {
		t.Errorf("depends = %v, want nil (declared only inside build())", got)
	}
}

// TestAppendAssignment guards a regression caught in review: `+=` extends a
// declaration in bash, and treating it as a plain assignment silently dropped
// everything declared before it. The source= case is the one that bites -- a
// dropped entry means a companion file never reaches the analyzer.
func TestAppendAssignment(t *testing.T) {
	const src = `depends=('a' 'b')
depends+=('c')
source=('x.patch')
source+=('y.patch')
pkgdesc='hello'
pkgdesc+=' world'
`
	v, err := Parse(src)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got, want := v.Slice("depends"), []string{"a", "b", "c"}; !reflect.DeepEqual(got, want) {
		t.Errorf("depends = %v, want %v", got, want)
	}
	if got, want := v.Slice("source"), []string{"x.patch", "y.patch"}; !reflect.DeepEqual(got, want) {
		t.Errorf("source = %v, want %v", got, want)
	}
	if got, want := v.LocalSources(), []string{"x.patch", "y.patch"}; !reflect.DeepEqual(got, want) {
		t.Errorf("LocalSources() = %v, want %v", got, want)
	}
	if got, want := v.Str("pkgdesc"), "hello world"; got != want {
		t.Errorf("pkgdesc = %q, want %q", got, want)
	}
}

// TestInstall covers the input to the decision of whether a package's .install
// script -- the part that runs as root -- gets collected for analysis.
func TestInstall(t *testing.T) {
	for _, tc := range []struct{ name, src, want string }{
		{"literal", "install=hello.install\n", "hello.install"},
		{"expanded", "pkgname=hello\ninstall=$pkgname.install\n", "hello.install"},
		{"braced and quoted", "pkgname=hello\ninstall=\"${pkgname}.install\"\n", "hello.install"},
		{"absent", "pkgname=hello\n", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v, err := Parse(tc.src)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if got := v.Install(); got != tc.want {
				t.Errorf("Install() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestLocalSourcesRejectsPaths: makepkg requires a local source to sit beside
// the PKGBUILD, so a path component means the entry is malformed. Honouring one
// would let a hostile PKGBUILD name a file outside the package directory and
// have its contents collected and sent to the analysis provider.
func TestLocalSourcesRejectsPaths(t *testing.T) {
	const src = `source=('good.patch'
        '../../../etc/passwd'
        '/etc/shadow'
        'sub/dir/file.sh'
        'https://example.com/real.tar.gz'
        'renamed.tar.gz::https://example.com/x.tar.gz'
        'name::git+https://example.com/r.git#commit=abc')
`
	v, err := Parse(src)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	want := []string{"good.patch"}
	if got := v.LocalSources(); !reflect.DeepEqual(got, want) {
		t.Errorf("LocalSources() = %v, want %v", got, want)
	}
}

// TestExpansionBombIsBounded guards a denial of service introduced by adding
// expansion: because a variable can reference earlier ones, `a1=$a0$a0$a0$a0`
// repeated grows by 4x per level. Unbounded, 158 bytes of input reached 2.6 MB
// by the ninth level and a few hundred bytes exhausted memory outright -- a
// fatal error, not a panic, so no recover() could have caught it.
func TestExpansionBombIsBounded(t *testing.T) {
	var b strings.Builder
	b.WriteString("a0=xxxxxxxxxx\n")
	for i := 1; i <= 12; i++ {
		fmt.Fprintf(&b, "a%d=$a%d$a%d$a%d$a%d\n", i, i-1, i-1, i-1, i-1)
	}
	v, err := Parse(b.String())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	for i := range 13 {
		if got := len(v.Str(fmt.Sprintf("a%d", i))); got > maxValueLen {
			t.Errorf("a%d expanded to %d bytes, exceeds cap of %d", i, got, maxValueLen)
		}
	}
}

func TestOversizedInputRejected(t *testing.T) {
	_, err := Parse("pkgname=x\n" + strings.Repeat("# padding\n", maxInputSize/10))
	if !errors.Is(err, ErrTooLarge) {
		t.Errorf("Parse(oversized) error = %v, want ErrTooLarge", err)
	}
}

// TestInstallRejectsTraversal: the caller reads this file and sends its contents
// to the analysis provider, so a path escaping the package directory is an
// exfiltration primitive. The obfuscated form matters because expansion is
// resolved -- the target need not appear literally in the source.
func TestInstallRejectsTraversal(t *testing.T) {
	for _, tc := range []struct{ name, src, want string }{
		{"literal traversal", "pkgname=x\ninstall=../../../etc/passwd\n", ""},
		{"expanded traversal", "_p=../../../.ssh\npkgname=x\ninstall=$_p/id_rsa\n", ""},
		{"absolute path", "pkgname=x\ninstall=/etc/shadow\n", ""},
		{"subdirectory", "pkgname=x\ninstall=sub/x.install\n", ""},
		{"unresolved", "pkgname=x\ninstall=$undefined.install\n", ""},
		{"legitimate", "pkgname=hello\ninstall=$pkgname.install\n", "hello.install"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v, err := Parse(tc.src)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if got := v.Install(); got != tc.want {
				t.Errorf("Install() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestUnresolvedSourceEntriesDropped: marktext-bin builds its source array from
// a command substitution, `source=($(_source))`. That names no file we can
// identify, so it must not be offered as one.
func TestUnresolvedSourceEntriesDropped(t *testing.T) {
	v, err := Parse("source=($(_source))\nsource+=('real.patch')\n")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got, want := v.LocalSources(), []string{"real.patch"}; !reflect.DeepEqual(got, want) {
		t.Errorf("LocalSources() = %v, want %v", got, want)
	}
}

// TestLocalSchemePrefix covers `local://foo.patch`, which names a file beside
// the PKGBUILD. simavr uses it; without stripping, the `//` made it look like a
// path component and the patch was never collected.
func TestLocalSchemePrefix(t *testing.T) {
	v, err := Parse("source=(\"pkg::git+https://x/y.git#commit=a\"\n\t\"local://make_fix.patch\")\n")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got, want := v.LocalSources(), []string{"make_fix.patch"}; !reflect.DeepEqual(got, want) {
		t.Errorf("LocalSources() = %v, want %v", got, want)
	}
}

// TestArchSpecificSources: many binary packages leave source= empty and declare
// everything in source_x86_64=.
func TestArchSpecificSources(t *testing.T) {
	const src = `source=('common.patch')
source_x86_64=('amd64.bin' 'https://example.com/a.tar.gz')
source_aarch64=('arm64.bin')
`
	v, err := Parse(src)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	want := []string{"common.patch", "arm64.bin", "amd64.bin"} // arch keys sorted
	if got := v.LocalSources(); !reflect.DeepEqual(got, want) {
		t.Errorf("LocalSources() = %v, want %v", got, want)
	}
}

// TestOperatorExpansionsNotResolved guards against returning a plausible wrong
// value. `${v//-/.}` must not come back as the unmodified `v`: that is the exact
// failure class -- silently wrong rather than visibly unknown -- that this
// package exists to remove.
func TestOperatorExpansionsNotResolved(t *testing.T) {
	const src = `_ver=1.2.3-beta-4
dotted=${_ver//-/.}
initial=${_ver:0:1}
trimmed=${_ver%%-*}
fallback=${undefined:-fallbackvalue}
plain=$_ver
braced=${_ver}
`
	v, err := Parse(src)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	// Plain references resolve.
	if got, want := v.Str("plain"), "1.2.3-beta-4"; got != want {
		t.Errorf("plain = %q, want %q", got, want)
	}
	if got, want := v.Str("braced"), "1.2.3-beta-4"; got != want {
		t.Errorf("braced = %q, want %q", got, want)
	}
	// Operator forms must NOT come back as the unmodified value.
	for _, name := range []string{"dotted", "initial", "trimmed", "fallback"} {
		if got := v.Str(name); got == "1.2.3-beta-4" {
			t.Errorf("%s = %q -- operator expansion resolved to the unmodified value", name, got)
		}
	}
}

// TestUnquotedExpansionWordSplits: bash splits an unquoted expansion, quoted
// text stays one entry.
func TestUnquotedExpansionWordSplits(t *testing.T) {
	const src = `_deps='glibc gtk3 zlib'
depends=($_deps)
optdepends=("$_deps")
`
	v, err := Parse(src)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got, want := v.Slice("depends"), []string{"glibc", "gtk3", "zlib"}; !reflect.DeepEqual(got, want) {
		t.Errorf("depends = %v, want %v (unquoted expansion word-splits)", got, want)
	}
	if got, want := v.Slice("optdepends"), []string{"glibc gtk3 zlib"}; !reflect.DeepEqual(got, want) {
		t.Errorf("optdepends = %v, want %v (quoted expansion does not split)", got, want)
	}
}

// TestLaterDeclarationWins: a scalar followed by an array declaration of the
// same name must not leave the stale scalar visible to Name().
func TestLaterDeclarationWins(t *testing.T) {
	v, err := Parse("pkgname=single\npkgname=('first' 'second')\n")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got, want := v.Name(), "first"; got != want {
		t.Errorf("Name() = %q, want %q (stale scalar shadowed the array)", got, want)
	}
	if got, want := v.Str("pkgname"), ""; got != want {
		t.Errorf("Str(pkgname) = %q, want %q", got, want)
	}
}

// TestScalarFormArray covers `depends=glibc` without parentheses, which makepkg
// reads as a one-element list.
func TestScalarFormArray(t *testing.T) {
	v, err := Parse("depends=glibc\n")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got, want := v.Slice("depends"), []string{"glibc"}; !reflect.DeepEqual(got, want) {
		t.Errorf("depends = %v, want %v", got, want)
	}
}

// TestZeroValueMaintainer: Maintainer documents a "Unknown" fallback, so the
// zero value must honour it rather than returning "".
func TestZeroValueMaintainer(t *testing.T) {
	var v Vars
	if got := v.Maintainer(); got != "Unknown" {
		t.Errorf("(zero Vars).Maintainer() = %q, want %q", got, "Unknown")
	}
}

func TestMaintainer(t *testing.T) {
	for _, tc := range []struct{ name, src, want string }{
		{"standard", "# Maintainer: Jane Doe <jane@example.com>\npkgname=x\n", "Jane Doe <jane@example.com>"},
		{"lowercase", "# maintainer: Jane Doe\npkgname=x\n", "Jane Doe"},
		{"no space after hash", "#Maintainer: Jane Doe\npkgname=x\n", "Jane Doe"},
		{"contributor first", "# Contributor: Bob\n# Maintainer: Jane\npkgname=x\n", "Jane"},
		// Real shape from llama.cpp-vulkan; stripping only one # loses it.
		{"double hash", "# # Maintainer: Orion-zhen <https://github.com/Orion-zhen>\npkgname=x\n", "Orion-zhen <https://github.com/Orion-zhen>"},
		{"absent", "pkgname=x\n", "Unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v, err := Parse(tc.src)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if got := v.Maintainer(); got != tc.want {
				t.Errorf("Maintainer() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestParseErrorIsReported(t *testing.T) {
	if _, err := Parse("pkgname=(unclosed\n"); err == nil {
		t.Fatal("Parse succeeded on malformed input, want error")
	}
}
