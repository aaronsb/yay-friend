package pkgbuild

import (
	"reflect"
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

func TestMaintainer(t *testing.T) {
	for _, tc := range []struct{ name, src, want string }{
		{"standard", "# Maintainer: Jane Doe <jane@example.com>\npkgname=x\n", "Jane Doe <jane@example.com>"},
		{"lowercase", "# maintainer: Jane Doe\npkgname=x\n", "Jane Doe"},
		{"no space after hash", "#Maintainer: Jane Doe\npkgname=x\n", "Jane Doe"},
		{"contributor first", "# Contributor: Bob\n# Maintainer: Jane\npkgname=x\n", "Jane"},
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
