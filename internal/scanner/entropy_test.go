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
