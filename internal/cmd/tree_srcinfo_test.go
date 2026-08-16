package cmd

import (
	"os"
	"path/filepath"
	"testing"
)

func writeSrcinfo(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), ".SRCINFO")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestSrcinfoVersionReadsPkgbase covers the ordinary shape.
func TestSrcinfoVersionReadsPkgbase(t *testing.T) {
	for _, tc := range []struct {
		name    string
		content string
		want    string
	}{
		{
			"pkgver and pkgrel",
			"pkgbase = hello\n\tpkgver = 2.12.1\n\tpkgrel = 1\n\tarch = x86_64\n\npkgname = hello\n",
			"2.12.1-1",
		},
		{
			"with epoch",
			"pkgbase = hello\n\tpkgver = 2.12.1\n\tpkgrel = 3\n\tepoch = 2\n\tarch = x86_64\n\npkgname = hello\n",
			"2:2.12.1-3",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := srcinfoVersion(writeSrcinfo(t, tc.content)); got != tc.want {
				t.Errorf("srcinfoVersion() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestSrcinfoVersionIgnoresPerPackageOverrides is the case the hand-rolled
// reader could only get right by accident. It scanned for "key = value" with no
// notion of sections and took the first match, so a pkgbase whose own pkgver
// happened to appear after a split package's would have been misread.
func TestSrcinfoVersionIgnoresPerPackageOverrides(t *testing.T) {
	const content = "pkgbase = mixed\n" +
		"\tpkgver = 1.0.0\n" +
		"\tpkgrel = 2\n" +
		"\tarch = x86_64\n" +
		"\n" +
		"pkgname = mixed-core\n" +
		"\n" +
		"pkgname = mixed-docs\n" +
		"\tpkgdesc = docs only\n"

	if got, want := srcinfoVersion(writeSrcinfo(t, content)), "1.0.0-2"; got != want {
		t.Errorf("srcinfoVersion() = %q, want the pkgbase version %q", got, want)
	}
}

// TestSrcinfoVersionOnMissingOrJunkIsEmpty keeps the caller's best-effort
// contract: treeVersion falls back to the PKGBUILD, and an empty string is how
// it is told to.
func TestSrcinfoVersionOnMissingOrJunkIsEmpty(t *testing.T) {
	if got := srcinfoVersion(filepath.Join(t.TempDir(), "absent")); got != "" {
		t.Errorf("srcinfoVersion(missing) = %q, want empty", got)
	}
	if got := srcinfoVersion(writeSrcinfo(t, "<!DOCTYPE html>\n<html></html>\n")); got != "" {
		t.Errorf("srcinfoVersion(html) = %q, want empty", got)
	}
}

// TestSrcinfoVersionAgainstRealFile parses a .SRCINFO produced by
// `makepkg --printsrcinfo`, which is the only kind that reaches this code in
// practice -- the AUR will not accept any other.
func TestSrcinfoVersionAgainstRealFile(t *testing.T) {
	const path = "testdata/real.SRCINFO"
	if _, err := os.Stat(path); err != nil {
		t.Skipf("no fixture: %v", err)
	}
	if got := srcinfoVersion(path); got == "" {
		t.Error("a real .SRCINFO produced no version")
	} else {
		t.Logf("parsed version %q", got)
	}
}
