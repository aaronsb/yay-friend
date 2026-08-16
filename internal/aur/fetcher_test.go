package aur

import (
	"testing"

	"github.com/aaronsb/yay-friend/internal/types"
)

// TestEnrichBackfillsMetadata guards the defect where the RPC response was
// fetched, read for votes and dates, and then dropped on the floor for
// everything else. ya-claude-code reached the analyzer as "Maintainer: Unknown,
// Version: (empty)" while the response in hand said aaronsb / 2.1.233-1 -- and
// the analyzer marked the package down for the unknown maintainer it had just
// been told about.
func TestEnrichBackfillsMetadata(t *testing.T) {
	aurData := &AURPackageInfo{
		Name:        "ya-claude-code",
		Version:     "2.1.233-1",
		Description: "Claude Code CLI",
		URL:         "https://github.com/anthropics/claude-code",
		Maintainer:  "aaronsb",
		NumVotes:    0,
	}
	// What a PKGBUILD that failed to parse leaves behind.
	pkgInfo := &types.PackageInfo{Name: "ya-claude-code", Maintainer: "Unknown"}

	(&AURFetcher{}).enrichFromAURData(aurData, pkgInfo)

	if got, want := pkgInfo.Maintainer, "aaronsb"; got != want {
		t.Errorf("Maintainer = %q, want %q", got, want)
	}
	if got, want := pkgInfo.Version, "2.1.233-1"; got != want {
		t.Errorf("Version = %q, want %q", got, want)
	}
	if got, want := pkgInfo.Description, "Claude Code CLI"; got != want {
		t.Errorf("Description = %q, want %q", got, want)
	}
	if got, want := pkgInfo.URL, "https://github.com/anthropics/claude-code"; got != want {
		t.Errorf("URL = %q, want %q", got, want)
	}
}

// TestEnrichPrefersPKGBUILDValues keeps the backfill from overwriting what the
// PKGBUILD actually declares. Its pkgver is the version about to be built; the
// RPC carries the pkgrel-qualified version last published, which is a different
// fact.
func TestEnrichPrefersPKGBUILDValues(t *testing.T) {
	aurData := &AURPackageInfo{
		Version:     "2.1.233-1",
		Description: "stale AUR description",
		Maintainer:  "aaronsb",
	}
	pkgInfo := &types.PackageInfo{
		Version:     "2.1.240",
		Description: "from the PKGBUILD",
		Maintainer:  "Aaron Bockelie <aaronsb@gmail.com>",
	}

	(&AURFetcher{}).enrichFromAURData(aurData, pkgInfo)

	if got, want := pkgInfo.Version, "2.1.240"; got != want {
		t.Errorf("Version = %q, want %q", got, want)
	}
	if got, want := pkgInfo.Description, "from the PKGBUILD"; got != want {
		t.Errorf("Description = %q, want %q", got, want)
	}
	if got, want := pkgInfo.Maintainer, "Aaron Bockelie <aaronsb@gmail.com>"; got != want {
		t.Errorf("Maintainer = %q, want %q", got, want)
	}
}

// TestEnrichFlagsOrphaned covers the case the `# Maintainer:` comment cannot
// report: an orphaned package keeps the comment its last maintainer left, so a
// package nobody is answerable for still names someone.
func TestEnrichFlagsOrphaned(t *testing.T) {
	aurData := &AURPackageInfo{Maintainer: ""}
	pkgInfo := &types.PackageInfo{Maintainer: "Someone Who Left <x@y.z>"}

	(&AURFetcher{}).enrichFromAURData(aurData, pkgInfo)

	if got, want := pkgInfo.Maintainer, "Orphaned (no AUR maintainer)"; got != want {
		t.Errorf("Maintainer = %q, want %q", got, want)
	}
}
