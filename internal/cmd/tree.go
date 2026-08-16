package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Morganamilo/go-srcinfo"

	"github.com/aaronsb/yay-friend/internal/pkgbuild"
	"github.com/aaronsb/yay-friend/internal/types"
	"github.com/aaronsb/yay-friend/internal/ui"
)

// resolvePKGBUILDPath accepts either a PKGBUILD file or the directory holding
// one and returns the file.
func resolvePKGBUILDPath(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("cannot read %s: %w", path, err)
	}
	if !info.IsDir() {
		return path, nil
	}
	pkgbuildPath := filepath.Join(path, "PKGBUILD")
	if _, err := os.Stat(pkgbuildPath); err != nil {
		return "", fmt.Errorf("no PKGBUILD in %s: %w", path, err)
	}
	return pkgbuildPath, nil
}

// readRegular reads a file after proving it is a regular file. The tree's
// paths are chosen by whoever staged it, and os.ReadFile on a FIFO blocks in
// open() forever — past SIGTERM, since main's signal context replaces
// die-on-signal with a cancel no file read observes. Refusing anything
// irregular keeps a hostile tree from hanging a grade that a caller then has
// to SIGKILL.
func readRegular(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	// A symlink is followed one hop and its target held to the same rule.
	if info.Mode()&os.ModeSymlink != 0 {
		if info, err = os.Stat(path); err != nil {
			return nil, err
		}
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	return os.ReadFile(path)
}

// collectPackageTree reads a PKGBUILD and every companion file it references —
// the .install hook and any source= entry shipped beside it — so the analyzer
// sees the code that actually runs, not just the recipe that fetches it.
//
// It returns the path of the install script it found, if any, because that is
// the one companion worth naming to the user: it is the part that runs as root.
func collectPackageTree(pkgbuildPath string) (types.PackageInfo, string, error) {
	content, err := readRegular(pkgbuildPath)
	if err != nil {
		return types.PackageInfo{}, "", fmt.Errorf("failed to read PKGBUILD: %w", err)
	}

	pkgInfo, vars := parseLocalPKGBUILD(string(content), pkgbuildPath)
	dir := filepath.Dir(pkgbuildPath)
	pkgInfo.AdditionalFiles = make(map[string]string)

	// Companion files are only discoverable when the PKGBUILD parses; an
	// unparseable one still gets analyzed on its own source above.
	var installScriptPath string
	if vars != nil {
		installScriptPath = findInstallScript(vars, dir)
		if installScriptPath != "" {
			if content, err := readRegular(installScriptPath); err == nil {
				pkgInfo.InstallScript = string(content)
				pkgInfo.AdditionalFiles[filepath.Base(installScriptPath)] = string(content)
			}
		}

		for _, file := range findAdditionalFiles(vars, dir) {
			if content, err := readRegular(filepath.Join(dir, file)); err == nil {
				pkgInfo.AdditionalFiles[file] = string(content)
			}
		}
	}

	return pkgInfo, installScriptPath, nil
}

// parseLocalPKGBUILD extracts basic package information from a PKGBUILD.
// A PKGBUILD that will not parse still yields a usable PackageInfo: the raw
// source is what the analyzer reads, and metadata is only there to orient the
// user.
// It returns the parsed variables alongside the info so companion-file discovery
// does not have to parse the same source a second time; vars is nil when the
// PKGBUILD could not be parsed.
func parseLocalPKGBUILD(content string, path string) (types.PackageInfo, *pkgbuild.Vars) {
	info := types.PackageInfo{
		PKGBUILD:   content,
		Maintainer: "Unknown",
		// Defaults for local analysis
		AURPageURL:     "Local PKGBUILD",
		LastUpdated:    "Not available (local PKGBUILD)",
		FirstSubmitted: "Not available (local PKGBUILD)",
	}

	vars, err := pkgbuild.Parse(content)
	if err != nil {
		ui.Warn("could not parse %s as shell (%v); analyzing raw source", path, err)
		return info, nil
	}

	info.Name = vars.Name()
	info.Version = vars.Str("pkgver")
	info.Description = vars.Str("pkgdesc")
	info.URL = vars.Str("url")
	info.Maintainer = vars.Maintainer()
	info.Dependencies = vars.Slice("depends")
	info.MakeDepends = vars.Slice("makedepends")
	info.OptDepends = vars.Slice("optdepends")

	return info, vars
}

// findInstallScript returns the path to the .install script referenced by the
// PKGBUILD, if that file exists alongside it.
func findInstallScript(vars *pkgbuild.Vars, dir string) string {
	name := vars.Install()
	if name == "" {
		return ""
	}
	path := filepath.Join(dir, name)
	if _, err := os.Stat(path); err != nil {
		return ""
	}
	return path
}

// findAdditionalFiles returns the source= entries that name a file present in
// the PKGBUILD's directory, so their contents can be sent for analysis too.
func findAdditionalFiles(vars *pkgbuild.Vars, dir string) []string {
	var files []string
	for _, name := range vars.LocalSources() {
		if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
			files = append(files, name)
		}
	}
	return files
}

// treeVersion returns the full package version of a staged tree, in makepkg's
// own spelling: [epoch:]pkgver[-pkgrel].
//
// .SRCINFO is preferred because it is already expanded — a PKGBUILD whose
// pkgver() function computes the version from a git checkout has no usable
// pkgver in its source. Best effort throughout: this only feeds an optional,
// display-only field, and a tree without either is not a failure.
func treeVersion(dir string) string {
	if v := srcinfoVersion(filepath.Join(dir, ".SRCINFO")); v != "" {
		return v
	}
	content, err := readRegular(filepath.Join(dir, "PKGBUILD"))
	if err != nil {
		return ""
	}
	vars, err := pkgbuild.Parse(string(content))
	if err != nil {
		return ""
	}
	return joinVersion(vars.Str("epoch"), vars.Str("pkgver"), vars.Str("pkgrel"))
}

// srcinfoVersion reads the package-wide version out of a .SRCINFO.
//
// Parsing is go-srcinfo's, the same parser yay uses. The hand-rolled reader it
// replaces scanned for "key = value" with no notion of the pkgbase/pkgname
// sections the format is built from, and leaned on first-occurrence ordering to
// stay on the pkgbase one. That held for the files it was tried against, which
// is a different claim from holding for the format.
//
// Version() reports the pkgbase version; a split package's per-package override
// is deliberately not consulted, because a grading is about the tree, not one
// output package of it.
func srcinfoVersion(path string) string {
	info, err := srcinfo.ParseFile(path)
	if err != nil {
		return ""
	}
	return info.Version()
}

func joinVersion(epoch, pkgver, pkgrel string) string {
	if pkgver == "" {
		return ""
	}
	var b strings.Builder
	if epoch != "" {
		b.WriteString(epoch)
		b.WriteString(":")
	}
	b.WriteString(pkgver)
	if pkgrel != "" {
		b.WriteString("-")
		b.WriteString(pkgrel)
	}
	return b.String()
}
