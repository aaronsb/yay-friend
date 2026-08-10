package cmd

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

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

// collectPackageTree reads a PKGBUILD and every companion file it references —
// the .install hook and any source= entry shipped beside it — so the analyzer
// sees the code that actually runs, not just the recipe that fetches it.
//
// It returns the path of the install script it found, if any, because that is
// the one companion worth naming to the user: it is the part that runs as root.
func collectPackageTree(pkgbuildPath string) (types.PackageInfo, string, error) {
	content, err := os.ReadFile(pkgbuildPath)
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
			if content, err := os.ReadFile(installScriptPath); err == nil {
				pkgInfo.InstallScript = string(content)
				pkgInfo.AdditionalFiles[filepath.Base(installScriptPath)] = string(content)
			}
		}

		for _, file := range findAdditionalFiles(vars, dir) {
			if content, err := os.ReadFile(filepath.Join(dir, file)); err == nil {
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
	content, err := os.ReadFile(filepath.Join(dir, "PKGBUILD"))
	if err != nil {
		return ""
	}
	vars, err := pkgbuild.Parse(string(content))
	if err != nil {
		return ""
	}
	return joinVersion(vars.Str("epoch"), vars.Str("pkgver"), vars.Str("pkgrel"))
}

// srcinfoVersion reads epoch/pkgver/pkgrel out of a .SRCINFO. The format is
// "key = value" lines, indented under pkgbase; the first declaration of each
// key is the package-wide one, and a later per-package override is not what a
// grading is about.
func srcinfoVersion(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	var epoch, pkgver, pkgrel string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		key, value, found := strings.Cut(scanner.Text(), "=")
		if !found {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		switch key {
		case "epoch":
			if epoch == "" {
				epoch = value
			}
		case "pkgver":
			if pkgver == "" {
				pkgver = value
			}
		case "pkgrel":
			if pkgrel == "" {
				pkgrel = value
			}
		}
	}

	return joinVersion(epoch, pkgver, pkgrel)
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
