package yay

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const realPKGBUILD = `# ya-claude-code

# Maintainer: Aaron Bockelie <aaronsb@gmail.com>
pkgname=ya-claude-code
pkgver=2.1.233
pkgrel=1
pkgdesc="Claude Code CLI"
url="https://github.com/anthropics/claude-code"
depends=('bash' 'glibc')
`

// gitlabSignIn is the shape of what Arch's packaging GitLab returns for a
// project that does not exist: a 302 to the sign-in page, which yay prints as
// the PKGBUILD. Trimmed from the 19 KB the real fetch produced.
const gitlabSignIn = `# ya-claude-code

<!DOCTYPE html>
<html class="html-devise-layout gl-system" lang="en">
<head prefix="og: http://ogp.me/ns#">
<title>Sign in · GitLab</title>
<script>
window.gon={};gon.gitlab_url="https://gitlab.archlinux.org";
</script>
</head>
</html>
`

// fakeYay writes a stand-in yay that answers `-G --print` from repoOut and
// `-G --print --aur` from aurOut, logging every invocation. An empty payload
// means that call fails the way the real one does -- by exiting non-zero.
func fakeYay(t *testing.T, repoOut, aurOut string) (yayPath, callLog string) {
	t.Helper()
	dir := t.TempDir()

	for name, content := range map[string]string{"repo.out": repoOut, "aur.out": aurOut} {
		if content == "" {
			continue // absent file: cat exits non-zero
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	script := "#!/bin/sh\n" +
		"echo \"$*\" >> " + dir + "/calls.log\n" +
		"for a in \"$@\"; do\n" +
		"  [ \"$a\" = \"--aur\" ] && exec cat " + dir + "/aur.out\n" +
		"done\n" +
		"exec cat " + dir + "/repo.out\n"

	yayPath = filepath.Join(dir, "yay")
	if err := os.WriteFile(yayPath, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return yayPath, filepath.Join(dir, "calls.log")
}

func readLog(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(b)
}

// TestShadowedPackageFallsBackToAUR is the defect this fallback exists for.
// ya-claude-code is in the AUR and in a third-party binary repository; yay
// resolves the repository first, asks Arch's packaging GitLab for a project that
// is not there, and prints the sign-in page it gets back -- exiting 0. That HTML
// reached the analyzer as the PKGBUILD, and the resulting verdict described a
// GitLab login form.
func TestShadowedPackageFallsBackToAUR(t *testing.T) {
	yayPath, callLog := fakeYay(t, gitlabSignIn, realPKGBUILD)
	client := NewYayClient(yayPath)

	info, err := client.GetPackageInfo(context.Background(), "ya-claude-code")
	if err != nil {
		t.Fatalf("GetPackageInfo: %v", err)
	}

	if strings.Contains(info.PKGBUILD, "DOCTYPE html") {
		t.Error("PKGBUILD is the GitLab sign-in page; the fetch accepted HTML as package source")
	}
	if got, want := info.Version, "2.1.233"; got != want {
		t.Errorf("Version = %q, want %q", got, want)
	}
	if got, want := info.Maintainer, "Aaron Bockelie <aaronsb@gmail.com>"; got != want {
		t.Errorf("Maintainer = %q, want %q", got, want)
	}
	if !strings.Contains(readLog(t, callLog), "--aur") {
		t.Error("never retried with --aur")
	}
}

// TestOfficialPackageDoesNotAskAUR guards the cost of the fallback. `--aur` is
// the narrower question -- it answers "Unable to find the following packages"
// for anything in the official repositories -- so a plain fetch that already
// produced a PKGBUILD must not be second-guessed.
func TestOfficialPackageDoesNotAskAUR(t *testing.T) {
	yayPath, callLog := fakeYay(t, "# bash\n\npkgname=bash\npkgver=5.3\n", "")
	client := NewYayClient(yayPath)

	info, err := client.GetPackageInfo(context.Background(), "bash")
	if err != nil {
		t.Fatalf("GetPackageInfo: %v", err)
	}
	if got, want := info.Version, "5.3"; got != want {
		t.Errorf("Version = %q, want %q", got, want)
	}
	if strings.Contains(readLog(t, callLog), "--aur") {
		t.Error("retried with --aur despite the first fetch returning a PKGBUILD")
	}
}

// TestNoPKGBUILDAnywhereFails covers the case both sources miss. Returning the
// content anyway is what produced a security verdict over a sign-in page, so the
// only safe answer is to refuse.
func TestNoPKGBUILDAnywhereFails(t *testing.T) {
	yayPath, _ := fakeYay(t, gitlabSignIn, " -> Unable to find the following packages: nope\n")
	client := NewYayClient(yayPath)

	info, err := client.GetPackageInfo(context.Background(), "nope")
	if err == nil {
		t.Fatalf("GetPackageInfo succeeded, want error; PKGBUILD = %.60q", info.PKGBUILD)
	}
	if !strings.Contains(err.Error(), "no PKGBUILD found") {
		t.Errorf("error = %v, want it to say no PKGBUILD was found", err)
	}
}

// TestUnparseablePKGBUILDStillAnalyzed keeps the fetch check from becoming a
// safety check. Bash that will not parse is a reason to look closer, not a
// reason to drop the package -- so long as it is a PKGBUILD at all.
func TestUnparseablePKGBUILDStillAnalyzed(t *testing.T) {
	const broken = "# evil\n\npkgname=evil\ndepends=(unclosed\n"
	yayPath, callLog := fakeYay(t, broken, "")
	client := NewYayClient(yayPath)

	info, err := client.GetPackageInfo(context.Background(), "evil")
	if err != nil {
		t.Fatalf("GetPackageInfo: %v", err)
	}
	if info.PKGBUILD != broken {
		t.Errorf("PKGBUILD = %q, want the raw source passed through", info.PKGBUILD)
	}
	if strings.Contains(readLog(t, callLog), "--aur") {
		t.Error("retried with --aur; unparseable is not the same as not-a-PKGBUILD")
	}
}

// TestYayFailureIsReported covers yay itself exiting non-zero.
func TestYayFailureIsReported(t *testing.T) {
	yayPath, _ := fakeYay(t, "", "")
	client := NewYayClient(yayPath)

	if _, err := client.GetPackageInfo(context.Background(), "whatever"); err == nil {
		t.Fatal("GetPackageInfo succeeded, want error")
	}
}

// TestBarePackageSeparatesFlags covers the branch taken when the first argument
// is a package name rather than a yay operation. It used to file every argument
// as a package, so `yay-friend pkg --needed` searched for a package named
// "--needed" and offered an install selection instead of analyzing pkg.
func TestBarePackageSeparatesFlags(t *testing.T) {
	op, err := ParseYayCommand([]string{"ya-claude-code", "--needed", "another-pkg"})
	if err != nil {
		t.Fatal(err)
	}

	if got, want := op.Operation, "analyze"; got != want {
		t.Errorf("Operation = %q, want %q", got, want)
	}
	if got, want := len(op.Packages), 2; got != want {
		t.Fatalf("Packages = %v, want %d entries", op.Packages, want)
	}
	if op.Packages[0] != "ya-claude-code" || op.Packages[1] != "another-pkg" {
		t.Errorf("Packages = %v, want the two package names only", op.Packages)
	}
	if len(op.Flags) != 1 || op.Flags[0] != "--needed" {
		t.Errorf("Flags = %v, want [--needed]", op.Flags)
	}
}

// TestFlagValuesAreNotPackageNames covers the argument that belongs to the flag
// before it. `--answerdiff None` filed "None" as a package, and yay-friend went
// looking for one -- offering a search selection, or under --noconfirm failing
// outright. Both branches of ParseYayCommand had it.
func TestFlagValuesAreNotPackageNames(t *testing.T) {
	for _, tc := range []struct {
		name         string
		args         []string
		wantPackages []string
		wantFlags    []string
	}{
		{
			"operation branch",
			[]string{"-S", "--answerdiff", "None", "pkg"},
			[]string{"pkg"},
			[]string{"--answerdiff", "None"},
		},
		{
			"bare package branch",
			[]string{"pkg", "--answerdiff", "None"},
			[]string{"pkg"},
			[]string{"--answerdiff", "None"},
		},
		{
			"value-less flag keeps the package",
			[]string{"-S", "--needed", "pkg"},
			[]string{"pkg"},
			[]string{"--needed"},
		},
		{
			"joined form needs no lookahead",
			[]string{"-S", "--answerdiff=None", "pkg"},
			[]string{"pkg"},
			[]string{"--answerdiff=None"},
		},
		{
			"trailing value-taking flag does not run off the end",
			[]string{"-S", "pkg", "--builddir"},
			[]string{"pkg"},
			[]string{"--builddir"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			op, err := ParseYayCommand(tc.args)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(op.Packages, tc.wantPackages) {
				t.Errorf("Packages = %v, want %v", op.Packages, tc.wantPackages)
			}
			if !reflect.DeepEqual(op.Flags, tc.wantFlags) {
				t.Errorf("Flags = %v, want %v", op.Flags, tc.wantFlags)
			}
		})
	}
}
