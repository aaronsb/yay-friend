package yay

import (
	"context"
	"os"
	"path/filepath"
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
