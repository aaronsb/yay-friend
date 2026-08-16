package yay

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/aaronsb/yay-friend/internal/pkgbuild"
	"github.com/aaronsb/yay-friend/internal/types"
	"github.com/aaronsb/yay-friend/internal/ui"
)

// PackageSearchResult represents a search result from yay
type PackageSearchResult struct {
	Repository  string `json:"repository"`
	Name        string `json:"name"`
	Version     string `json:"version"`
	Info        string `json:"info"` // Vote count, popularity, etc
	Description string `json:"description"`
}

// YayClient handles interactions with the yay command
type YayClient struct {
	yayPath string
}

// NewYayClient creates a new yay client
func NewYayClient(yayPath string) *YayClient {
	if yayPath == "" {
		yayPath = "yay"
	}
	return &YayClient{yayPath: yayPath}
}

// IsAvailable checks if yay is available on the system
func (y *YayClient) IsAvailable() error {
	_, err := exec.LookPath(y.yayPath)
	if err != nil {
		return fmt.Errorf("yay not found: %w", err)
	}
	return nil
}

// GetPackageInfo fetches PKGBUILD and metadata for a package
func (y *YayClient) GetPackageInfo(ctx context.Context, packageName string) (*types.PackageInfo, error) {
	src, err := y.fetchPKGBUILD(ctx, packageName)
	if err != nil {
		return nil, err
	}

	// Parse PKGBUILD for metadata. Name stays as the caller requested it: for a
	// split package the requested name is the authoritative one, and it need not
	// be the first entry of the pkgname array.
	info := &types.PackageInfo{
		Name:       packageName,
		PKGBUILD:   src,
		Maintainer: "Unknown",
	}

	// A PKGBUILD that will not parse is not fatal here -- the raw source still
	// reaches the analyzer, which is the part that matters for a security review.
	// It is worth saying out loud though: this path ends in an install, and a
	// PKGBUILD that will not parse as shell is itself a reason to look closer.
	vars, perr := pkgbuild.Parse(src)
	if perr != nil {
		fmt.Fprintf(os.Stderr, "Warning: %s has a PKGBUILD that does not parse as shell (%v); metadata unavailable, analyzing raw source\n", packageName, perr)
		return info, nil
	}

	info.Version = vars.Str("pkgver")
	info.Description = vars.Str("pkgdesc")
	info.URL = vars.Str("url")
	info.Maintainer = vars.Maintainer()

	return info, nil
}

// fetchPKGBUILD returns the PKGBUILD source yay holds for a package.
//
// yay resolves a binary repository ahead of the AUR, so for a package carried by
// both -- an AUR package that some third-party repo also ships prebuilt -- the
// default fetch asks Arch's packaging GitLab for a project that was never there.
// GitLab answers that with a redirect to its sign-in page, and yay prints those
// 19 KB of HTML as though they were the PKGBUILD. It exits 0 doing so, as it does
// for every other failure on this path ("Unable to find the following packages"
// is also a clean exit), which leaves the returned content as the only signal
// worth reading. So: check what came back, and ask the AUR directly before
// concluding there is nothing to analyze.
func (y *YayClient) fetchPKGBUILD(ctx context.Context, packageName string) (string, error) {
	src, err := y.printPKGBUILD(ctx, packageName)
	if err == nil && pkgbuild.LooksLike(src) {
		return src, nil
	}

	// --aur is the fallback rather than the default because it is the narrower
	// question: it fails outright for the official packages the plain fetch
	// serves correctly.
	aurSrc, aurErr := y.printPKGBUILD(ctx, packageName, "--aur")
	if aurErr == nil && pkgbuild.LooksLike(aurSrc) {
		ui.Warn("%s: the repository source returned no PKGBUILD; analyzing the AUR PKGBUILD instead", packageName)
		return aurSrc, nil
	}

	if err != nil {
		return "", fmt.Errorf("failed to get PKGBUILD for %s: %w", packageName, err)
	}
	// Refusing here is the point. The caller's next move is to hand this to an
	// analyzer and report a verdict on it, and a verdict rendered over a sign-in
	// page reads exactly like a verdict rendered over a clean package.
	return "", fmt.Errorf("no PKGBUILD found for %s: yay returned %d bytes declaring no pkgname", packageName, len(strings.TrimSpace(src)))
}

// printPKGBUILD runs `yay -G --print` and returns its stdout verbatim.
func (y *YayClient) printPKGBUILD(ctx context.Context, packageName string, extraArgs ...string) (string, error) {
	args := append([]string{"-G", "--print"}, extraArgs...)
	args = append(args, packageName)

	output, err := exec.CommandContext(ctx, y.yayPath, args...).Output()
	return string(output), err
}

// InstallPackages runs yay to install packages
func (y *YayClient) InstallPackages(ctx context.Context, operation *types.YayOperation) error {
	args := []string{operation.Command}
	args = append(args, operation.Flags...)
	args = append(args, operation.Packages...)

	cmd := exec.CommandContext(ctx, y.yayPath, args...)
	// Wire yay directly to our terminal so it can run interactively — sudo
	// password, PKGBUILD review, and confirmation prompts. (In os/exec, a nil
	// std stream means /dev/null, not "inherit"; we must assign os.Std* here.)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}

// SearchPackages searches for packages and returns structured results
func (y *YayClient) SearchPackages(ctx context.Context, query string) ([]PackageSearchResult, error) {
	cmd := exec.CommandContext(ctx, y.yayPath, "-Ss", query)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("search failed: %w", err)
	}

	// Parse search results
	var results []PackageSearchResult
	scanner := bufio.NewScanner(strings.NewReader(string(output)))

	// Regex patterns for parsing yay output
	packageRe := regexp.MustCompile(`^([a-zA-Z0-9][a-zA-Z0-9._+-]*)/([a-zA-Z0-9][a-zA-Z0-9._+-]*)\s+([^\s]+)\s+(.*)`)

	for scanner.Scan() {
		line := scanner.Text()
		if matches := packageRe.FindStringSubmatch(line); len(matches) >= 5 {
			// Parse the repo/package version info line
			repo := matches[1]
			name := matches[2]
			version := matches[3]
			info := matches[4]

			// Get description from next line if available
			var description string
			if scanner.Scan() {
				descLine := scanner.Text()
				description = strings.TrimSpace(descLine)
			}

			results = append(results, PackageSearchResult{
				Repository:  repo,
				Name:        name,
				Version:     version,
				Info:        info,
				Description: description,
			})
		}
	}

	return results, nil
}

// valueTakingFlags are the pacman and yay long options whose value is a
// separate argument. Without them the value lands in the package list: with
// `-S --answerdiff None pkg`, "None" became a package name, and yay-friend went
// off to analyze a package by that name.
//
// The list is deliberately partial and conservative, covering the options that
// take a value in pacman(8) and yay(8). Being wrong in the other direction is
// the expensive mistake -- naming an option here that takes no value would eat
// the package after it -- so an option is listed only when its value argument is
// certain. Anything missing degrades to the old behaviour for that one option,
// which surfaces as a visible "package not found", not as a silent wrong action.
var valueTakingFlags = map[string]bool{
	// pacman(8)
	"--config": true, "--dbpath": true, "--root": true, "--cachedir": true,
	"--gpgdir": true, "--hookdir": true, "--logfile": true, "--arch": true,
	"--color": true, "--ignore": true, "--ignoregroup": true,
	"--assume-installed": true, "--print-format": true, "--sysroot": true,
	"--overwrite": true,
	// yay(8)
	"--answerclean": true, "--answerdiff": true, "--answeredit": true,
	"--answerupgrade": true, "--builddir": true, "--editor": true,
	"--editorflags": true, "--makepkg": true, "--mflags": true, "--pacman": true,
	"--git": true, "--gitflags": true, "--gpg": true, "--gpgflags": true,
	"--sudo": true, "--sudoflags": true, "--requestsplitn": true,
	"--completioninterval": true, "--sortby": true, "--searchby": true,
	"--aururl": true, "--aurrpcurl": true, "--limit": true,
	"--makepkgconf": true, "--pacmanconf": true,
}

// takesValue reports whether flag consumes the argument after it.
func takesValue(flag string) bool {
	// `--opt=value` carries its own value; only the separated form can strand one.
	if strings.Contains(flag, "=") {
		return false
	}
	return valueTakingFlags[flag]
}

// splitFlagsAndPackages files each argument as a flag or a package name.
//
// A flag's value goes with the flag: `--answerdiff None` is one option and its
// argument, not an option and a package called "None". Both branches of
// ParseYayCommand share this so they cannot disagree about which is which.
func splitFlagsAndPackages(args []string, operation *types.YayOperation) {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if !strings.HasPrefix(arg, "-") {
			operation.Packages = append(operation.Packages, arg)
			continue
		}
		operation.Flags = append(operation.Flags, arg)
		if takesValue(arg) && i+1 < len(args) {
			operation.Flags = append(operation.Flags, args[i+1])
			i++
		}
	}
}

// ParseYayCommand parses a yay command into a YayOperation.
func ParseYayCommand(args []string) (*types.YayOperation, error) {
	if len(args) == 0 {
		return &types.YayOperation{
			Command:   "-Syu", // Default yay behavior
			Operation: "upgrade",
		}, nil
	}

	// Check if first argument is a flag or a package name
	if strings.HasPrefix(args[0], "-") {
		// First arg is a flag, standard yay command
		operation := &types.YayOperation{
			Command:  args[0],
			Flags:    []string{},
			Packages: []string{},
		}

		// Determine operation type
		if strings.HasPrefix(operation.Command, "-S") {
			operation.Operation = "install"
		} else if strings.HasPrefix(operation.Command, "-R") {
			operation.Operation = "remove"
		} else if strings.HasPrefix(operation.Command, "-U") {
			operation.Operation = "upgrade"
		} else {
			operation.Operation = "other"
		}

		// Separate flags from packages
		splitFlagsAndPackages(args[1:], operation)

		return operation, nil
	} else {
		// First arg is not a flag, assume it's just analysis (no install)
		operation := &types.YayOperation{
			Command:   "", // No command means analyze-only
			Operation: "analyze",
			Flags:     []string{},
			Packages:  []string{},
		}

		// Flags are separated here for the same reason as above. Filing every
		// argument as a package name meant `yay-friend pkg --needed` went looking
		// for a package called "--needed", found none, and offered a search.
		splitFlagsAndPackages(args, operation)

		return operation, nil
	}
}
