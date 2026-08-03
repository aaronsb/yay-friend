package yay

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/aaronsb/yay-friend/internal/types"
)

// PackageSearchResult represents a search result from yay
type PackageSearchResult struct {
	Repository  string `json:"repository"`
	Name        string `json:"name"`
	Version     string `json:"version"`
	Info        string `json:"info"`        // Vote count, popularity, etc
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
	// Get PKGBUILD content
	cmd := exec.CommandContext(ctx, y.yayPath, "-G", "--print", packageName)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get PKGBUILD for %s: %w", packageName, err)
	}

	pkgbuild := string(output)
	
	// Parse PKGBUILD for metadata
	info := &types.PackageInfo{
		Name:     packageName,
		PKGBUILD: pkgbuild,
	}

	// Extract metadata from PKGBUILD
	info.Version = extractPKGBUILDField(pkgbuild, "pkgver")
	info.Description = extractPKGBUILDField(pkgbuild, "pkgdesc")
	info.URL = extractPKGBUILDField(pkgbuild, "url")
	info.Maintainer = extractMaintainer(pkgbuild)

	return info, nil
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

// ParseYayCommand parses a yay command into a YayOperation
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
			Command: args[0],
			Flags:   []string{},
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
		for i := 1; i < len(args); i++ {
			arg := args[i]
			if strings.HasPrefix(arg, "-") {
				operation.Flags = append(operation.Flags, arg)
			} else {
				operation.Packages = append(operation.Packages, arg)
			}
		}

		return operation, nil
	} else {
		// First arg is not a flag, assume it's just analysis (no install)
		return &types.YayOperation{
			Command:   "", // No command means analyze-only
			Operation: "analyze",
			Flags:     []string{},
			Packages:  args, // All args are packages
		}, nil
	}
}

// extractPKGBUILDField extracts a field value from PKGBUILD content
func extractPKGBUILDField(pkgbuild, field string) string {
	re := regexp.MustCompile(fmt.Sprintf(`%s\s*=\s*['"]?([^'"'\n\r]*)['"]?`, field))
	matches := re.FindStringSubmatch(pkgbuild)
	if len(matches) >= 2 {
		return strings.Trim(matches[1], "\"'")
	}
	return ""
}

// extractMaintainer extracts maintainer info from PKGBUILD comments
func extractMaintainer(pkgbuild string) string {
	re := regexp.MustCompile(`#\s*[Mm]aintainer:\s*(.+)`)
	matches := re.FindStringSubmatch(pkgbuild)
	if len(matches) >= 2 {
		return strings.TrimSpace(matches[1])
	}
	return "Unknown"
}