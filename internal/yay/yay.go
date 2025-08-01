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
	cmd.Stdout = nil // Let it inherit our stdout for interactive behavior
	cmd.Stderr = nil // Let it inherit our stderr
	cmd.Stdin = nil  // Let it inherit our stdin

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

// InteractiveSearch performs interactive package selection like yay
func (y *YayClient) InteractiveSearch(ctx context.Context, query string) ([]string, error) {
	// Let yay handle the interactive search and capture the selection
	fmt.Printf("🔍 Searching for packages matching '%s'...\n", query)
	
	// Run yay in interactive mode and let it handle selection
	cmd := exec.CommandContext(ctx, y.yayPath, query)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	
	// This will return after user makes selection or cancels
	err := cmd.Run()
	if err != nil {
		// User likely cancelled (Ctrl+C)
		return nil, fmt.Errorf("search cancelled or failed: %w", err)
	}
	
	// If we get here, yay would have proceeded with installation
	// But we've intercepted it, so we need to parse what was selected
	// This is tricky - we'd need to capture yay's selection somehow
	
	// For now, return empty to indicate we need a different approach
	return nil, fmt.Errorf("interactive search completed, but package selection capture not implemented")
}

// CheckDependencies checks if packages exist and can be installed
func (y *YayClient) CheckDependencies(ctx context.Context, packages []string) error {
	for _, pkg := range packages {
		cmd := exec.CommandContext(ctx, y.yayPath, "-Si", pkg)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("package %s not found or not available: %w", pkg, err)
		}
	}
	return nil
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
		// First arg is not a flag, assume it's a package search/install
		return &types.YayOperation{
			Command:   "-S", // Default to install
			Operation: "install",
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