package cmd

import (
	"context"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/gookit/color"
	"github.com/spf13/cobra"

	"github.com/aaronsb/yay-friend/internal/aur"
	"github.com/aaronsb/yay-friend/internal/cache"
	"github.com/aaronsb/yay-friend/internal/config"
	"github.com/aaronsb/yay-friend/internal/providers"
	"github.com/aaronsb/yay-friend/internal/types"
	"github.com/aaronsb/yay-friend/internal/yay"
)

var fileFlag string

// newAnalyzeCmd creates the analyze command
func newAnalyzeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "analyze <package-or-path>",
		Short: "Analyze a package without installing it",
		Long: `Analyze a package's PKGBUILD for security issues without installing it.
This is useful for checking packages before deciding whether to install them.

You can analyze:
  - AUR packages by name: yay-friend analyze package-name
  - Local PKGBUILD files: yay-friend analyze --file /path/to/PKGBUILD
  - Local directories: yay-friend analyze --file /path/to/package-dir/`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if fileFlag != "" {
				return runAnalyzeLocal(cmd.Context(), fileFlag)
			}
			if len(args) == 0 {
				return fmt.Errorf("please specify a package name or use --file flag")
			}
			return runAnalyze(cmd.Context(), args[0])
		},
	}

	cmd.Flags().StringVar(&fileFlag, "file", "", "Analyze a local PKGBUILD file or directory")

	return cmd
}

func runAnalyze(ctx context.Context, packageName string) error {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Initialize yay client
	yayClient := yay.NewYayClient(cfg.Yay.Path)
	if err := yayClient.IsAvailable(); err != nil {
		return fmt.Errorf("yay not available: %w", err)
	}

	// Initialize providers
	registry := providers.NewProviderRegistry()
	claudeProvider := providers.NewClaudeProvider()
	claudeProvider.SetConfig(cfg)
	registry.Register("claude", claudeProvider)
	registry.Register("qwen", providers.NewQwenProvider())
	registry.Register("copilot", providers.NewCopilotProvider())
	registry.Register("goose", providers.NewGooseProvider())

	// Determine which provider to use
	providerName := provider
	if providerName == "" {
		providerName = cfg.DefaultProvider
	}
	if providerName == "" {
		providerName = "claude"
	}

	aiProvider, err := registry.Get(providerName)
	if err != nil {
		return fmt.Errorf("provider error: %w", err)
	}

	// Authenticate provider
	if err := aiProvider.Authenticate(ctx); err != nil {
		return fmt.Errorf("authentication failed for %s: %w", providerName, err)
	}

	fmt.Printf("🔍 Analyzing %s with %s...\n", packageName, aiProvider.Name())

	// Get package info
	pkgInfo, err := yayClient.GetPackageInfo(ctx, packageName)
	if err != nil {
		return fmt.Errorf("failed to get package info: %w", err)
	}

	// Fetch additional AUR context (including commit hash)
	fmt.Printf("Fetching AUR context...\n")
	aurFetcher := aur.NewAURFetcher()
	if err := aurFetcher.EnrichPackageInfo(ctx, pkgInfo); err != nil {
		fmt.Printf("Warning: Could not enrich with AUR context: %v\n", err)
	}

	// Initialize cache manager
	cacheManager, err := cache.NewCacheManager()
	if err != nil {
		fmt.Printf("Warning: Could not initialize cache: %v\n", err)
		// Continue without caching
	}

	// Check cache first if enabled and we have commit hash and cache manager
	var analysis *types.SecurityAnalysis
	if cfg.Cache.Enabled && cacheManager != nil && pkgInfo.CommitHash != "" {
		cachedAnalysis, cacheErr := cacheManager.GetCachedAnalysis(pkgInfo.Name, pkgInfo.CommitHash)
		if cacheErr == nil {
			fmt.Printf("📋 Using cached analysis (commit: %s)\n", pkgInfo.CommitHash[:8])
			analysis = cachedAnalysis
		} else {
			fmt.Printf("🤖 Running fresh analysis (commit: %s)\n", pkgInfo.CommitHash[:8])
			// Cache miss - continue to run AI analysis
		}
	}

	// If no cached analysis found, run AI analysis
	if analysis == nil {
		// Display what we collected for analysis
		displayCollectedDataAnalyze(pkgInfo)

		// Analyze security with options (support --no-spinner)
		// Check if provider supports options (for Claude)
		if claudeProvider, ok := aiProvider.(*providers.ClaudeProvider); ok {
			analysis, err = claudeProvider.AnalyzePKGBUILDWithOptions(ctx, *pkgInfo, noSpinner)
		} else {
			analysis, err = aiProvider.AnalyzePKGBUILD(ctx, *pkgInfo)
		}
		
		if err != nil {
			return fmt.Errorf("analysis failed: %w", err)
		}

		// Save to cache if enabled and available
		if cfg.Cache.Enabled && cacheManager != nil && pkgInfo.CommitHash != "" {
			if cacheErr := cacheManager.SaveAnalysis(pkgInfo.Name, pkgInfo.CommitHash, analysis); cacheErr != nil {
				fmt.Printf("Warning: Could not save analysis to cache: %v\n", cacheErr)
			}
		}
	}

	// Display detailed results
	displayDetailedAnalysis(analysis)

	return nil
}

func displayDetailedAnalysis(analysis *types.SecurityAnalysis) {
	fmt.Printf("\n%s\n", strings.Repeat("=", 60))
	fmt.Printf("Security Analysis for %s\n", analysis.PackageName)
	fmt.Printf("%s\n", strings.Repeat("=", 60))
	fmt.Printf("Provider: %s\n", analysis.Provider)
	fmt.Printf("Analyzed: %s\n", analysis.AnalyzedAt.Format("2006-01-02 15:04:05"))
	fmt.Printf("Overall Level: %s\n", getColoredLevel(analysis.OverallLevel))
	fmt.Printf("\nSummary:\n%s\n", analysis.Summary)
	
	if analysis.Recommendation != "" {
		fmt.Printf("\nRecommendation: %s\n", analysis.Recommendation)
	}

	if len(analysis.Findings) > 0 {
		fmt.Printf("\nDetailed Findings:\n")
		fmt.Printf("%s\n", strings.Repeat("-", 40))
		for i, finding := range analysis.Findings {
			fmt.Printf("%d. [%s] %s\n", i+1, getColoredLevel(finding.Severity), finding.Type)
			fmt.Printf("   %s\n", finding.Description)
			
			if finding.LineNumber > 0 {
				fmt.Printf("   Line: %d\n", finding.LineNumber)
			}
			
			if finding.Context != "" {
				fmt.Printf("   Context: %s\n", finding.Context)
			}
			
			if finding.Suggestion != "" {
				fmt.Printf("   💡 %s\n", finding.Suggestion)
			}
			fmt.Println()
		}
	} else {
		fmt.Println("\n✅ No security issues found!")
	}
}

func getColoredLevel(level types.SecurityLevel) string {
	// For now, just return the string. We'll add colors when we implement the TUI
	return level.String()
}

// displayCollectedDataAnalyze shows what information we gathered for analysis (analyze command version)
func displayCollectedDataAnalyze(pkgInfo *types.PackageInfo) {
	fmt.Printf("\n")
	color.Bold.Printf("Collected for Analysis:\n")
	fmt.Printf("─────────────────────────\n")
	
	// PKGBUILD stats
	pkgbuildLines := len(strings.Split(pkgInfo.PKGBUILD, "\n"))
	fmt.Printf("• PKGBUILD: %d lines of shell script\n", pkgbuildLines)
	
	// Package metadata
	fmt.Printf("• Package metadata: %s v%s by %s\n", pkgInfo.Name, pkgInfo.Version, pkgInfo.Maintainer)
	
	// Dependencies
	if len(pkgInfo.Dependencies) > 0 {
		fmt.Printf("• Runtime dependencies: %d packages (%s)\n", 
			len(pkgInfo.Dependencies), truncateListAnalyze(pkgInfo.Dependencies, 3))
	}
	if len(pkgInfo.MakeDepends) > 0 {
		fmt.Printf("• Build dependencies: %d packages (%s)\n", 
			len(pkgInfo.MakeDepends), truncateListAnalyze(pkgInfo.MakeDepends, 3))
	}
	
	// AUR history
	if pkgInfo.FirstSubmitted != "" && pkgInfo.LastUpdated != "" {
		fmt.Printf("• AUR history: submitted %s, last updated %s\n", 
			pkgInfo.FirstSubmitted, pkgInfo.LastUpdated)
	}
	
	// Community engagement
	if pkgInfo.Votes > 0 || pkgInfo.Popularity > 0 {
		fmt.Printf("• Community: %d votes, %.3f popularity score\n", 
			pkgInfo.Votes, pkgInfo.Popularity) 
	}
	
	// Optional dependencies
	if len(pkgInfo.OptDepends) > 0 {
		fmt.Printf("• Optional dependencies: %d packages\n", len(pkgInfo.OptDepends))
	}
	
	fmt.Printf("\n")
}

// truncateListAnalyze truncates a string slice for display (analyze command version)
func truncateListAnalyze(items []string, maxItems int) string {
	if len(items) <= maxItems {
		return strings.Join(items, ", ")
	}
	return strings.Join(items[:maxItems], ", ") + fmt.Sprintf(" (+%d more)", len(items)-maxItems)
}

// runAnalyzeLocal analyzes a local PKGBUILD file or directory
func runAnalyzeLocal(ctx context.Context, path string) error {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Initialize providers
	registry := providers.NewProviderRegistry()
	claudeProvider := providers.NewClaudeProvider()
	claudeProvider.SetConfig(cfg)
	registry.Register("claude", claudeProvider)
	registry.Register("qwen", providers.NewQwenProvider())
	registry.Register("copilot", providers.NewCopilotProvider())
	registry.Register("goose", providers.NewGooseProvider())

	// Determine which provider to use
	providerName := provider
	if providerName == "" {
		providerName = cfg.DefaultProvider
	}
	if providerName == "" {
		providerName = "claude"
	}

	aiProvider, err := registry.Get(providerName)
	if err != nil {
		return fmt.Errorf("provider error: %w", err)
	}

	// Authenticate provider
	if err := aiProvider.Authenticate(ctx); err != nil {
		return fmt.Errorf("authentication failed for %s: %w", providerName, err)
	}

	// Determine if path is a file or directory
	info, err := ioutil.ReadFile(path)
	var pkgbuildPath string
	var pkgbuildContent []byte
	
	if err == nil {
		// Path is a file
		pkgbuildPath = path
		pkgbuildContent = info
	} else {
		// Try as directory
		pkgbuildPath = filepath.Join(path, "PKGBUILD")
		pkgbuildContent, err = ioutil.ReadFile(pkgbuildPath)
		if err != nil {
			return fmt.Errorf("failed to read PKGBUILD: %w", err)
		}
	}

	fmt.Printf("🔍 Analyzing local PKGBUILD: %s with %s...\n", pkgbuildPath, aiProvider.Name())
	fmt.Printf("Note: Local PKGBUILD analysis is not cached\n")

	// Parse basic package info from PKGBUILD
	pkgInfo := parseLocalPKGBUILD(string(pkgbuildContent), pkgbuildPath)
	
	// Try to read additional files from the same directory
	dir := filepath.Dir(pkgbuildPath)
	pkgInfo.AdditionalFiles = make(map[string]string)
	
	// Look for .install script
	installScriptPath := findInstallScript(string(pkgbuildContent), dir)
	if installScriptPath != "" {
		if content, err := ioutil.ReadFile(installScriptPath); err == nil {
			pkgInfo.InstallScript = string(content)
			pkgInfo.AdditionalFiles[filepath.Base(installScriptPath)] = string(content)
		}
	}
	
	// Look for other referenced files (like shell scripts)
	additionalFiles := findAdditionalFiles(string(pkgbuildContent), dir)
	for _, file := range additionalFiles {
		filePath := filepath.Join(dir, file)
		if content, err := ioutil.ReadFile(filePath); err == nil {
			pkgInfo.AdditionalFiles[file] = string(content)
		}
	}

	// Display what we collected for analysis
	displayCollectedDataAnalyze(&pkgInfo)
	
	// Show if we found additional files
	if len(pkgInfo.AdditionalFiles) > 0 {
		fmt.Printf("• Additional files found: ")
		var fileNames []string
		for name := range pkgInfo.AdditionalFiles {
			fileNames = append(fileNames, name)
		}
		fmt.Printf("%s\n", strings.Join(fileNames, ", "))
	}
	if pkgInfo.InstallScript != "" {
		fmt.Printf("• Install script: %s\n", filepath.Base(installScriptPath))
	}

	// Analyze security
	var analysis *types.SecurityAnalysis
	if claudeProvider, ok := aiProvider.(*providers.ClaudeProvider); ok {
		analysis, err = claudeProvider.AnalyzePKGBUILDWithOptions(ctx, pkgInfo, noSpinner)
	} else {
		analysis, err = aiProvider.AnalyzePKGBUILD(ctx, pkgInfo)
	}
	
	if err != nil {
		return fmt.Errorf("analysis failed: %w", err)
	}

	// Display detailed results
	displayDetailedAnalysis(analysis)

	return nil
}
// parseLocalPKGBUILD extracts basic package information from a PKGBUILD
func parseLocalPKGBUILD(content string, path string) types.PackageInfo {
	info := types.PackageInfo{
		PKGBUILD: content,
	}
	
	// Extract package name
	if match := extractBashVar(content, "pkgname"); match != "" {
		info.Name = match
	}
	
	// Extract version
	if match := extractBashVar(content, "pkgver"); match != "" {
		info.Version = match
	}
	
	// Extract description
	if match := extractBashVar(content, "pkgdesc"); match != "" {
		info.Description = match
	}
	
	// Extract maintainer from comments
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "# Maintainer:") {
			info.Maintainer = strings.TrimSpace(strings.TrimPrefix(line, "# Maintainer:"))
			break
		}
	}
	
	// Extract dependencies
	if deps := extractBashArray(content, "depends"); deps != nil {
		info.Dependencies = deps
	}
	
	// Extract make dependencies
	if deps := extractBashArray(content, "makedepends"); deps != nil {
		info.MakeDepends = deps
	}
	
	// Set defaults for local analysis
	info.AURPageURL = "Local PKGBUILD"
	info.LastUpdated = "Not available (local PKGBUILD)"
	info.FirstSubmitted = "Not available (local PKGBUILD)"
	
	return info
}

// extractBashVar extracts a simple bash variable value
func extractBashVar(content, varName string) string {
	// Look for pattern: varName=value or varName="value" or varName='value'
	patterns := []string{
		varName + `=['"]([^'"]+)['"]`,
		varName + `=([^\s]+)`,
	}
	
	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		if matches := re.FindStringSubmatch(content); len(matches) > 1 {
			return matches[1]
		}
	}
	
	return ""
}

// extractBashArray extracts a bash array
func extractBashArray(content, varName string) []string {
	// Look for pattern: varName=(item1 item2 item3)
	re := regexp.MustCompile(varName + `=\(([^)]+)\)`)
	if matches := re.FindStringSubmatch(content); len(matches) > 1 {
		// Parse the array content
		items := strings.Fields(matches[1])
		var result []string
		for _, item := range items {
			// Remove quotes if present
			item = strings.Trim(item, `'"`)
			if item != "" {
				result = append(result, item)
			}
		}
		return result
	}
	
	return nil
}

// findInstallScript looks for the install script referenced in PKGBUILD
func findInstallScript(pkgbuild, dir string) string {
	// Look for install=filename pattern (with or without quotes)
	re := regexp.MustCompile(`install=(['"]?)([^'"\s]+)(['"]?)`)
	if matches := re.FindStringSubmatch(pkgbuild); len(matches) > 2 {
		installFile := matches[2]
		installPath := filepath.Join(dir, installFile)
		if _, err := ioutil.ReadFile(installPath); err == nil {
			return installPath
		}
	}
	
	return ""
}

// findAdditionalFiles finds other files referenced in the PKGBUILD
func findAdditionalFiles(pkgbuild, dir string) []string {
	var files []string
	
	// Look in source array (can be multi-line)
	re := regexp.MustCompile(`(?s)source=\(([^)]+)\)`)
	if matches := re.FindStringSubmatch(pkgbuild); len(matches) > 1 {
		// Split by newlines and whitespace, clean up quotes
		sourceContent := matches[1]
		// Replace newlines with spaces for easier parsing
		sourceContent = strings.ReplaceAll(sourceContent, "\n", " ")
		sourceContent = strings.ReplaceAll(sourceContent, "\t", " ")
		
		// Find quoted strings and unquoted tokens
		tokenRe := regexp.MustCompile(`(['"]?)([^'"\s]+)(['"]?)`)
		tokens := tokenRe.FindAllStringSubmatch(sourceContent, -1)
		
		for _, token := range tokens {
			item := token[2] // The actual value without quotes
			// Skip URLs
			if !strings.HasPrefix(item, "http://") && 
			   !strings.HasPrefix(item, "https://") && 
			   !strings.HasPrefix(item, "ftp://") {
				// If contains variable, try to expand it
				if strings.Contains(item, "$") {
					// Common variable: $_channel = stable
					expanded := strings.ReplaceAll(item, "$_channel", "stable")
					expanded = strings.ReplaceAll(expanded, "${_channel}", "stable")
					filePath := filepath.Join(dir, expanded)
					if _, err := ioutil.ReadFile(filePath); err == nil {
						files = append(files, expanded)
						continue
					}
				}
				
				// Check if file exists as-is
				filePath := filepath.Join(dir, item)
				if _, err := ioutil.ReadFile(filePath); err == nil {
					files = append(files, item)
				}
			}
		}
	}
	
	return files
}
