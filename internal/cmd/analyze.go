package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/aaronsb/yay-friend/internal/aur"
	"github.com/aaronsb/yay-friend/internal/cache"
	"github.com/aaronsb/yay-friend/internal/config"
	"github.com/aaronsb/yay-friend/internal/pkgbuild"
	"github.com/aaronsb/yay-friend/internal/providers"
	"github.com/aaronsb/yay-friend/internal/types"
	"github.com/aaronsb/yay-friend/internal/ui"
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

	ui.Say("analyzing %s with %s", packageName, aiProvider.Name())

	// Get package info
	pkgInfo, err := yayClient.GetPackageInfo(ctx, packageName)
	if err != nil {
		return fmt.Errorf("failed to get package info: %w", err)
	}

	// Fetch additional AUR context (including commit hash)
	ui.Say("fetching AUR context")
	aurFetcher := aur.NewAURFetcher()
	if err := aurFetcher.EnrichPackageInfo(ctx, pkgInfo); err != nil {
		ui.Warn("could not enrich with AUR context: %v", err)
	}

	// Initialize cache manager
	cacheManager, err := cache.NewCacheManager()
	if err != nil {
		ui.Warn("could not initialize cache: %v", err)
		// Continue without caching
	}

	// Check cache first if enabled and we have commit hash and cache manager
	var analysis *types.SecurityAnalysis
	if cfg.Cache.Enabled && cacheManager != nil && pkgInfo.CommitHash != "" {
		cachedAnalysis, cacheErr := cacheManager.GetCachedAnalysis(pkgInfo.Name, pkgInfo.CommitHash)
		if cacheErr == nil {
			ui.Say("using cached analysis (commit %s)", pkgInfo.CommitHash[:8])
			analysis = cachedAnalysis
		} else {
			ui.Say("running fresh analysis (commit %s)", pkgInfo.CommitHash[:8])
			// Cache miss - continue to run AI analysis
		}
	}

	// If no cached analysis found, run AI analysis
	if analysis == nil {
		// Display what we collected for analysis
		ui.RenderCollected(pkgInfo)

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
				ui.Warn("could not save analysis to cache: %v", cacheErr)
			}
		}
	}

	// Display detailed results
	ui.RenderAnalysis(analysis, true)

	return nil
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
	info, err := os.ReadFile(path)
	var pkgbuildPath string
	var pkgbuildContent []byte

	if err == nil {
		// Path is a file
		pkgbuildPath = path
		pkgbuildContent = info
	} else {
		// Try as directory
		pkgbuildPath = filepath.Join(path, "PKGBUILD")
		pkgbuildContent, err = os.ReadFile(pkgbuildPath)
		if err != nil {
			return fmt.Errorf("failed to read PKGBUILD: %w", err)
		}
	}

	ui.Say("analyzing local PKGBUILD %s with %s", pkgbuildPath, aiProvider.Name())
	ui.Say("local PKGBUILD analysis is not cached")

	// Parse basic package info from PKGBUILD
	pkgInfo, vars := parseLocalPKGBUILD(string(pkgbuildContent), pkgbuildPath)

	// Try to read additional files from the same directory
	dir := filepath.Dir(pkgbuildPath)
	pkgInfo.AdditionalFiles = make(map[string]string)

	// Companion files are only discoverable when the PKGBUILD parses; an
	// unparseable one still gets analyzed on its own source above.
	var installScriptPath string
	if vars != nil {
		// Look for .install script
		installScriptPath = findInstallScript(vars, dir)
		if installScriptPath != "" {
			if content, err := os.ReadFile(installScriptPath); err == nil {
				pkgInfo.InstallScript = string(content)
				pkgInfo.AdditionalFiles[filepath.Base(installScriptPath)] = string(content)
			}
		}

		// Look for other referenced files (like shell scripts)
		for _, file := range findAdditionalFiles(vars, dir) {
			if content, err := os.ReadFile(filepath.Join(dir, file)); err == nil {
				pkgInfo.AdditionalFiles[file] = string(content)
			}
		}
	}

	// Display what we collected for analysis
	ui.RenderCollected(&pkgInfo)

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
	ui.RenderAnalysis(analysis, true)

	return nil
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
