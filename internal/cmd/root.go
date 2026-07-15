package cmd

import (
	"context"
	"fmt"
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

var (
	cfgFile      string
	verbose      bool
	skipAnalysis bool
	provider     string
	noSpinner    bool
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "yay-friend [packages...]",
	Short: "A security-focused wrapper around yay",
	Long: `yay-friend is a security-focused wrapper around yay that uses AI to analyze 
PKGBUILD files for potential security issues before installation.

It acts as a security layer between you and the Arch User Repository (AUR),
analyzing packages for suspicious patterns, malicious code, and security risks.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runInstall(cmd.Context(), args)
	},
	// Allow unknown flags to be passed through to yay
	FParseErrWhitelist: cobra.FParseErrWhitelist{
		UnknownFlags: true,
	},
	// Disable the automatic 'help' command when no subcommand matches
	CompletionOptions: cobra.CompletionOptions{
		DisableDefaultCmd: true,
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute(ctx context.Context) error {
	return rootCmd.ExecuteContext(ctx)
}

func init() {
	cobra.OnInitialize(initConfig)

	// Global flags
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is ${XDG_CONFIG_HOME:-$HOME/.config}/yay-friend/config.yaml)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")
	rootCmd.PersistentFlags().BoolVar(&skipAnalysis, "skip-analysis", false, "skip security analysis and proceed directly to yay")
	rootCmd.PersistentFlags().StringVar(&provider, "provider", "", "AI provider to use (claude, qwen, copilot, goose)")
	rootCmd.PersistentFlags().BoolVar(&noSpinner, "no-spinner", false, "disable spinner animations (useful for scripts/automation)")

	// Add yay-compatible flags
	rootCmd.Flags().BoolP("sync", "S", false, "install packages")
	rootCmd.Flags().BoolP("remove", "R", false, "remove packages")
	rootCmd.Flags().BoolP("upgrade", "U", false, "upgrade packages")
	rootCmd.Flags().BoolP("query", "Q", false, "query packages")
	rootCmd.Flags().BoolP("files", "F", false, "query files")
	rootCmd.Flags().BoolP("database", "D", false, "database operations")
	rootCmd.Flags().BoolP("yay", "Y", false, "yay operations")

	// Add subcommands
	rootCmd.AddCommand(newAnalyzeCmd())
	rootCmd.AddCommand(newCacheCmd())
	rootCmd.AddCommand(newConfigCmd())
	rootCmd.AddCommand(newProviderCmd())
	rootCmd.AddCommand(newVersionCmd())
}

// initConfig wires the --config flag into the config package so that
// config.Load reads from the requested file (or the default path when empty).
func initConfig() {
	config.SetConfigPath(cfgFile)
}

// runInstall handles the main package installation workflow
func runInstall(ctx context.Context, args []string) error {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Debug config loading - only show in verbose mode
	if verbose {
		fmt.Printf("Config Debug - Default Provider: %s, Block Level: %d, Warn Level: %d\n",
			cfg.DefaultProvider, int(cfg.SecurityThresholds.BlockLevel), int(cfg.SecurityThresholds.WarnLevel))
	}

	// Parse yay command
	operation, err := yay.ParseYayCommand(args)
	if err != nil {
		return fmt.Errorf("failed to parse command: %w", err)
	}

	// Initialize yay client
	yayClient := yay.NewYayClient(cfg.Yay.Path)
	if err := yayClient.IsAvailable(); err != nil {
		return fmt.Errorf("yay not available: %w", err)
	}

	// If skip analysis or no packages to analyze, proceed directly
	if skipAnalysis || len(operation.Packages) == 0 {
		if operation.Operation == "analyze" {
			// For analyze-only mode, don't try to install
			return fmt.Errorf("no packages specified for analysis")
		}
		return yayClient.InstallPackages(ctx, operation)
	}

	// For non-install operations (like -Q, -R, etc.), pass through to yay
	if operation.Operation != "install" && operation.Operation != "analyze" {
		return yayClient.InstallPackages(ctx, operation)
	}

	// Handle potential search queries by checking if packages exist
	var finalPackages []string
	for _, pkg := range operation.Packages {
		// Try to get package info directly first
		_, err := yayClient.GetPackageInfo(ctx, pkg)
		if err != nil {
			// Package not found directly, might be a search query
			fmt.Printf("🔍 Package '%s' not found exactly, searching...\n", pkg)

			// Search for packages
			searchResults, searchErr := yayClient.SearchPackages(ctx, pkg)
			if searchErr != nil {
				return fmt.Errorf("search failed for '%s': %w", pkg, searchErr)
			}

			if len(searchResults) == 0 {
				return fmt.Errorf("no packages found matching '%s'", pkg)
			}

			// Present selection to user
			selectedPkgs, selectErr := presentPackageSelection(searchResults)
			if selectErr != nil {
				return selectErr
			}

			if len(selectedPkgs) == 0 {
				fmt.Println("Selection cancelled")
				return nil
			}

			finalPackages = append(finalPackages, selectedPkgs...)
		} else {
			// Package found directly
			finalPackages = append(finalPackages, pkg)
		}
	}

	// Update operation with final package list
	operation.Packages = finalPackages

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
		providerName = "claude" // Default fallback
	}

	aiProvider, err := registry.Get(providerName)
	if err != nil {
		return fmt.Errorf("provider error: %w", err)
	}

	// Authenticate provider
	if err := aiProvider.Authenticate(ctx); err != nil {
		return fmt.Errorf("authentication failed for %s: %w", providerName, err)
	}

	// Analyze packages
	allSafe := true
	for _, packageName := range operation.Packages {
		if err := analyzeAndDecide(ctx, yayClient, aiProvider, packageName, cfg); err != nil {
			return fmt.Errorf("analysis failed for %s: %w", packageName, err)
		}
	}

	// If we get here, all packages passed analysis
	if operation.Operation == "analyze" {
		// In analyze-only mode, ask user if they want to proceed with installation
		if allSafe {
			fmt.Printf("\n✅ All packages passed security analysis.\n")
			fmt.Printf("Would you like to proceed with installation? [y/N]: ")

			var response string
			fmt.Scanln(&response)
			response = strings.ToLower(strings.TrimSpace(response))

			if response == "y" || response == "yes" {
				// Change operation to install and proceed
				operation.Command = "-S"
				operation.Operation = "install"
				fmt.Printf("Proceeding with installation...\n")
				return yayClient.InstallPackages(ctx, operation)
			} else {
				fmt.Printf("Installation cancelled.\n")
				return nil
			}
		} else {
			fmt.Printf("\n⚠️  Security concerns found. Installation not recommended.\n")
			return nil
		}
	} else {
		// Regular install mode, proceed automatically if safe
		fmt.Printf("✅ All packages passed security analysis, proceeding with installation...\n")
		return yayClient.InstallPackages(ctx, operation)
	}
}

// analyzeAndDecide analyzes a package and decides whether to proceed
func analyzeAndDecide(ctx context.Context, yayClient *yay.YayClient, provider types.AIProvider, packageName string, cfg *types.Config) error {
	fmt.Printf("Analyzing %s...\n", packageName)

	// Get package info
	pkgInfo, err := yayClient.GetPackageInfo(ctx, packageName)
	if err != nil {
		return err
	}

	// Fetch additional AUR context (including commit hash)
	fmt.Printf("Fetching AUR context...\n")
	aurFetcher := aur.NewAURFetcher()
	if err := aurFetcher.EnrichPackageInfo(ctx, pkgInfo); err != nil {
		fmt.Printf("Warning: Could not enrich with AUR context: %v\n", err)
	} else {
		fmt.Printf("AUR context: %d votes, %.3f popularity, %d comments\n",
			pkgInfo.Votes, pkgInfo.Popularity, len(pkgInfo.Comments))
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
		displayCollectedData(pkgInfo)

		// Analyze security with enriched context
		// Check if provider supports options (for Claude)
		if claudeProvider, ok := provider.(*providers.ClaudeProvider); ok {
			analysis, err = claudeProvider.AnalyzePKGBUILDWithOptions(ctx, *pkgInfo, noSpinner)
		} else {
			analysis, err = provider.AnalyzePKGBUILD(ctx, *pkgInfo)
		}

		if err != nil {
			return err
		}

		// Save to cache if enabled and available
		if cfg.Cache.Enabled && cacheManager != nil && pkgInfo.CommitHash != "" {
			if cacheErr := cacheManager.SaveAnalysis(pkgInfo.Name, pkgInfo.CommitHash, analysis); cacheErr != nil {
				fmt.Printf("Warning: Could not save analysis to cache: %v\n", cacheErr)
			}
		}
	}

	// Display results and make decision
	return handleAnalysisResult(analysis, cfg)
}

// handleAnalysisResult processes the analysis result and makes a decision
func handleAnalysisResult(analysis *types.SecurityAnalysis, cfg *types.Config) error {
	// Display analysis summary with better formatting
	fmt.Printf("\n" + strings.Repeat("=", 60) + "\n")
	color.Bold.Print("Security Analysis Results: ")
	color.Magenta.Printf("%s\n", analysis.PackageName)
	fmt.Printf(strings.Repeat("=", 60) + "\n")

	// Display entropy level with color coding
	entropyIcon := getEntropyIcon(analysis.OverallLevel)
	fmt.Printf("Security Entropy: %s %s\n", entropyIcon, analysis.OverallLevel.String())

	if analysis.PredictabilityScore > 0 {
		fmt.Printf("Predictability Score: %.2f/1.0\n", analysis.PredictabilityScore)
	}

	if len(analysis.EntropyFactors) > 0 {
		fmt.Printf("Risk Factors: %s\n", strings.Join(analysis.EntropyFactors, ", "))
	}

	fmt.Printf("Summary: %s\n", analysis.Summary)

	// Show educational content
	if analysis.EducationalSummary != "" {
		fmt.Printf("\n")
		color.Bold.Printf("Security Education:\n")
		fmt.Printf(strings.Repeat("-", 60) + "\n")
		fmt.Printf("%s\n", analysis.EducationalSummary)
	}

	if len(analysis.SecurityLessons) > 0 {
		fmt.Printf("\n")
		color.Bold.Printf("Key Security Lessons:\n")
		for i, lesson := range analysis.SecurityLessons {
			fmt.Printf("   %d. %s\n", i+1, lesson)
		}
	}

	// Debug threshold comparison (only show if verbose mode)
	if verbose {
		fmt.Printf("\nDebug - Analysis Level: %d (%s), Block Threshold: %d (%s), Warn Threshold: %d (%s)\n",
			int(analysis.OverallLevel), analysis.OverallLevel.String(),
			int(cfg.SecurityThresholds.BlockLevel), cfg.SecurityThresholds.BlockLevel.String(),
			int(cfg.SecurityThresholds.WarnLevel), cfg.SecurityThresholds.WarnLevel.String())
	}

	// Check against thresholds
	if analysis.OverallLevel >= cfg.SecurityThresholds.BlockLevel {
		fmt.Printf("\nBLOCKED: Package security level (%s) exceeds block threshold (%s)\n",
			analysis.OverallLevel.String(), cfg.SecurityThresholds.BlockLevel.String())
		return fmt.Errorf("package %s blocked by security policy", analysis.PackageName)
	}

	// Show detailed findings
	if len(analysis.Findings) > 0 {
		fmt.Printf("\n")
		color.Bold.Printf("Detailed Security Analysis:\n")
		fmt.Printf(strings.Repeat("-", 60) + "\n")
		for i, finding := range analysis.Findings {
			icon := getEntropyIcon(finding.Entropy)
			entropyColor := getEntropyColor(finding.Entropy)
			fmt.Printf("%d. %s ", i+1, icon)
			entropyColor.Printf("[%s] ", finding.Entropy.String())
			fmt.Printf("%s\n", finding.Type)
			fmt.Printf("   Description: %s\n", finding.Description)

			if finding.Context != "" {
				fmt.Printf("   Code: %s\n", finding.Context)
			}

			if finding.EntropyNotes != "" {
				fmt.Printf("   Analysis: %s\n", finding.EntropyNotes)
			}

			if finding.Suggestion != "" {
				fmt.Printf("   Action: %s\n", finding.Suggestion)
			}

			if finding.LineNumber > 0 {
				fmt.Printf("   Line: %d\n", finding.LineNumber)
			}
			fmt.Println()
		}
	}

	if analysis.OverallLevel >= cfg.SecurityThresholds.WarnLevel {
		fmt.Printf("\nWARNING: Security concerns detected (%s entropy level)\n", analysis.OverallLevel.String())

		// Ask user for confirmation unless auto-proceed is enabled
		if !cfg.SecurityThresholds.AutoProceed {
			fmt.Print("\nContinue with installation? [y/N]: ")
			var response string
			fmt.Scanln(&response)
			if response != "y" && response != "Y" {
				return fmt.Errorf("installation cancelled by user")
			}
		}
	}

	fmt.Printf("\n%s approved for installation\n", analysis.PackageName)
	return nil
}

// getEntropyIcon returns an icon based on entropy level
func getEntropyIcon(level types.SecurityEntropy) string {
	switch level {
	case types.EntropyMinimal:
		return "🟢"
	case types.EntropyLow:
		return "🟢"
	case types.EntropyModerate:
		return "🟡"
	case types.EntropyHigh:
		return "🔴"
	case types.EntropyCritical:
		return "🔴"
	default:
		return "❓"
	}
}

// getEntropyColor returns a color style matching the entropy level
func getEntropyColor(level types.SecurityEntropy) color.Style {
	switch level {
	case types.EntropyMinimal:
		return color.New(color.FgGreen, color.OpBold)
	case types.EntropyLow:
		return color.New(color.FgGreen)
	case types.EntropyModerate:
		return color.New(color.FgYellow) // Yellow/orange color
	case types.EntropyHigh:
		return color.New(color.FgRed)
	case types.EntropyCritical:
		return color.New(color.FgRed, color.OpBold)
	default:
		return color.New(color.FgDarkGray)
	}
}

// displayCollectedData shows what information we gathered for analysis
func displayCollectedData(pkgInfo *types.PackageInfo) {
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
			len(pkgInfo.Dependencies), truncateList(pkgInfo.Dependencies, 3))
	}
	if len(pkgInfo.MakeDepends) > 0 {
		fmt.Printf("• Build dependencies: %d packages (%s)\n",
			len(pkgInfo.MakeDepends), truncateList(pkgInfo.MakeDepends, 3))
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

// truncateList truncates a string slice for display
func truncateList(items []string, maxItems int) string {
	if len(items) <= maxItems {
		return strings.Join(items, ", ")
	}
	return strings.Join(items[:maxItems], ", ") + fmt.Sprintf(" (+%d more)", len(items)-maxItems)
}
