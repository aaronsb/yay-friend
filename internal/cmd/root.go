package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/aaronsb/yay-friend/internal/aur"
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
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.yay-friend.yaml)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")
	rootCmd.PersistentFlags().BoolVar(&skipAnalysis, "skip-analysis", false, "skip security analysis and proceed directly to yay")
	rootCmd.PersistentFlags().StringVar(&provider, "provider", "", "AI provider to use (claude, qwen, copilot, goose)")
	
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
	rootCmd.AddCommand(newConfigCmd())
	rootCmd.AddCommand(newProviderCmd())
	rootCmd.AddCommand(newTestCmd())
}

// initConfig reads in config file and ENV variables.
func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		home, err := os.UserHomeDir()
		cobra.CheckErr(err)

		configDir := filepath.Join(home, ".yay-friend")
		viper.AddConfigPath(configDir)
		viper.SetConfigType("yaml")
		viper.SetConfigName("config")
	}

	viper.AutomaticEnv()

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil && verbose {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	}
}

// runInstall handles the main package installation workflow  
func runInstall(ctx context.Context, args []string) error {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}
	
	// Debug config loading - temporarily show for troubleshooting
	fmt.Printf("🔧 Config Debug - Default Provider: %s, Block Level: %d, Warn Level: %d\n", 
		cfg.DefaultProvider, int(cfg.SecurityThresholds.BlockLevel), int(cfg.SecurityThresholds.WarnLevel))

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
	if skipAnalysis || len(operation.Packages) == 0 || operation.Operation != "install" {
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
	registry.Register("claude", providers.NewClaudeProvider())
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
	for _, packageName := range operation.Packages {
		if err := analyzeAndDecide(ctx, yayClient, aiProvider, packageName, cfg); err != nil {
			return fmt.Errorf("analysis failed for %s: %w", packageName, err)
		}
	}

	// If we get here, all packages passed analysis, proceed with installation
	fmt.Printf("✅ All packages passed security analysis, proceeding with installation...\n")
	return yayClient.InstallPackages(ctx, operation)
}

// analyzeAndDecide analyzes a package and decides whether to proceed
func analyzeAndDecide(ctx context.Context, yayClient *yay.YayClient, provider types.AIProvider, packageName string, cfg *types.Config) error {
	fmt.Printf("🔍 Analyzing %s...\n", packageName)

	// Get package info
	pkgInfo, err := yayClient.GetPackageInfo(ctx, packageName)
	if err != nil {
		return err
	}

	// Fetch additional AUR context
	fmt.Printf("🌐 Fetching AUR page context...\n")
	aurFetcher := aur.NewAURFetcher()
	if err := aurFetcher.EnrichPackageInfo(ctx, pkgInfo); err != nil {
		fmt.Printf("⚠️  Warning: Could not enrich with AUR context: %v\n", err)
	} else {
		fmt.Printf("✅ AUR context: %d votes, %.3f popularity, %d comments\n", 
			pkgInfo.Votes, pkgInfo.Popularity, len(pkgInfo.Comments))
	}

	// Analyze security with enriched context
	analysis, err := provider.AnalyzePKGBUILD(ctx, *pkgInfo)
	if err != nil {
		return err
	}

	// Display results and make decision
	return handleAnalysisResult(analysis, cfg)
}

// handleAnalysisResult processes the analysis result and makes a decision
func handleAnalysisResult(analysis *types.SecurityAnalysis, cfg *types.Config) error {
	// Display analysis summary with better formatting
	fmt.Printf("\n" + strings.Repeat("=", 60) + "\n")
	fmt.Printf("📋 Security Analysis Results: %s\n", analysis.PackageName)
	fmt.Printf(strings.Repeat("=", 60) + "\n")
	
	// Display entropy level with color coding
	entropyIcon := getEntropyIcon(analysis.OverallLevel)
	fmt.Printf("🔒 Security Entropy: %s %s\n", entropyIcon, analysis.OverallLevel.String())
	
	if analysis.PredictabilityScore > 0 {
		fmt.Printf("📊 Predictability Score: %.2f/1.0\n", analysis.PredictabilityScore)
	}
	
	if len(analysis.EntropyFactors) > 0 {
		fmt.Printf("⚡ Entropy Factors: %s\n", strings.Join(analysis.EntropyFactors, ", "))
	}
	
	fmt.Printf("📝 Summary: %s\n", analysis.Summary)
	
	// Show educational content
	if analysis.EducationalSummary != "" {
		fmt.Printf("\n🎓 Security Education:\n")
		fmt.Printf(strings.Repeat("-", 60) + "\n")
		fmt.Printf("%s\n", analysis.EducationalSummary)
	}

	if len(analysis.SecurityLessons) > 0 {
		fmt.Printf("\n💡 Key Security Lessons:\n")
		for i, lesson := range analysis.SecurityLessons {
			fmt.Printf("   %d. %s\n", i+1, lesson)
		}
	}

	// Debug threshold comparison - always show for debugging this issue
	fmt.Printf("\n🔧 Debug - Analysis Level: %d (%s), Block Threshold: %d (%s), Warn Threshold: %d (%s)\n", 
		int(analysis.OverallLevel), analysis.OverallLevel.String(),
		int(cfg.SecurityThresholds.BlockLevel), cfg.SecurityThresholds.BlockLevel.String(),
		int(cfg.SecurityThresholds.WarnLevel), cfg.SecurityThresholds.WarnLevel.String())

	// Check against thresholds
	if analysis.OverallLevel >= cfg.SecurityThresholds.BlockLevel {
		fmt.Printf("\n🚫 BLOCKED: Package security level (%s) exceeds block threshold (%s)\n", 
			analysis.OverallLevel.String(), cfg.SecurityThresholds.BlockLevel.String())
		return fmt.Errorf("package %s blocked by security policy", analysis.PackageName)
	}

	// Show detailed findings
	if len(analysis.Findings) > 0 {
		fmt.Printf("\n🔍 Detailed Security Analysis:\n")
		fmt.Printf(strings.Repeat("-", 60) + "\n")
		for i, finding := range analysis.Findings {
			icon := getEntropyIcon(finding.Entropy)
			fmt.Printf("%d. %s [%s] %s\n", i+1, icon, finding.Entropy.String(), finding.Type)
			fmt.Printf("   📄 %s\n", finding.Description)
			
			if finding.Context != "" {
				fmt.Printf("   📋 Context: %s\n", finding.Context)
			}
			
			if finding.EntropyNotes != "" {
				fmt.Printf("   🧠 Entropy Analysis: %s\n", finding.EntropyNotes)
			}
			
			if finding.Suggestion != "" {
				fmt.Printf("   💡 Suggestion: %s\n", finding.Suggestion)
			}
			
			if finding.LineNumber > 0 {
				fmt.Printf("   📍 Line: %d\n", finding.LineNumber)
			}
			fmt.Println()
		}
	}

	if analysis.OverallLevel >= cfg.SecurityThresholds.WarnLevel {
		fmt.Printf("⚠️  WARNING: Security concerns detected (%s entropy level)\n", analysis.OverallLevel.String())

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

	fmt.Printf("✅ %s approved for installation\n", analysis.PackageName)
	return nil
}

// getEntropyIcon returns an icon based on entropy level
func getEntropyIcon(level types.SecurityEntropy) string {
	switch level {
	case types.EntropyMinimal:
		return "🟢"
	case types.EntropyLow:
		return "🟡"
	case types.EntropyModerate:
		return "🟠"
	case types.EntropyHigh:
		return "🔴"
	case types.EntropyCritical:
		return "🚨"
	default:
		return "❓"
	}
}