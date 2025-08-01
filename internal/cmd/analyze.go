package cmd

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/aaronsb/yay-friend/internal/config"
	"github.com/aaronsb/yay-friend/internal/providers"
	"github.com/aaronsb/yay-friend/internal/types"
	"github.com/aaronsb/yay-friend/internal/yay"
)

// newAnalyzeCmd creates the analyze command
func newAnalyzeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "analyze <package>",
		Short: "Analyze a package without installing it",
		Long: `Analyze a package's PKGBUILD for security issues without installing it.
This is useful for checking packages before deciding whether to install them.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAnalyze(cmd.Context(), args[0])
		},
	}

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

	// Analyze security
	analysis, err := aiProvider.AnalyzePKGBUILD(ctx, *pkgInfo)
	if err != nil {
		return fmt.Errorf("analysis failed: %w", err)
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