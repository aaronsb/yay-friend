package cmd

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/aaronsb/yay-friend/internal/config"
	"github.com/aaronsb/yay-friend/internal/providers"
	"github.com/aaronsb/yay-friend/internal/yay"
)

// newTestCmd creates the test command
func newTestCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "test <package>",
		Short: "Test analysis on a safe package (for development/debugging)",
		Long: `Test the security analysis on a known safe package to verify the system works.
This is useful for development and debugging the analysis pipeline.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runTest(cmd.Context(), args[0])
		},
	}

	return cmd
}

func runTest(ctx context.Context, packageName string) error {
	fmt.Printf("🧪 Testing analysis pipeline with package: %s\n", packageName)
	
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

	// Use Claude for testing
	aiProvider, err := registry.Get("claude")
	if err != nil {
		return fmt.Errorf("provider error: %w", err)
	}

	// Authenticate provider
	fmt.Printf("🔑 Authenticating with %s...\n", aiProvider.Name())
	if err := aiProvider.Authenticate(ctx); err != nil {
		return fmt.Errorf("authentication failed for %s: %w", aiProvider.Name(), err)
	}

	fmt.Printf("📦 Fetching package information for %s...\n", packageName)

	// Get package info
	pkgInfo, err := yayClient.GetPackageInfo(ctx, packageName)
	if err != nil {
		return fmt.Errorf("failed to get package info: %w", err)
	}

	fmt.Printf("📝 Package details:\n")
	fmt.Printf("   Name: %s\n", pkgInfo.Name)
	fmt.Printf("   Version: %s\n", pkgInfo.Version)
	fmt.Printf("   Description: %s\n", pkgInfo.Description)
	fmt.Printf("   Maintainer: %s\n", pkgInfo.Maintainer)
	fmt.Printf("   PKGBUILD size: %d characters\n", len(pkgInfo.PKGBUILD))

	fmt.Printf("\n🔍 Running security analysis...\n")

	// Analyze security
	analysis, err := aiProvider.AnalyzePKGBUILD(ctx, *pkgInfo)
	if err != nil {
		return fmt.Errorf("analysis failed: %w", err)
	}

	// Display detailed results
	fmt.Printf("\n%s\n", strings.Repeat("=", 60))
	fmt.Printf("TEST ANALYSIS RESULTS\n")
	fmt.Printf("%s\n", strings.Repeat("=", 60))
	fmt.Printf("Package: %s\n", analysis.PackageName)
	fmt.Printf("Provider: %s\n", analysis.Provider)
	fmt.Printf("Overall Entropy: %s\n", analysis.OverallEntropy.String())
	fmt.Printf("Predictability Score: %.2f\n", analysis.PredictabilityScore)
	fmt.Printf("Recommendation: %s\n", analysis.Recommendation)
	fmt.Printf("\nSummary:\n%s\n", analysis.Summary)
	
	if len(analysis.EntropyFactors) > 0 {
		fmt.Printf("\nEntropy Factors:\n")
		for _, factor := range analysis.EntropyFactors {
			fmt.Printf("  • %s\n", factor)
		}
	}

	if len(analysis.Findings) > 0 {
		fmt.Printf("\nFindings (%d):\n", len(analysis.Findings))
		for i, finding := range analysis.Findings {
			fmt.Printf("  %d. [%s] %s: %s\n", i+1, finding.Entropy.String(), finding.Type, finding.Description)
			if finding.EntropyNotes != "" {
				fmt.Printf("     🌪️  Entropy: %s\n", finding.EntropyNotes)
			}
			if finding.Suggestion != "" {
				fmt.Printf("     💡 %s\n", finding.Suggestion)
			}
		}
	} else {
		fmt.Println("\n✅ No security issues found!")
	}

	fmt.Printf("\n%s\n", strings.Repeat("-", 40))
	fmt.Printf("Test completed successfully!\n")

	return nil
}