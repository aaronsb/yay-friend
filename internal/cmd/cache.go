package cmd

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/gookit/color"
	"github.com/spf13/cobra"

	"github.com/aaronsb/yay-friend/internal/cache"
)

// newCacheCmd creates the cache command
func newCacheCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cache",
		Short: "Manage analysis cache",
		Long: `Manage the analysis cache system that stores security analysis results
keyed by AUR git commit hashes to avoid redundant AI calls.`,
	}

	cmd.AddCommand(newCacheStatusCmd())
	cmd.AddCommand(newCacheCleanCmd())
	cmd.AddCommand(newCacheClearCmd())
	cmd.AddCommand(newCacheShowCmd())

	return cmd
}

// newCacheStatusCmd creates the cache status command
func newCacheStatusCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show cache statistics",
		Long:  `Display cache statistics including size, number of packages, and hit rate.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCacheStatus(cmd.Context())
		},
	}

	return cmd
}

// newCacheCleanCmd creates the cache clean command
func newCacheCleanCmd() *cobra.Command {
	var days int

	cmd := &cobra.Command{
		Use:   "clean",
		Short: "Clean expired cache entries",
		Long:  `Remove cache entries older than the specified number of days (default: 90).`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCacheClean(cmd.Context(), days)
		},
	}

	cmd.Flags().IntVar(&days, "days", 90, "Remove cache entries older than this many days")

	return cmd
}

// newCacheClearCmd creates the cache clear command
func newCacheClearCmd() *cobra.Command {
	var confirm bool

	cmd := &cobra.Command{
		Use:   "clear",
		Short: "Clear all cache entries",
		Long:  `Remove all cached analysis results. This cannot be undone.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCacheClear(cmd.Context(), confirm)
		},
	}

	cmd.Flags().BoolVarP(&confirm, "yes", "y", false, "Skip confirmation prompt")

	return cmd
}

// newCacheShowCmd creates the cache show command
func newCacheShowCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "show <package>",
		Short: "Show cached analyses for a package",
		Long:  `Display all cached security analyses for the specified package.`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCacheShow(cmd.Context(), args[0])
		},
	}

	return cmd
}

func runCacheStatus(ctx context.Context) error {
	cacheManager, err := cache.NewCacheManager()
	if err != nil {
		return fmt.Errorf("failed to initialize cache manager: %w", err)
	}

	stats, err := cacheManager.GetCacheStats()
	if err != nil {
		return fmt.Errorf("failed to get cache statistics: %w", err)
	}

	fmt.Printf("\n")
	color.Bold.Printf("Cache Statistics\n")
	fmt.Printf(strings.Repeat("=", 40) + "\n")
	
	fmt.Printf("Total Packages: %d\n", stats.TotalPackages)
	fmt.Printf("Total Analyses: %d\n", stats.TotalAnalyses)
	fmt.Printf("Cache Size: %s\n", formatBytes(stats.CacheSize))
	
	if !stats.OldestEntry.IsZero() {
		fmt.Printf("Oldest Entry: %s\n", stats.OldestEntry.Format("2006-01-02 15:04:05"))
	}
	if !stats.NewestEntry.IsZero() {
		fmt.Printf("Newest Entry: %s\n", stats.NewestEntry.Format("2006-01-02 15:04:05"))
	}
	
	if stats.RecentHits > 0 || stats.RecentMisses > 0 {
		total := stats.RecentHits + stats.RecentMisses
		hitRate := float64(stats.RecentHits) / float64(total) * 100
		fmt.Printf("Hit Rate: %.1f%% (%d hits, %d misses)\n", 
			hitRate, stats.RecentHits, stats.RecentMisses)
	}

	fmt.Printf("\n")

	return nil
}

func runCacheClean(ctx context.Context, days int) error {
	cacheManager, err := cache.NewCacheManager()
	if err != nil {
		return fmt.Errorf("failed to initialize cache manager: %w", err)
	}

	fmt.Printf("🧹 Cleaning cache entries older than %d days...\n", days)
	
	maxAge := time.Duration(days) * 24 * time.Hour
	if err := cacheManager.CleanExpiredCache(maxAge); err != nil {
		return fmt.Errorf("failed to clean cache: %w", err)
	}

	fmt.Printf("✅ Cache cleaning completed\n")
	return nil
}

func runCacheClear(ctx context.Context, confirm bool) error {
	if !confirm {
		fmt.Print("This will remove ALL cached analysis results. Continue? [y/N]: ")
		var response string
		fmt.Scanln(&response)
		if response != "y" && response != "Y" {
			fmt.Println("Operation cancelled")
			return nil
		}
	}

	cacheManager, err := cache.NewCacheManager()
	if err != nil {
		return fmt.Errorf("failed to initialize cache manager: %w", err)
	}

	fmt.Printf("🗑️  Clearing all cache entries...\n")
	
	// Clean all entries (0 days = everything)
	if err := cacheManager.CleanExpiredCache(0); err != nil {
		return fmt.Errorf("failed to clear cache: %w", err)
	}

	fmt.Printf("✅ All cache entries cleared\n")
	return nil
}

func runCacheShow(ctx context.Context, packageName string) error {
	cacheManager, err := cache.NewCacheManager()
	if err != nil {
		return fmt.Errorf("failed to initialize cache manager: %w", err)
	}

	versions, err := cacheManager.GetPackageVersions(packageName)
	if err != nil {
		return fmt.Errorf("failed to get package versions: %w", err)
	}

	if len(versions) == 0 {
		fmt.Printf("No cached analyses found for package '%s'\n", packageName)
		return nil
	}

	fmt.Printf("\n")
	color.Bold.Printf("Cached Analyses for %s\n", packageName)
	fmt.Printf(strings.Repeat("=", 40) + "\n")

	for i, commitHash := range versions {
		analysis, err := cacheManager.GetCachedAnalysis(packageName, commitHash)
		if err != nil {
			fmt.Printf("%d. %s (error reading cache)\n", i+1, commitHash[:8])
			continue
		}

		fmt.Printf("%d. Commit: %s\n", i+1, commitHash[:8])
		fmt.Printf("   Level: %s\n", analysis.OverallLevel.String())
		fmt.Printf("   Provider: %s\n", analysis.Provider)
		fmt.Printf("   Analyzed: %s\n", analysis.AnalyzedAt.Format("2006-01-02 15:04:05"))
		if analysis.Summary != "" {
			// Truncate long summaries
			summary := analysis.Summary
			if len(summary) > 100 {
				summary = summary[:97] + "..."
			}
			fmt.Printf("   Summary: %s\n", summary)
		}
		fmt.Printf("   Findings: %d\n", len(analysis.Findings))
		fmt.Println()
	}

	return nil
}

// formatBytes formats a byte count into a human-readable string
func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}