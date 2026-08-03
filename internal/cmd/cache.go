package cmd

import (
	"context"
	"fmt"
	"time"

	"github.com/dustin/go-humanize"
	"github.com/spf13/cobra"

	"github.com/aaronsb/yay-friend/internal/cache"
	"github.com/aaronsb/yay-friend/internal/ui"
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

	ui.Blank()
	fmt.Println(ui.Rule("cache"))
	ui.Field("packages", fmt.Sprintf("%d", stats.TotalPackages))
	ui.Field("analyses", fmt.Sprintf("%d", stats.TotalAnalyses))
	ui.Field("size", humanize.Bytes(uint64(stats.CacheSize)))

	if !stats.OldestEntry.IsZero() {
		ui.Field("oldest", humanize.Time(stats.OldestEntry))
	}
	if !stats.NewestEntry.IsZero() {
		ui.Field("newest", humanize.Time(stats.NewestEntry))
	}

	if stats.RecentHits > 0 || stats.RecentMisses > 0 {
		total := stats.RecentHits + stats.RecentMisses
		hitRate := float64(stats.RecentHits) / float64(total) * 100
		ui.Field("hit rate", fmt.Sprintf("%.1f%% (%d hits, %d misses)",
			hitRate, stats.RecentHits, stats.RecentMisses))
	}
	ui.Blank()

	return nil
}

func runCacheClean(ctx context.Context, days int) error {
	cacheManager, err := cache.NewCacheManager()
	if err != nil {
		return fmt.Errorf("failed to initialize cache manager: %w", err)
	}

	ui.Say("cleaning cache entries older than %d days", days)

	maxAge := time.Duration(days) * 24 * time.Hour
	if err := cacheManager.CleanExpiredCache(maxAge); err != nil {
		return fmt.Errorf("failed to clean cache: %w", err)
	}

	ui.Say("cache cleaning completed")
	return nil
}

func runCacheClear(ctx context.Context, confirm bool) error {
	if !confirm {
		ui.Ask("this will remove ALL cached analysis results. continue? [y/N]: ")
		var response string
		fmt.Scanln(&response)
		if response != "y" && response != "Y" {
			ui.Say("operation cancelled")
			return nil
		}
	}

	cacheManager, err := cache.NewCacheManager()
	if err != nil {
		return fmt.Errorf("failed to initialize cache manager: %w", err)
	}

	ui.Say("clearing all cache entries")

	// Clean all entries (0 days = everything)
	if err := cacheManager.CleanExpiredCache(0); err != nil {
		return fmt.Errorf("failed to clear cache: %w", err)
	}

	ui.Say("all cache entries cleared")
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
		ui.Say("no cached analyses found for %q", packageName)
		return nil
	}

	ui.Blank()
	fmt.Println(ui.Rule("cached analyses for " + packageName))

	for _, commitHash := range versions {
		analysis, err := cacheManager.GetCachedAnalysis(packageName, commitHash)
		if err != nil {
			ui.Bullet("%s (error reading cache)", commitHash[:8])
			continue
		}

		ui.Blank()
		fmt.Printf("  %s  %s\n", ui.Mark(analysis.OverallLevel), commitHash[:8])
		ui.Field("provider", analysis.Provider)
		ui.Field("analyzed", humanize.Time(analysis.AnalyzedAt))
		if analysis.Summary != "" {
			// Truncate long summaries
			summary := analysis.Summary
			if len(summary) > 100 {
				summary = summary[:97] + "..."
			}
			ui.Field("summary", summary)
		}
		ui.Field("findings", fmt.Sprintf("%d", len(analysis.Findings)))
		fmt.Println()
	}

	return nil
}
