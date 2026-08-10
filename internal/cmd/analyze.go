package cmd

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/aaronsb/yay-friend/internal/aur"
	"github.com/aaronsb/yay-friend/internal/cache"
	"github.com/aaronsb/yay-friend/internal/config"
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

	aiProvider, err := resolveProvider(ctx, cfg)
	if err != nil {
		return err
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
			ui.Say("using cached analysis (commit %s)", cache.ShortHash(pkgInfo.CommitHash))
			analysis = cachedAnalysis
		} else {
			ui.Say("running fresh analysis (commit %s)", cache.ShortHash(pkgInfo.CommitHash))
			// Cache miss - continue to run AI analysis
		}
	}

	// If no cached analysis found, run AI analysis
	if analysis == nil {
		// Display what we collected for analysis
		ui.RenderCollected(pkgInfo)

		analysis, err = analyzeWith(ctx, aiProvider, *pkgInfo, false)
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

	aiProvider, err := resolveProvider(ctx, cfg)
	if err != nil {
		return err
	}

	pkgbuildPath, err := resolvePKGBUILDPath(path)
	if err != nil {
		return err
	}

	ui.Say("analyzing local PKGBUILD %s with %s", pkgbuildPath, aiProvider.Name())
	ui.Say("local PKGBUILD analysis is not cached")

	pkgInfo, installScriptPath, err := collectPackageTree(pkgbuildPath)
	if err != nil {
		return err
	}

	// Display what we collected for analysis
	ui.RenderCollected(&pkgInfo)

	// RenderCollected already lists AdditionalFiles; only the install script
	// needs calling out, because it is the part that runs as root.
	if installScriptPath != "" {
		ui.Field("install script", filepath.Base(installScriptPath))
	}

	analysis, err := analyzeWith(ctx, aiProvider, pkgInfo, false)
	if err != nil {
		return fmt.Errorf("analysis failed: %w", err)
	}

	// Display detailed results
	ui.RenderAnalysis(analysis, true)

	return nil
}
