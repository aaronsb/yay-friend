package cmd

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/aaronsb/yay-friend/internal/aur"
	"github.com/aaronsb/yay-friend/internal/cache"
	"github.com/aaronsb/yay-friend/internal/config"
	"github.com/aaronsb/yay-friend/internal/types"
	"github.com/aaronsb/yay-friend/internal/ui"
	"github.com/aaronsb/yay-friend/internal/yay"
)

var (
	cfgFile      string
	verbose      bool
	skipAnalysis bool
	provider     string
	noSpinner    bool
	noColor      bool
	noConfirm    bool
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "yay-friend [packages...]",
	Short: "A security-focused wrapper around yay",
	Long: `yay-friend is a security-focused wrapper around yay that uses AI to analyze 
PKGBUILD files for potential security issues before installation.

It acts as a security layer between you and the Arch User Repository (AUR),
analyzing packages for suspicious patterns, malicious code, and security risks.`,
	// RunE is assigned in init(): it reaches runInstall, which reaches rootCmd
	// again to print help, and Go rejects that as an initialization cycle when it
	// is written as part of this literal.
	//
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

	rootCmd.RunE = func(cmd *cobra.Command, args []string) error {
		return runInstall(cmd.Context(), args)
	}

	// Global flags. Declared from the same table the yay-style parser reads, so
	// the two entry points cannot drift apart; see internal/cmd/args.go.
	registerOwnFlags(rootCmd)

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
	rootCmd.AddCommand(newGradeCmd())
	rootCmd.AddCommand(newCacheCmd())
	rootCmd.AddCommand(newConfigCmd())
	rootCmd.AddCommand(newProviderCmd())
	rootCmd.AddCommand(newVersionCmd())
}

// initConfig wires the --config flag into the config package so that
// config.Load reads from the requested file (or the default path when empty),
// then settles colour output before anything prints.
func initConfig() {
	config.SetConfigPath(cfgFile)

	// Colour has to be decided before the first rendered byte. A config that
	// will not load must not prevent that, so fall back to permitting colour
	// and let the TTY check in ui.Configure have the last word.
	useColors := true
	if cfg, err := config.Load(); err == nil {
		useColors = cfg.UI.UseColors
	}
	ui.Configure(noColor, useColors)
}

// withNoConfirmFlag hands --noconfirm back to yay.
//
// Unknown flags reach yay untouched, which is how --noconfirm worked before it
// was declared here: cobra never saw it and yay did. Declaring it consumed it,
// so without this, asking yay-friend to stop prompting would have made yay start.
func withNoConfirmFlag(flags []string, noConfirm bool) []string {
	if !noConfirm {
		return flags
	}
	for _, f := range flags {
		if f == "--noconfirm" {
			return flags
		}
	}
	return append(flags, "--noconfirm")
}

// runInstall handles the main package installation workflow
func runInstall(ctx context.Context, args []string) error {
	// Naming no operation used to mean `yay -Syu`: a whole-system upgrade with
	// nothing analyzed, reachable by typing the tool's name and pressing enter.
	// That is a security wrapper's least defensible default. An upgrade is still
	// one word away (`yay-friend -Syu`) -- it just has to be asked for.
	//
	// The check sits here rather than in RunE because both entry points converge
	// on this function, and the flags-only case (`yay-friend --noconfirm`) never
	// reaches cobra at all.
	if len(args) == 0 {
		return rootCmd.Help()
	}

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Debug config loading - only show in verbose mode
	if verbose {
		ui.Field("config", fmt.Sprintf("provider %s, block %s, warn %s",
			cfg.DefaultProvider, cfg.SecurityThresholds.BlockLevel, cfg.SecurityThresholds.WarnLevel))
	}

	// Parse yay command
	operation, err := yay.ParseYayCommand(args)
	if err != nil {
		return fmt.Errorf("failed to parse command: %w", err)
	}

	operation.Flags = withNoConfirmFlag(operation.Flags, noConfirm)

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
			// Which of several search hits was meant is not a confirmation, so
			// --noconfirm has no answer to supply. Say that, rather than pick.
			if noConfirm {
				return fmt.Errorf("package %q not found and --noconfirm cannot choose among search results: name the package exactly", pkg)
			}
			ui.Say("package %q not found exactly, searching", pkg)

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
				ui.Say("selection cancelled")
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

	aiProvider, err := resolveProvider(ctx, cfg)
	if err != nil {
		return err
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
			ui.Blank()
			ui.Say("all packages passed security analysis")

			// Without -S the request was to analyze, and this prompt is an offer
			// on top of that. --noconfirm declines unasked-for offers: it means
			// stop asking, not start installing.
			if noConfirm {
				ui.Say("not installing: no -S given (--noconfirm declines the offer)")
				return nil
			}

			ui.Ask("proceed with installation? [y/N]: ")

			var response string
			fmt.Scanln(&response)
			response = strings.ToLower(strings.TrimSpace(response))

			if response == "y" || response == "yes" {
				// Change operation to install and proceed
				operation.Command = "-S"
				operation.Operation = "install"
				ui.Say("proceeding with installation")
				return yayClient.InstallPackages(ctx, operation)
			} else {
				ui.Say("installation cancelled")
				return nil
			}
		} else {
			ui.Blank()
			ui.Say("security concerns found; installation not recommended")
			return nil
		}
	} else {
		// Regular install mode, proceed automatically if safe
		ui.Say("all packages passed security analysis, proceeding with installation")
		return yayClient.InstallPackages(ctx, operation)
	}
}

// analyzeAndDecide analyzes a package and decides whether to proceed
func analyzeAndDecide(ctx context.Context, yayClient *yay.YayClient, provider types.AIProvider, packageName string, cfg *types.Config) error {
	ui.Say("analyzing %s", packageName)

	// Get package info
	pkgInfo, err := yayClient.GetPackageInfo(ctx, packageName)
	if err != nil {
		return err
	}

	// Fetch additional AUR context (including commit hash)
	ui.Say("fetching AUR context")
	aurFetcher := aur.NewAURFetcher()
	if err := aurFetcher.EnrichPackageInfo(ctx, pkgInfo); err != nil {
		ui.Warn("could not enrich with AUR context: %v", err)
	} else {
		ui.Say("AUR context: %d votes, %.3f popularity, %d comments",
			pkgInfo.Votes, pkgInfo.Popularity, len(pkgInfo.Comments))
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

		// Analyze security with enriched context
		analysis, err = analyzeWith(ctx, provider, *pkgInfo, false)
		if err != nil {
			return err
		}

		// Save to cache if enabled and available
		if cfg.Cache.Enabled && cacheManager != nil && pkgInfo.CommitHash != "" {
			if cacheErr := cacheManager.SaveAnalysis(pkgInfo.Name, pkgInfo.CommitHash, analysis); cacheErr != nil {
				ui.Warn("could not save analysis to cache: %v", cacheErr)
			}
		}
	}

	// Display results and make decision
	return handleAnalysisResult(analysis, cfg)
}

// handleAnalysisResult processes the analysis result and makes a decision
func handleAnalysisResult(analysis *types.SecurityAnalysis, cfg *types.Config) error {
	ui.RenderAnalysis(analysis, false)

	if verbose {
		ui.Blank()
		ui.Field("thresholds", fmt.Sprintf("level %s, block at %s, warn at %s",
			analysis.OverallLevel, cfg.SecurityThresholds.BlockLevel, cfg.SecurityThresholds.WarnLevel))
	}

	// The block threshold is checked before any auto-proceed is consulted, and
	// nothing below can reach past it. --noconfirm answers questions; it is not a
	// way to overrule the policy, or a security tool with a flag that turns it off
	// is what this would be. Strictness is set by moving block_level, in config,
	// deliberately.
	if analysis.OverallLevel >= cfg.SecurityThresholds.BlockLevel {
		ui.Blank()
		ui.Say("%s blocked: %s entropy exceeds the %s threshold",
			analysis.PackageName, analysis.OverallLevel, cfg.SecurityThresholds.BlockLevel)
		return fmt.Errorf("package %s blocked by security policy", analysis.PackageName)
	}

	if analysis.OverallLevel >= cfg.SecurityThresholds.WarnLevel {
		ui.Blank()
		ui.Say("%s entropy is %s, at or above the warn threshold", analysis.PackageName, analysis.OverallLevel)

		// Ask user for confirmation unless auto-proceed is enabled
		switch {
		case cfg.SecurityThresholds.AutoProceed:
		case noConfirm:
			ui.Say("proceeding without confirmation (--noconfirm)")
		default:
			ui.Ask("continue with installation? [y/N]: ")
			var response string
			fmt.Scanln(&response)
			if response != "y" && response != "Y" {
				return fmt.Errorf("installation cancelled by user")
			}
		}
	}

	ui.Blank()
	ui.Say("%s approved for installation", analysis.PackageName)
	return nil
}
