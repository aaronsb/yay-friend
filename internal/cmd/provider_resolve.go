package cmd

import (
	"context"
	"fmt"

	"github.com/aaronsb/yay-friend/internal/providers"
	"github.com/aaronsb/yay-friend/internal/types"
)

// resolveProvider returns the AI provider named by --provider, else the one in
// config, else claude — registered, authenticated, and ready to analyze.
//
// It is a variable so a test can substitute a provider that never calls a model.
// Nothing in production assigns it: the install path, the analyze path and the
// grade path all went through their own copy of this block before, and the four
// copies had already started to drift.
var resolveProvider = defaultResolveProvider

func defaultResolveProvider(ctx context.Context, cfg *types.Config) (types.AIProvider, error) {
	registry := providers.NewProviderRegistry()
	claudeProvider := providers.NewClaudeProvider()
	claudeProvider.SetConfig(cfg)
	registry.Register("claude", claudeProvider)
	registry.Register("qwen", providers.NewQwenProvider())
	registry.Register("copilot", providers.NewCopilotProvider())
	registry.Register("goose", providers.NewGooseProvider())

	name := provider
	if name == "" {
		name = cfg.DefaultProvider
	}
	if name == "" {
		name = "claude"
	}

	aiProvider, err := registry.Get(name)
	if err != nil {
		return nil, fmt.Errorf("provider error: %w", err)
	}

	if err := aiProvider.Authenticate(ctx); err != nil {
		return nil, fmt.Errorf("authentication failed for %s: %w", name, err)
	}

	return aiProvider, nil
}

// analyzeWith runs an analysis, taking Claude's options-aware entry point when
// the provider is Claude so that --no-spinner is honored.
//
// quiet forces the non-streaming path regardless of --no-spinner. Machine
// output (grade, analyze --json) sets it: the streaming renderer repaints its
// progress line with carriage returns and ANSI erases, and a caller reading
// stderr for a diagnostic should not have to read past that.
func analyzeWith(ctx context.Context, aiProvider types.AIProvider, pkgInfo types.PackageInfo, quiet bool) (*types.SecurityAnalysis, error) {
	if claudeProvider, ok := aiProvider.(*providers.ClaudeProvider); ok {
		return claudeProvider.AnalyzePKGBUILDWithOptions(ctx, pkgInfo, quiet || noSpinner)
	}
	return aiProvider.AnalyzePKGBUILD(ctx, pkgInfo)
}
