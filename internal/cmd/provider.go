package cmd

import (
	"fmt"
	"github.com/dustin/go-humanize"

	"github.com/spf13/cobra"

	"github.com/aaronsb/yay-friend/internal/providers"
	"github.com/aaronsb/yay-friend/internal/ui"
)

// newProviderCmd creates the provider command
func newProviderCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "provider",
		Short: "Manage AI providers",
		Long:  "Manage and test AI provider connections",
	}

	cmd.AddCommand(newProviderListCmd())
	cmd.AddCommand(newProviderTestCmd())

	return cmd
}

func newProviderListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List available providers",
		Long:  "List all available AI providers and their status",
		RunE: func(cmd *cobra.Command, args []string) error {
			registry := providers.NewProviderRegistry()
			registry.Register("claude", providers.NewClaudeProvider())
			registry.Register("qwen", providers.NewQwenProvider())
			registry.Register("copilot", providers.NewCopilotProvider())
			registry.Register("goose", providers.NewGooseProvider())

			ui.Blank()
			fmt.Println(ui.Rule("providers"))

			for _, name := range registry.List() {
				provider, _ := registry.Get(name)
				capabilities := provider.GetCapabilities()

				status := "not authenticated"
				if provider.IsAuthenticated() {
					status = "authenticated"
				}

				ui.Blank()
				fmt.Printf("  %s\n", name)
				ui.Field("status", status)
				ui.Field("code analysis", fmt.Sprintf("%v", capabilities.SupportsCodeAnalysis))
				ui.Field("explanations", fmt.Sprintf("%v", capabilities.SupportsExplanations))
				ui.Field("rate limit", fmt.Sprintf("%d/min", capabilities.RateLimitPerMinute))
				ui.Field("max size", humanize.Bytes(uint64(capabilities.MaxAnalysisSize)))
				fmt.Println()
			}

			return nil
		},
	}
}

func newProviderTestCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "test [provider]",
		Short: "Test provider authentication",
		Long:  "Test authentication for a specific provider or all providers",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			registry := providers.NewProviderRegistry()
			registry.Register("claude", providers.NewClaudeProvider())
			registry.Register("qwen", providers.NewQwenProvider())
			registry.Register("copilot", providers.NewCopilotProvider())
			registry.Register("goose", providers.NewGooseProvider())

			if len(args) == 1 {
				// Test specific provider
				providerName := args[0]
				provider, err := registry.Get(providerName)
				if err != nil {
					return err
				}

				ui.Say("testing %s", providerName)
				if err := provider.Authenticate(cmd.Context()); err != nil {
					ui.Warn("authentication failed: %v", err)
					return err
				}
				ui.Say("%s authentication successful", providerName)
			} else {
				// Test all providers
				ui.Say("testing all providers")
				results := registry.AuthenticateAll(cmd.Context())

				for name, err := range results {
					if err != nil {
						ui.Warn("%s: %v", name, err)
					} else {
						ui.Say("%s: authentication successful", name)
					}
				}
			}

			return nil
		},
	}
}
