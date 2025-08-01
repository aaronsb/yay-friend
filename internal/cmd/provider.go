package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/aaronsb/yay-friend/internal/providers"
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

			fmt.Println("Available AI Providers:")
			fmt.Println("======================")

			for _, name := range registry.List() {
				provider, _ := registry.Get(name)
				capabilities := provider.GetCapabilities()
				
				status := "❌ Not authenticated"
				if provider.IsAuthenticated() {
					status = "✅ Authenticated"
				}

				fmt.Printf("Name: %s\n", name)
				fmt.Printf("Status: %s\n", status)
				fmt.Printf("Code Analysis: %v\n", capabilities.SupportsCodeAnalysis)
				fmt.Printf("Explanations: %v\n", capabilities.SupportsExplanations)
				fmt.Printf("Rate Limit: %d/min\n", capabilities.RateLimitPerMinute)
				fmt.Printf("Max Analysis Size: %d bytes\n", capabilities.MaxAnalysisSize)
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

				fmt.Printf("Testing %s...\n", providerName)
				if err := provider.Authenticate(cmd.Context()); err != nil {
					fmt.Printf("❌ Authentication failed: %v\n", err)
					return err
				}
				fmt.Printf("✅ %s authentication successful\n", providerName)
			} else {
				// Test all providers
				fmt.Println("Testing all providers...")
				results := registry.AuthenticateAll(cmd.Context())
				
				for name, err := range results {
					if err != nil {
						fmt.Printf("❌ %s: %v\n", name, err)
					} else {
						fmt.Printf("✅ %s: Authentication successful\n", name)
					}
				}
			}

			return nil
		},
	}
}