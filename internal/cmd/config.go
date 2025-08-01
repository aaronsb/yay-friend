package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/aaronsb/yay-friend/internal/config"
)

// newConfigCmd creates the config command
func newConfigCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Manage yay-friend configuration",
		Long:  "Manage yay-friend configuration settings",
	}

	cmd.AddCommand(newConfigInitCmd())
	cmd.AddCommand(newConfigShowCmd())
	cmd.AddCommand(newConfigSetCmd())

	return cmd
}

func newConfigInitCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Initialize default configuration",
		Long:  "Create a default configuration file",
		RunE: func(cmd *cobra.Command, args []string) error {
			return config.InitializeConfig()
		},
	}
}

func newConfigShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show",
		Short: "Show current configuration",
		Long:  "Display the current configuration settings",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return fmt.Errorf("failed to load config: %w", err)
			}

			fmt.Println("Current Configuration:")
			fmt.Printf("Default Provider: %s\n", cfg.DefaultProvider)
			fmt.Printf("Security Thresholds:\n")
			fmt.Printf("  Block Level: %s\n", cfg.SecurityThresholds.BlockLevel.String())
			fmt.Printf("  Warn Level: %s\n", cfg.SecurityThresholds.WarnLevel.String())
			fmt.Printf("  Auto Proceed: %v\n", cfg.SecurityThresholds.AutoProceed)
			fmt.Printf("UI Settings:\n")
			fmt.Printf("  Show Details: %v\n", cfg.UI.ShowDetails)
			fmt.Printf("  Use Colors: %v\n", cfg.UI.UseColors)
			fmt.Printf("  Verbose Output: %v\n", cfg.UI.VerboseOutput)
			fmt.Printf("Yay Settings:\n")
			fmt.Printf("  Path: %s\n", cfg.Yay.Path)
			fmt.Printf("  Default Flags: %v\n", cfg.Yay.Flags)

			return nil
		},
	}
}

func newConfigSetCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "set <key> <value>",
		Short: "Set a configuration value",
		Long:  "Set a configuration value (e.g., 'yay-friend config set default_provider claude')",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			key := args[0]
			value := args[1]

			viper.Set(key, value)
			
			if err := viper.WriteConfig(); err != nil {
				return fmt.Errorf("failed to write config: %w", err)
			}

			fmt.Printf("Set %s = %s\n", key, value)
			return nil
		},
	}

	return cmd
}