package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"

	"github.com/aaronsb/yay-friend/internal/types"
)

// Load loads the configuration from file
func Load() (*types.Config, error) {
	cfg := &types.Config{}

	// Set defaults
	setDefaults()

	// Try to unmarshal into our config struct
	if err := viper.Unmarshal(cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Validate configuration
	if err := validateConfig(cfg); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return cfg, nil
}

// InitializeConfig creates a default configuration directory and file
func InitializeConfig() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get user home directory: %w", err)
	}

	configDir := filepath.Join(home, ".yay-friend")
	configPath := filepath.Join(configDir, "config.yaml")

	// Create config directory if it doesn't exist
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Check if config already exists
	if _, err := os.Stat(configPath); err == nil {
		return fmt.Errorf("configuration file already exists at %s", configPath)
	}

	// Create default config
	defaultConfig := &types.Config{
		DefaultProvider: "claude",
		Providers: map[string]string{
			"claude":  "",
			"qwen":    "",
			"copilot": "",
			"goose":   "",
		},
		SecurityThresholds: struct {
			BlockLevel  types.SecurityLevel `yaml:"block_level"`
			WarnLevel   types.SecurityLevel `yaml:"warn_level"`
			AutoProceed bool                `yaml:"auto_proceed_safe"`
		}{
			BlockLevel:  types.SecurityCritical,
			WarnLevel:   types.SecurityMedium,
			AutoProceed: false,
		},
		UI: struct {
			ShowDetails   bool `yaml:"show_details"`
			UseColors     bool `yaml:"use_colors"`
			VerboseOutput bool `yaml:"verbose_output"`
		}{
			ShowDetails:   true,
			UseColors:     true,
			VerboseOutput: false,
		},
		Yay: struct {
			Path  string   `yaml:"path"`
			Flags []string `yaml:"default_flags"`
		}{
			Path:  "yay",
			Flags: []string{},
		},
	}

	// Write to file
	data, err := yaml.Marshal(defaultConfig)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(configPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	// Create subdirectories for provider configs, cache, etc.
	if err := os.MkdirAll(filepath.Join(configDir, "providers"), 0755); err != nil {
		return fmt.Errorf("failed to create providers directory: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(configDir, "cache"), 0755); err != nil {
		return fmt.Errorf("failed to create cache directory: %w", err)
	}

	fmt.Printf("Created yay-friend configuration directory at %s\n", configDir)
	fmt.Printf("Main configuration file: %s\n", configPath)
	fmt.Println("You can edit the config.yaml file to customize your settings.")

	return nil
}

// setDefaults sets default configuration values
func setDefaults() {
	viper.SetDefault("default_provider", "claude")
	viper.SetDefault("providers.claude", "")
	viper.SetDefault("providers.qwen", "")
	viper.SetDefault("providers.copilot", "")
	viper.SetDefault("providers.goose", "")
	
	viper.SetDefault("security_thresholds.block_level", int(types.SecurityCritical))
	viper.SetDefault("security_thresholds.warn_level", int(types.SecurityMedium))
	viper.SetDefault("security_thresholds.auto_proceed_safe", false)
	
	viper.SetDefault("ui.show_details", true)
	viper.SetDefault("ui.use_colors", true)
	viper.SetDefault("ui.verbose_output", false)
	
	viper.SetDefault("yay.path", "yay")
	viper.SetDefault("yay.default_flags", []string{})
}

// validateConfig validates the configuration
func validateConfig(cfg *types.Config) error {
	// Validate provider exists
	validProviders := map[string]bool{
		"claude":  true,
		"qwen":    true,
		"copilot": true,
		"goose":   true,
	}

	if cfg.DefaultProvider != "" && !validProviders[cfg.DefaultProvider] {
		return fmt.Errorf("invalid default provider: %s", cfg.DefaultProvider)
	}

	// Validate security levels
	if cfg.SecurityThresholds.BlockLevel < types.SecuritySafe || cfg.SecurityThresholds.BlockLevel > types.SecurityCritical {
		return fmt.Errorf("invalid block level: %d", cfg.SecurityThresholds.BlockLevel)
	}

	if cfg.SecurityThresholds.WarnLevel < types.SecuritySafe || cfg.SecurityThresholds.WarnLevel > types.SecurityCritical {
		return fmt.Errorf("invalid warn level: %d", cfg.SecurityThresholds.WarnLevel)
	}

	return nil
}