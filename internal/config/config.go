package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"

	"github.com/aaronsb/yay-friend/internal/types"
)

// getConfigDir returns the XDG-compliant config directory
func getConfigDir() string {
	if xdgConfig := os.Getenv("XDG_CONFIG_HOME"); xdgConfig != "" {
		return filepath.Join(xdgConfig, "yay-friend")
	}
	
	home, err := os.UserHomeDir()
	if err != nil {
		// Fallback to current directory if we can't determine home
		return ".yay-friend"
	}
	
	return filepath.Join(home, ".config", "yay-friend")
}

// Load loads the configuration from file
func Load() (*types.Config, error) {
	// For now, return hardcoded sensible defaults to get the tool working
	// TODO: Implement proper YAML config loading later
	cfg := &types.Config{
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
			BlockLevel:  types.SecurityCritical, // Only block CRITICAL
			WarnLevel:   types.SecurityMedium,   // Warn on MODERATE and above
			AutoProceed: false,
		},
		Cache: struct {
			Enabled      bool `yaml:"enabled"`
			MaxAgeDays   int  `yaml:"max_age_days"`
			MaxSizeMB    int  `yaml:"max_size_mb"`
			Compress     bool `yaml:"compress"`
		}{
			Enabled:      true,
			MaxAgeDays:   90,
			MaxSizeMB:    100,
			Compress:     false,
		},
		Prompts: struct {
			SecurityAnalysis string `yaml:"security_analysis"`
		}{
			SecurityAnalysis: getDefaultSecurityPrompt(),
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

	return cfg, nil
}

// InitializeConfig creates a default configuration directory and file
func InitializeConfig() error {
	configDir := getConfigDir()
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
		Cache: struct {
			Enabled      bool `yaml:"enabled"`
			MaxAgeDays   int  `yaml:"max_age_days"`
			MaxSizeMB    int  `yaml:"max_size_mb"`
			Compress     bool `yaml:"compress"`
		}{
			Enabled:      true,
			MaxAgeDays:   90,
			MaxSizeMB:    100,
			Compress:     false,
		},
		Prompts: struct {
			SecurityAnalysis string `yaml:"security_analysis"`
		}{
			SecurityAnalysis: getDefaultSecurityPrompt(),
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
	
	// Use the same key structure as the YAML
	viper.SetDefault("security_thresholds.block_level", int(types.SecurityCritical))
	viper.SetDefault("security_thresholds.warn_level", int(types.SecurityMedium))
	viper.SetDefault("security_thresholds.auto_proceed_safe", false)
	
	viper.SetDefault("cache.enabled", true)
	viper.SetDefault("cache.max_age_days", 90)
	viper.SetDefault("cache.max_size_mb", 100)
	viper.SetDefault("cache.compress", false)
	
	viper.SetDefault("prompts.security_analysis", getDefaultSecurityPrompt())
	
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

// getDefaultSecurityPrompt returns the default security analysis prompt template
func getDefaultSecurityPrompt() string {
	return `You are a security expert analyzing AUR packages for malicious behavior. Your PRIMARY goal is to detect and flag dangerous code patterns.

<critical_patterns>
SCAN FOR THESE MALICIOUS PATTERNS FIRST:
1. curl/wget piped to shell: curl URL | sh, wget -O- URL | bash
2. Downloading and executing code: python -c "$(curl ...)", eval "$(wget ...)"
3. Base64/hex encoded commands: echo BASE64 | base64 -d | sh
4. Commands in install hooks: post_install() running executables
5. Suspicious URLs: URL shorteners, paste sites, non-official domains
6. Hidden network activity: Background downloads, data exfiltration
7. System modification: Writing to /usr/bin during build, modifying system files
8. Obfuscated scripts: Encoded strings, complex redirections, hidden commands
</critical_patterns>

<package_context>
Name: {NAME} | Version: {VERSION} | Maintainer: {MAINTAINER}
Votes: {VOTES} | Popularity: {POPULARITY}
First Submitted: {FIRST_SUBMITTED} | Last Updated: {LAST_UPDATED}
Dependencies: {DEPENDENCIES}
Build Dependencies: {MAKE_DEPENDS}
</package_context>

<pkgbuild_content>
{PKGBUILD}
</pkgbuild_content>

<install_script>
{INSTALL_SCRIPT}
</install_script>

<additional_files>
{ADDITIONAL_FILES}
</additional_files>

<analysis_instructions>
1. FIRST check ALL files for the critical patterns listed above
2. Pay special attention to .install scripts and helper scripts
3. Look for ANY network activity (curl, wget, git clone during runtime)
4. Check for code execution during install/upgrade hooks
5. Verify all URLs point to official/trusted sources
6. Flag ANY obfuscation or encoding of commands
</analysis_instructions>

<response_format>
Provide ONLY a JSON response:
{
  "overall_entropy": "MINIMAL|LOW|MODERATE|HIGH|CRITICAL",
  "summary": "Clear statement of findings, especially any malicious code",
  "recommendation": "PROCEED|REVIEW|BLOCK",
  "findings": [
    {
      "type": "malicious_code|suspicious_behavior|source_analysis|build_process|file_operations|maintainer_trust|dependency_analysis",
      "entropy": "MINIMAL|LOW|MODERATE|HIGH|CRITICAL",
      "description": "Specific description of the threat",
      "context": "Exact code snippet showing the issue",
      "line_number": 0,
      "file": "filename where found (PKGBUILD, .install, etc)",
      "suggestion": "Remove this package immediately / Review before installing / etc"
    }
  ],
  "entropy_factors": ["list of specific risk factors found"],
  "educational_summary": "What this attack vector teaches about AUR security",
  "security_lessons": ["Key takeaways for users"]
}
</response_format>

REMEMBER: Any code execution during installation, hidden network requests, or obfuscated commands should result in CRITICAL entropy and BLOCK recommendation.`
}