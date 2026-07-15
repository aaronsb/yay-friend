package config

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/aaronsb/yay-friend/internal/types"
)

// DefaultClaudeModel is the model alias passed to `claude --model` when the
// user hasn't configured one. "sonnet" resolves to the latest Sonnet: a strong,
// cost-effective choice for structured PKGBUILD security classification.
const DefaultClaudeModel = "sonnet"

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

// configFileOverride, when set via SetConfigPath (from the --config flag),
// takes precedence over the default config path.
var configFileOverride string

// SetConfigPath overrides the config file location that Load reads from.
// An empty path clears the override.
func SetConfigPath(path string) {
	configFileOverride = path
}

// configFilePath returns the config file Load should read.
func configFilePath() string {
	if configFileOverride != "" {
		return configFileOverride
	}
	return filepath.Join(getConfigDir(), "config.yaml")
}

// defaultConfig returns the built-in configuration. It is both the config used
// when no file exists and the base that a user's config.yaml is overlaid onto.
func defaultConfig() *types.Config {
	cfg := &types.Config{
		DefaultProvider: "claude",
		Providers: map[string]string{
			"claude":  "",
			"qwen":    "",
			"copilot": "",
			"goose":   "",
		},
	}
	cfg.SecurityThresholds.BlockLevel = types.SecurityCritical // Only block CRITICAL
	cfg.SecurityThresholds.WarnLevel = types.SecurityMedium    // Warn on MODERATE and above
	cfg.SecurityThresholds.AutoProceed = false
	cfg.Cache.Enabled = true
	cfg.Cache.MaxAgeDays = 90
	cfg.Cache.MaxSizeMB = 100
	cfg.Cache.Compress = false
	cfg.Prompts.SecurityAnalysis = GetDefaultSecurityPrompt()
	cfg.UI.ShowDetails = true
	cfg.UI.UseColors = true
	cfg.UI.VerboseOutput = false
	cfg.Yay.Path = "yay"
	cfg.Yay.Flags = []string{}
	cfg.Claude.Model = DefaultClaudeModel
	return cfg
}

// Load builds the default configuration and overlays the user's config.yaml
// (if present) on top of it, then validates the result. When no config file
// exists, the built-in defaults are authoritative.
func Load() (*types.Config, error) {
	cfg := defaultConfig()

	path := configFilePath()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return nil, fmt.Errorf("failed to read config file %s: %w", path, err)
	}

	// Overlay: fields present in the file override defaults; absent fields keep
	// their default. The struct's yaml tags drive the mapping.
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file %s: %w", path, err)
	}

	if err := validateConfig(cfg); err != nil {
		return nil, fmt.Errorf("invalid config in %s: %w", path, err)
	}

	return cfg, nil
}

// Set applies a single dotted-key change (e.g. "claude.model") to the config
// file and persists it. It handles scalar values: the value becomes an int or
// bool when it cleanly parses as one, otherwise it stays a string — so a model
// alias like "opus" stays a string and a stray "1.2" into an int field is
// rejected rather than silently truncated. To set list/complex values, edit the
// file directly.
//
// The file is created with defaults (at the resolved --config path) if it does
// not exist. The result is validated — unknown/typo'd keys and type mismatches
// are rejected — before it is written, so an invalid change never lands on disk.
func Set(key, value string) error {
	if strings.TrimSpace(key) == "" {
		return fmt.Errorf("config key must not be empty")
	}
	keys := strings.Split(key, ".")
	if slices.Contains(keys, "") {
		return fmt.Errorf("invalid config key %q: empty path segment", key)
	}

	path := configFilePath()
	if _, err := os.Stat(path); os.IsNotExist(err) {
		if err := writeDefaultConfigFile(path); err != nil {
			return err
		}
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read config file %s: %w", path, err)
	}

	root := map[string]any{}
	if err := yaml.Unmarshal(data, &root); err != nil {
		return fmt.Errorf("failed to parse config file %s: %w", path, err)
	}

	if err := setNested(root, keys, parseScalar(value)); err != nil {
		return err
	}

	out, err := yaml.Marshal(root)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	// Validate against the typed schema before persisting. KnownFields rejects
	// unknown/typo'd keys; Decode rejects type mismatches.
	check := defaultConfig()
	dec := yaml.NewDecoder(bytes.NewReader(out))
	dec.KnownFields(true)
	if err := dec.Decode(check); err != nil {
		return fmt.Errorf("resulting config would be invalid: %w", err)
	}
	if err := validateConfig(check); err != nil {
		return fmt.Errorf("resulting config would be invalid: %w", err)
	}

	if err := os.WriteFile(path, out, 0644); err != nil {
		return fmt.Errorf("failed to write config file %s: %w", path, err)
	}
	return nil
}

// parseScalar interprets a CLI-provided value as an int or bool when it cleanly
// is one, otherwise returns it unchanged as a string. Int is tried before bool
// so "1" stays an int rather than becoming true. Floats, dates, and other shapes
// stay strings, which the typed-schema validation then accepts or rejects per
// field — avoiding silent float->int truncation or timestamp coercion.
func parseScalar(s string) any {
	if i, err := strconv.Atoi(s); err == nil {
		return i
	}
	if b, err := strconv.ParseBool(s); err == nil {
		return b
	}
	return s
}

// writeDefaultConfigFile writes the built-in defaults to path, creating parent
// directories as needed. Unlike InitializeConfig it is quiet and honors the
// exact path (used by Set to bootstrap a missing file).
func writeDefaultConfigFile(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}
	data, err := yaml.Marshal(defaultConfig())
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file %s: %w", path, err)
	}
	return nil
}

// setNested walks (creating as needed) nested maps to set a dotted key path.
func setNested(m map[string]any, keys []string, value any) error {
	for i, k := range keys {
		if i == len(keys)-1 {
			m[k] = value
			return nil
		}
		child, ok := m[k]
		if !ok {
			next := map[string]any{}
			m[k] = next
			m = next
			continue
		}
		childMap, ok := child.(map[string]any)
		if !ok {
			return fmt.Errorf("cannot set %q: %q is not a section", strings.Join(keys, "."), k)
		}
		m = childMap
	}
	return nil
}

// InitializeConfig creates a default configuration directory and file at the
// resolved config path (honoring --config).
func InitializeConfig() error {
	configPath := configFilePath()
	configDir := filepath.Dir(configPath)

	// Inform the user if we're about to overwrite an existing config.
	if _, err := os.Stat(configPath); err == nil {
		fmt.Printf("Configuration file already exists at %s\n", configPath)
		fmt.Println("Overwriting with default configuration...")
	}

	if err := writeDefaultConfigFile(configPath); err != nil {
		return err
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

	// Validate cache bounds
	if cfg.Cache.MaxAgeDays < 0 {
		return fmt.Errorf("cache.max_age_days must be >= 0, got %d", cfg.Cache.MaxAgeDays)
	}
	if cfg.Cache.MaxSizeMB < 0 {
		return fmt.Errorf("cache.max_size_mb must be >= 0, got %d", cfg.Cache.MaxSizeMB)
	}

	// yay must be invocable
	if strings.TrimSpace(cfg.Yay.Path) == "" {
		return fmt.Errorf("yay.path must not be empty")
	}

	return nil
}

// GetDefaultSecurityPrompt returns the default security analysis prompt template
func GetDefaultSecurityPrompt() string {
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
