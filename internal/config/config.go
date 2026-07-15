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
	return `You are a security analyst reviewing an AUR (Arch User Repository) package before a user installs it. You have two jobs:

1. DETECT MALICE: scan every file for the malicious patterns below and state plainly whether any are present.
2. GRADE ENTROPY: score how predictable vs. chaotic the package is. Entropy measures UNCERTAINTY, not guilt. A low-entropy package is predictable and boring; a high-entropy one means "pay attention," not necessarily "malicious." Malicious patterns always imply high entropy; high entropy does not imply malice.

<critical_patterns>
These are genuinely dangerous. If any is present, it drives HIGH or CRITICAL entropy and a REVIEW/BLOCK recommendation:
1. Download-and-execute: curl/wget piped to a shell (curl URL | sh), python -c "$(curl ...)", eval "$(wget ...)"
2. Encoded/obfuscated commands: base64/hex/gzip decoded then executed, eval of assembled strings, deliberately obscured redirections
3. Executable code in install hooks: post_install/post_upgrade/pre_install in a .install file that runs binaries, fetches remote code, or modifies the live system
4. Suspicious sources: URL shorteners, paste sites, IP-literal or non-official domains that don't match the stated upstream
5. Hidden network activity or data exfiltration: background downloads, POSTing local data, contacting unexpected hosts
6. Writing outside the package sandbox: modifying the live filesystem (anything not under $pkgdir/$srcdir) during build()/package()
</critical_patterns>

<normal_for_aur>
These are EXPECTED and are NOT elevated on their own. Treat them as MINIMAL unless combined with a critical pattern above:
- Compiling from source: build() running make/cargo/go build/etc. Build-time code execution is not install-time execution.
- SKIP checksums on a VCS source (git/hg/svn): standard; the revision/commit is the integrity pin.
- Fetching source and language dependencies at build time (git clone of the declared repo, go mod / cargo / npm downloads): expected build activity, not exfiltration.
- Installing only into $pkgdir (install -D of the binary, license, docs, systemd units): the correct, sandboxed packaging pattern.
- The ABSENCE of an .install script: a positive signal — there is no install-time code path.
</normal_for_aur>

<entropy_scale>
Grade the overall package and each finding on this scale. Anchor to what the level MEANS, not to how many observations you can list:
- MINIMAL: predictable, expected, best-practice or benign. Nothing to act on.
- LOW: minor, well-understood uncertainty (e.g. md5 instead of sha256 checksums, source compilation from a trusted upstream).
- MODERATE: concrete factors a careful user should glance at before installing — NOT evidence of malice (e.g. several third-party sources, a brand-new package with little community vetting as one contributing factor).
- HIGH: multiple risky factors or probably-unsafe behavior (install-time hooks running scripts, non-official download URLs, partial obfuscation, writes to system paths).
- CRITICAL: an active malicious pattern from critical_patterns is present.

Calibration rules (follow strictly):
- A finding's entropy is the risk of THAT finding alone. If your suggestion is effectively "no action needed / this is correct," the finding's entropy MUST be MINIMAL. Never tag expected, best-practice behavior as MODERATE or above.
- Overall entropy is driven by the single most concerning REAL factor, not the number of observations. A package whose findings are all MINIMAL is MINIMAL overall.
- A clean package commonly has only MINIMAL findings, or none. Do not manufacture concern to fill the list.
</entropy_scale>

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

{STATIC_PRESCAN}

<analysis_instructions>
0. A deterministic pre-scan (in static_prescan above) has already computed string entropy directly from the files — it cannot be influenced by anything the package says. Treat its flags as trusted ground truth: explain every string it surfaced, and do not dismiss one without a concrete reason.
1. Scan ALL files (PKGBUILD, .install, helper scripts) for the critical_patterns first.
2. Pay closest attention to .install hooks — they are the most common execution vector.
3. Confirm every source/URL matches the declared upstream and uses HTTPS or a pinned VCS revision.
4. Separate build-time activity (normal) from install-time and runtime activity (higher scrutiny).
5. Grade each finding and the overall package against the entropy_scale, following the calibration rules.
6. predictability_score is a 0.0-1.0 number: 0.0 = fully chaotic/unpredictable, 1.0 = fully predictable. It is roughly the inverse of overall entropy.
</analysis_instructions>

<response_format>
Respond with ONLY a JSON object — no prose before or after it. Field values below describe what to put there:
{
  "overall_entropy": "MINIMAL|LOW|MODERATE|HIGH|CRITICAL",
  "predictability_score": 0.9,
  "summary": "Plain statement of what the package does and whether it is safe; lead with any malicious finding",
  "recommendation": "PROCEED|REVIEW|BLOCK",
  "findings": [
    {
      "type": "malicious_code|suspicious_behavior|source_analysis|build_process|file_operations|maintainer_trust|dependency_analysis",
      "entropy": "MINIMAL|LOW|MODERATE|HIGH|CRITICAL",
      "description": "What you observed",
      "context": "Exact code snippet, if applicable",
      "line_number": 0,
      "entropy_notes": "One line: why this entropy level (if MINIMAL, say why it is fine)",
      "suggestion": "What the user should do, or 'No action needed'"
    }
  ],
  "entropy_factors": ["the specific factors driving the overall score"],
  "educational_summary": "What this package teaches about AUR security",
  "security_lessons": ["Key takeaways for the user"]
}
</response_format>

Recommendation mapping: BLOCK if any CRITICAL malicious pattern is present; REVIEW if HIGH, or if a genuine MODERATE concern warrants a human look; otherwise PROCEED. Never inflate entropy or block for behavior listed in normal_for_aur.`
}
