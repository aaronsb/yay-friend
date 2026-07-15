package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadOverlayOnDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("default_provider: claude\nclaude:\n  model: opus\n"), 0644); err != nil {
		t.Fatal(err)
	}
	SetConfigPath(path)
	defer SetConfigPath("")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	// Overridden value from the file.
	if cfg.Claude.Model != "opus" {
		t.Errorf("Claude.Model = %q, want opus", cfg.Claude.Model)
	}
	// Untouched values keep their defaults.
	if cfg.Cache.MaxAgeDays != 90 {
		t.Errorf("Cache.MaxAgeDays = %d, want 90 (default preserved)", cfg.Cache.MaxAgeDays)
	}
	if cfg.Prompts.SecurityAnalysis == "" {
		t.Error("Prompts.SecurityAnalysis empty; default prompt not preserved")
	}
}

func TestLoadMissingFileUsesDefaults(t *testing.T) {
	SetConfigPath(filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	defer SetConfigPath("")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load with missing file should succeed: %v", err)
	}
	if cfg.Claude.Model != DefaultClaudeModel {
		t.Errorf("Claude.Model = %q, want default %q", cfg.Claude.Model, DefaultClaudeModel)
	}
}

func TestLoadRejectsInvalidConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("default_provider: bogus\n"), 0644); err != nil {
		t.Fatal(err)
	}
	SetConfigPath(path)
	defer SetConfigPath("")

	if _, err := Load(); err == nil {
		t.Error("expected Load to reject invalid default_provider, got nil error")
	}
}

func TestSetRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	SetConfigPath(path)
	defer SetConfigPath("")

	if err := Set("claude.model", "opus"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Claude.Model != "opus" {
		t.Errorf("Claude.Model = %q, want opus", cfg.Claude.Model)
	}
}

// TestSetCreatesFileAtOverridePath guards the bug where Set bootstrapped the
// default path instead of the resolved --config path (clobbering the real
// config). Setting to a not-yet-existing override path must create THAT file.
func TestSetCreatesFileAtOverridePath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "custom.yaml")
	SetConfigPath(path)
	defer SetConfigPath("")

	if err := Set("claude.model", "opus"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("Set did not create the file at the override path: %v", err)
	}
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Claude.Model != "opus" {
		t.Errorf("Claude.Model = %q, want opus", cfg.Claude.Model)
	}
}

func TestSetPreservesScalarTypes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	SetConfigPath(path)
	defer SetConfigPath("")

	if err := Set("cache.enabled", "false"); err != nil {
		t.Fatalf("Set bool: %v", err)
	}
	if err := Set("cache.max_age_days", "30"); err != nil {
		t.Fatalf("Set int: %v", err)
	}
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Cache.Enabled {
		t.Error("cache.enabled = true, want false (bool not preserved)")
	}
	if cfg.Cache.MaxAgeDays != 30 {
		t.Errorf("cache.max_age_days = %d, want 30 (int not preserved)", cfg.Cache.MaxAgeDays)
	}
}

func TestSetRejectsBadInput(t *testing.T) {
	cases := []struct {
		name, key, value string
	}{
		{"unknown key", "claude.modle", "opus"},      // typo -> unknown field
		{"float into int", "cache.max_age_days", "1.2"},
		{"invalid provider", "default_provider", "bogus"},
		{"type mismatch", "cache.enabled", "notabool"},
		{"empty key", "", "x"},
		{"empty segment", "claude..model", "opus"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err := writeDefaultConfigFile(path); err != nil {
				t.Fatal(err)
			}
			before, _ := os.ReadFile(path)

			SetConfigPath(path)
			defer SetConfigPath("")

			if err := Set(tc.key, tc.value); err == nil {
				t.Errorf("Set(%q, %q) succeeded, want error", tc.key, tc.value)
			}
			// A rejected Set must not modify the file.
			after, _ := os.ReadFile(path)
			if string(before) != string(after) {
				t.Error("rejected Set modified the config file")
			}
		})
	}
}

func TestSetNested(t *testing.T) {
	t.Run("creates nested section", func(t *testing.T) {
		m := map[string]any{}
		if err := setNested(m, []string{"claude", "model"}, "opus"); err != nil {
			t.Fatal(err)
		}
		child, ok := m["claude"].(map[string]any)
		if !ok || child["model"] != "opus" {
			t.Errorf("nested set failed: %#v", m)
		}
	})

	t.Run("sets into existing section", func(t *testing.T) {
		m := map[string]any{"claude": map[string]any{"model": "sonnet"}}
		if err := setNested(m, []string{"claude", "model"}, "opus"); err != nil {
			t.Fatal(err)
		}
		if m["claude"].(map[string]any)["model"] != "opus" {
			t.Errorf("did not overwrite existing key: %#v", m)
		}
	})

	t.Run("errors when path crosses a scalar", func(t *testing.T) {
		m := map[string]any{"claude": "not-a-section"}
		if err := setNested(m, []string{"claude", "model"}, "opus"); err == nil {
			t.Error("expected error when a path segment is not a section")
		}
	})
}
