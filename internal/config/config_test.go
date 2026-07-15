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
