package providers

import (
	"strings"
	"testing"

	"github.com/aaronsb/yay-friend/internal/types"
)

func TestBuildPromptInjectsPrescan(t *testing.T) {
	c := NewClaudeProvider()
	pkg := types.PackageInfo{
		Name:     "x",
		PKGBUILD: `build(){ echo "TWFsaWNpb3VzUGF5bG9hZFdpdGhIaWdoRW50cm9weTEyMzQ1" | base64 -d | sh; }`,
	}
	prompt := c.buildSimpleSecurityPrompt(pkg)
	if !strings.Contains(prompt, "<static_prescan>") {
		t.Fatal("generated prompt is missing the static_prescan block")
	}
	if !strings.Contains(prompt, "unexplained_entropy") {
		t.Errorf("pre-scan did not flag the planted payload in the prompt:\n%s", prompt)
	}
}

func TestBuildPromptCleanPackageNoFlag(t *testing.T) {
	c := NewClaudeProvider()
	pkg := types.PackageInfo{
		Name:     "hello",
		PKGBUILD: "source=('x.tar.gz')\nsha256sums=('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')",
	}
	prompt := c.buildSimpleSecurityPrompt(pkg)
	if !strings.Contains(prompt, "No anomalies") {
		t.Errorf("clean package should pre-scan clean; prompt:\n%s", prompt)
	}
}

func TestExtractClaudeResult(t *testing.T) {
	tests := []struct {
		name    string
		output  string
		want    string
		wantErr bool
	}{
		{
			name:   "array envelope with result event",
			output: `[{"type":"system","subtype":"init"},{"type":"assistant"},{"type":"result","subtype":"success","is_error":false,"result":"{\"ok\":true}"}]`,
			want:   `{"ok":true}`,
		},
		{
			name:   "single result object",
			output: `{"type":"result","subtype":"success","is_error":false,"result":"{\"ok\":true}"}`,
			want:   `{"ok":true}`,
		},
		{
			name:    "result event with is_error",
			output:  `[{"type":"result","subtype":"error_during_execution","is_error":true,"result":"boom"}]`,
			wantErr: true,
		},
		{
			name:    "empty output",
			output:  "",
			wantErr: true,
		},
		{
			name:    "whitespace-only output",
			output:  "   \n\t ",
			wantErr: true,
		},
		{
			name:   "non-JSON text falls back to raw",
			output: "here is some analysis {\"ok\":true}",
			want:   `here is some analysis {"ok":true}`,
		},
		{
			name:   "array with multiple result events keeps the last",
			output: `[{"type":"result","result":"first"},{"type":"result","result":"last"}]`,
			want:   `last`,
		},
		{
			name:   "array with no result event falls back to raw",
			output: `[{"type":"system"},{"type":"assistant"}]`,
			want:   `[{"type":"system"},{"type":"assistant"}]`,
		},
		{
			name:    "malformed JSON array errors",
			output:  `[{"type":"result",`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := extractClaudeResult([]byte(tt.output))
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got result %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}
