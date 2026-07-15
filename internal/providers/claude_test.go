package providers

import "testing"

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
