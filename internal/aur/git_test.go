package aur

import (
	"testing"
)

func TestGetAURGitURL(t *testing.T) {
	tests := []struct {
		packageName string
		expected    string
	}{
		{"yay", "https://aur.archlinux.org/yay.git"},
		{"vim", "https://aur.archlinux.org/vim.git"},
		{"test-package", "https://aur.archlinux.org/test-package.git"},
		{"package_with_underscores", "https://aur.archlinux.org/package_with_underscores.git"},
		{"package-with-hyphens", "https://aur.archlinux.org/package-with-hyphens.git"},
	}

	for _, test := range tests {
		result := GetAURGitURL(test.packageName)
		if result != test.expected {
			t.Errorf("GetAURGitURL(%q) = %q, expected %q", test.packageName, result, test.expected)
		}
	}
}

func TestValidateCommitHash(t *testing.T) {
	tests := []struct {
		hash     string
		expected bool
	}{
		// Valid commit hashes
		{"1234567890abcdef1234567890abcdef12345678", true},
		{"1234567890ABCDEF1234567890ABCDEF12345678", true},
		{"0000000000000000000000000000000000000000", true},
		{"ffffffffffffffffffffffffffffffffffffffff", true},
		{"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", true},
		{"a1b2c3d4e5f6789012345678901234567890abcd", true},
		
		// Invalid commit hashes
		{"", false},                                          // Empty
		{"123", false},                                       // Too short
		{"1234567890abcdef1234567890abcdef1234567", false},   // 39 characters (too short)
		{"1234567890abcdef1234567890abcdef123456789", false}, // 41 characters (too long)
		{"1234567890abcdefg234567890abcdef12345678", false},  // Contains invalid character 'g'
		{"1234567890abcdef 234567890abcdef12345678", false},  // Contains space
		{"1234567890abcdef-234567890abcdef12345678", false},  // Contains hyphen
		{"not-a-valid-commit-hash-at-all", false},           // Completely invalid
		{"1234567890abcdef1234567890abcdef1234567z", false},  // Contains invalid character 'z'
	}

	for _, test := range tests {
		result := ValidateCommitHash(test.hash)
		if result != test.expected {
			t.Errorf("ValidateCommitHash(%q) = %v, expected %v", test.hash, result, test.expected)
		}
	}
}

// Note: We skip testing GetLatestCommitHash because it requires network access
// and external dependencies. In a full test suite, this would be tested with mocks
// or in integration tests.
func TestGetLatestCommitHash_NotImplemented(t *testing.T) {
	// This test is intentionally skipped to avoid network calls in unit tests
	t.Skip("GetLatestCommitHash requires network access and is not suitable for unit tests")
	
	// In a real test suite, we would mock the git command or use a test repository
	// Example integration test (would require git and network):
	// 
	// ctx := context.Background()
	// commitHash, err := GetLatestCommitHash(ctx, "yay")
	// if err != nil {
	//     t.Fatalf("Failed to get commit hash: %v", err)
	// }
	// 
	// if !ValidateCommitHash(commitHash) {
	//     t.Errorf("GetLatestCommitHash returned invalid commit hash: %s", commitHash)
	// }
}