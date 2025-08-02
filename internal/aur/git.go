package aur

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// GetLatestCommitHash fetches the latest commit hash from AUR git repository
func GetLatestCommitHash(ctx context.Context, packageName string) (string, error) {
	gitURL := GetAURGitURL(packageName)
	
	// Use git ls-remote to get the latest commit hash without cloning
	cmd := exec.CommandContext(ctx, "git", "ls-remote", gitURL, "HEAD")
	
	// Set timeout for the git command
	cmdCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	cmd = exec.CommandContext(cmdCtx, "git", "ls-remote", gitURL, "HEAD")
	
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to fetch git commit hash for %s: %w", packageName, err)
	}
	
	// Parse output: "commit_hash\tHEAD"
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) == 0 {
		return "", fmt.Errorf("no commit hash found for package %s", packageName)
	}
	
	// Extract commit hash (first part before tab)
	parts := strings.Fields(lines[0])
	if len(parts) == 0 {
		return "", fmt.Errorf("invalid git ls-remote output for package %s", packageName)
	}
	
	commitHash := parts[0]
	
	// Validate commit hash format (should be 40 character hex string)
	if len(commitHash) != 40 {
		return "", fmt.Errorf("invalid commit hash format for package %s: %s", packageName, commitHash)
	}
	
	return commitHash, nil
}

// GetAURGitURL returns the AUR git repository URL for a package
func GetAURGitURL(packageName string) string {
	return fmt.Sprintf("https://aur.archlinux.org/%s.git", packageName)
}

// ValidateCommitHash checks if a commit hash has the correct format
func ValidateCommitHash(hash string) bool {
	if len(hash) != 40 {
		return false
	}
	
	// Check if all characters are hexadecimal
	for _, char := range hash {
		if !((char >= '0' && char <= '9') || (char >= 'a' && char <= 'f') || (char >= 'A' && char <= 'F')) {
			return false
		}
	}
	
	return true
}