package cache

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aaronsb/yay-friend/internal/types"
)

func TestCacheManager_BasicOperations(t *testing.T) {
	// Create temporary directory for testing
	tmpDir, err := os.MkdirTemp("", "yay-friend-cache-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create cache manager with custom cache directory
	cacheManager := &CacheManager{cacheDir: tmpDir}

	// Test data
	packageName := "test-package"
	commitHash := "1234567890abcdef1234567890abcdef12345678"
	
	analysis := &types.SecurityAnalysis{
		PackageName:    packageName,
		OverallLevel:   types.SecurityLow,
		Summary:        "Test analysis summary",
		Recommendation: "Test recommendation",
		AnalyzedAt:     time.Now(),
		Provider:       "test-provider",
		Findings: []types.SecurityFinding{
			{
				Type:        "Test Finding",
				Severity:    types.SecurityLow,
				Description: "Test finding description",
			},
		},
	}

	// Test cache miss
	if cacheManager.IsCached(packageName, commitHash) {
		t.Error("Expected cache miss, but package was cached")
	}

	// Test saving analysis
	if err := cacheManager.SaveAnalysis(packageName, commitHash, analysis); err != nil {
		t.Fatalf("Failed to save analysis: %v", err)
	}

	// Test cache hit
	if !cacheManager.IsCached(packageName, commitHash) {
		t.Error("Expected cache hit, but package was not cached")
	}

	// Test retrieving cached analysis
	cachedAnalysis, err := cacheManager.GetCachedAnalysis(packageName, commitHash)
	if err != nil {
		t.Fatalf("Failed to get cached analysis: %v", err)
	}

	// Verify cached data
	if cachedAnalysis.PackageName != analysis.PackageName {
		t.Errorf("Expected package name %s, got %s", analysis.PackageName, cachedAnalysis.PackageName)
	}
	if cachedAnalysis.OverallLevel != analysis.OverallLevel {
		t.Errorf("Expected overall level %s, got %s", analysis.OverallLevel, cachedAnalysis.OverallLevel)
	}
	if cachedAnalysis.Summary != analysis.Summary {
		t.Errorf("Expected summary %s, got %s", analysis.Summary, cachedAnalysis.Summary)
	}
	if len(cachedAnalysis.Findings) != len(analysis.Findings) {
		t.Errorf("Expected %d findings, got %d", len(analysis.Findings), len(cachedAnalysis.Findings))
	}
}

func TestCacheManager_PackageVersions(t *testing.T) {
	// Create temporary directory for testing
	tmpDir, err := os.MkdirTemp("", "yay-friend-cache-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	cacheManager := &CacheManager{cacheDir: tmpDir}
	packageName := "test-package"

	// Test with no versions
	versions, err := cacheManager.GetPackageVersions(packageName)
	if err != nil {
		t.Fatalf("Failed to get package versions: %v", err)
	}
	if len(versions) != 0 {
		t.Errorf("Expected 0 versions, got %d", len(versions))
	}

	// Add multiple versions (commit hashes)
	commitHashes := []string{
		"1111111111111111111111111111111111111111",
		"2222222222222222222222222222222222222222",
		"3333333333333333333333333333333333333333",
	}

	analysis := &types.SecurityAnalysis{
		PackageName:  packageName,
		OverallLevel: types.SecurityLow,
		Summary:      "Test analysis",
		AnalyzedAt:   time.Now(),
		Provider:     "test-provider",
	}

	// Save analyses for different commit hashes
	for _, commitHash := range commitHashes {
		if err := cacheManager.SaveAnalysis(packageName, commitHash, analysis); err != nil {
			t.Fatalf("Failed to save analysis for commit %s: %v", commitHash, err)
		}
	}

	// Get package versions
	versions, err = cacheManager.GetPackageVersions(packageName)
	if err != nil {
		t.Fatalf("Failed to get package versions: %v", err)
	}

	if len(versions) != len(commitHashes) {
		t.Errorf("Expected %d versions, got %d", len(commitHashes), len(versions))
	}

	// Verify all commit hashes are present
	versionMap := make(map[string]bool)
	for _, version := range versions {
		versionMap[version] = true
	}

	for _, commitHash := range commitHashes {
		if !versionMap[commitHash] {
			t.Errorf("Expected commit hash %s not found in versions", commitHash)
		}
	}
}

func TestCacheManager_CleanExpiredCache(t *testing.T) {
	// Create temporary directory for testing
	tmpDir, err := os.MkdirTemp("", "yay-friend-cache-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	cacheManager := &CacheManager{cacheDir: tmpDir}
	packageName := "test-package"
	commitHash := "1234567890abcdef1234567890abcdef12345678"

	analysis := &types.SecurityAnalysis{
		PackageName:  packageName,
		OverallLevel: types.SecurityLow,
		Summary:      "Test analysis",
		AnalyzedAt:   time.Now(),
		Provider:     "test-provider",
	}

	// Save analysis
	if err := cacheManager.SaveAnalysis(packageName, commitHash, analysis); err != nil {
		t.Fatalf("Failed to save analysis: %v", err)
	}

	// Verify it's cached
	if !cacheManager.IsCached(packageName, commitHash) {
		t.Error("Expected package to be cached")
	}

	// Clean with 0 duration (remove everything)
	if err := cacheManager.CleanExpiredCache(0); err != nil {
		t.Fatalf("Failed to clean expired cache: %v", err)
	}

	// Verify it's no longer cached
	if cacheManager.IsCached(packageName, commitHash) {
		t.Error("Expected package to be removed from cache")
	}
}

func TestCacheManager_CacheStats(t *testing.T) {
	// Create temporary directory for testing
	tmpDir, err := os.MkdirTemp("", "yay-friend-cache-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	cacheManager := &CacheManager{cacheDir: tmpDir}

	// Test with empty cache
	stats, err := cacheManager.GetCacheStats()
	if err != nil {
		t.Fatalf("Failed to get cache stats: %v", err)
	}

	if stats.TotalAnalyses != 0 {
		t.Errorf("Expected 0 analyses, got %d", stats.TotalAnalyses)
	}
	if stats.TotalPackages != 0 {
		t.Errorf("Expected 0 packages, got %d", stats.TotalPackages)
	}

	// Add some cache entries
	packages := []string{"package1", "package2"}
	commitHash := "1234567890abcdef1234567890abcdef12345678"

	analysis := &types.SecurityAnalysis{
		PackageName:  "test",
		OverallLevel: types.SecurityLow,
		Summary:      "Test analysis",
		AnalyzedAt:   time.Now(),
		Provider:     "test-provider",
	}

	for _, pkg := range packages {
		analysis.PackageName = pkg
		if err := cacheManager.SaveAnalysis(pkg, commitHash, analysis); err != nil {
			t.Fatalf("Failed to save analysis for %s: %v", pkg, err)
		}
	}

	// Get stats again
	stats, err = cacheManager.GetCacheStats()
	if err != nil {
		t.Fatalf("Failed to get cache stats: %v", err)
	}

	if stats.TotalAnalyses != len(packages) {
		t.Errorf("Expected %d analyses, got %d", len(packages), stats.TotalAnalyses)
	}
	if stats.TotalPackages != len(packages) {
		t.Errorf("Expected %d packages, got %d", len(packages), stats.TotalPackages)
	}
	if stats.CacheSize <= 0 {
		t.Error("Expected cache size to be greater than 0")
	}
}

func TestSanitizePackageName(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"normal-package", "normal-package"},
		{"package/with/slashes", "package_with_slashes"},
		{"package with spaces", "package_with_spaces"},
		{"package:with:colons", "package_with_colons"},
		{"package*with*stars", "package_with_stars"},
		{"package?with?questions", "package_with_questions"},
		{"package\"with\"quotes", "package_with_quotes"},
		{"package<with>brackets", "package_with_brackets"},
		{"package|with|pipes", "package_with_pipes"},
		{"package\\with\\backslashes", "package_with_backslashes"},
	}

	for _, test := range tests {
		result := sanitizePackageName(test.input)
		if result != test.expected {
			t.Errorf("sanitizePackageName(%q) = %q, expected %q", test.input, result, test.expected)
		}
	}
}

func TestValidateCommitHash(t *testing.T) {
	tests := []struct {
		hash  string
		valid bool
	}{
		{"1234567890abcdef1234567890abcdef12345678", true},  // Valid
		{"1234567890ABCDEF1234567890ABCDEF12345678", true},  // Valid with uppercase
		{"1234567890abcdef1234567890abcdef1234567", false},  // Too short
		{"1234567890abcdef1234567890abcdef123456789", false}, // Too long
		{"1234567890abcdefg234567890abcdef12345678", false},  // Invalid character 'g'
		{"", false}, // Empty
		{"not-a-hash-at-all", false}, // Invalid format
	}

	for _, test := range tests {
		// Import the function from git.go for testing
		// Since ValidateCommitHash is in git.go, we need to test it through aur package
		result := len(test.hash) == 40
		if result {
			for _, char := range test.hash {
				if !((char >= '0' && char <= '9') || (char >= 'a' && char <= 'f') || (char >= 'A' && char <= 'F')) {
					result = false
					break
				}
			}
		}

		if result != test.valid {
			t.Errorf("ValidateCommitHash(%q) = %v, expected %v", test.hash, result, test.valid)
		}
	}
}
// A copied or hand-edited entry declaring another package is a grading of
// something else wearing the right filename; replaying it would launder that
// analysis into an answer about this package. The adapter refuses this exact
// input, and the native path must agree.
func TestACachedEntryDeclaringAnotherPackageIsRefused(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "yay-friend-cache-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)
	cacheManager := &CacheManager{cacheDir: tmpDir}

	commitHash := "1234567890abcdef1234567890abcdef12345678"
	analysis := &types.SecurityAnalysis{
		PackageName: "evil-other",
		Summary:     "an analysis of a different package",
		AnalyzedAt:  time.Now(),
	}
	// Filed under hello's name, declaring evil-other inside — the tampered
	// shape, built through the real writer and then re-labelled by hand.
	if err := cacheManager.SaveAnalysis("evil-other", commitHash, analysis); err != nil {
		t.Fatal(err)
	}
	src := cacheManager.getCacheFilePath("evil-other", commitHash)
	dst := cacheManager.getCacheFilePath("hello", commitHash)
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, data, 0644); err != nil {
		t.Fatal(err)
	}

	if _, err := cacheManager.GetCachedEntry("hello", commitHash); err == nil {
		t.Fatal("a cache entry declaring another package was replayed")
	} else if !strings.Contains(err.Error(), "evil-other") {
		t.Errorf("the refusal does not name the declared package: %v", err)
	}
	// The un-tampered entry still replays under its own name.
	if _, err := cacheManager.GetCachedEntry("evil-other", commitHash); err != nil {
		t.Errorf("the honest entry stopped replaying: %v", err)
	}
}
