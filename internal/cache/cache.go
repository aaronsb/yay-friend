package cache

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/aaronsb/yay-friend/internal/types"
)

// CacheManager handles analysis result caching
type CacheManager struct {
	cacheDir string
}

// CacheMetadata represents metadata for cached analysis
type CacheMetadata struct {
	CommitHash       string    `json:"commit_hash"`
	PackageName      string    `json:"package_name"`
	CachedAt         time.Time `json:"cached_at"`
	CacheVersion     string    `json:"cache_version"`
	YayFriendVersion string    `json:"yay_friend_version"`
}

// CachedAnalysis represents a cached analysis with metadata
type CachedAnalysis struct {
	CacheMetadata CacheMetadata          `json:"cache_metadata"`
	Analysis      *types.SecurityAnalysis `json:"analysis"`
}

// CacheStats represents cache statistics
type CacheStats struct {
	TotalPackages    int           `json:"total_packages"`
	TotalAnalyses    int           `json:"total_analyses"`
	CacheSize        int64         `json:"cache_size_bytes"`
	OldestEntry      time.Time     `json:"oldest_entry"`
	NewestEntry      time.Time     `json:"newest_entry"`
	HitRate          float64       `json:"hit_rate"`
	RecentHits       int           `json:"recent_hits"`
	RecentMisses     int           `json:"recent_misses"`
}

// getDataDir returns the XDG-compliant data directory for cache
func getDataDir() string {
	if xdgData := os.Getenv("XDG_DATA_HOME"); xdgData != "" {
		return filepath.Join(xdgData, "yay-friend")
	}
	
	home, err := os.UserHomeDir()
	if err != nil {
		// Fallback to current directory if we can't determine home
		return ".yay-friend"
	}
	
	return filepath.Join(home, ".local", "share", "yay-friend")
}

// NewCacheManager creates a new cache manager instance
func NewCacheManager() (*CacheManager, error) {
	cacheDir := filepath.Join(getDataDir(), "cache")
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create cache directory: %w", err)
	}

	return &CacheManager{cacheDir: cacheDir}, nil
}

// GetCachedAnalysis retrieves a cached analysis if it exists
func (c *CacheManager) GetCachedAnalysis(packageName, commitHash string) (*types.SecurityAnalysis, error) {
	cacheFile := c.getCacheFilePath(packageName, commitHash)
	
	// Check if cache file exists
	if _, err := os.Stat(cacheFile); os.IsNotExist(err) {
		return nil, fmt.Errorf("cache miss: no cached analysis found for %s@%s", packageName, commitHash[:8])
	}
	
	// Read and parse cached analysis
	data, err := os.ReadFile(cacheFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read cache file: %w", err)
	}
	
	var cached CachedAnalysis
	if err := json.Unmarshal(data, &cached); err != nil {
		return nil, fmt.Errorf("failed to parse cached analysis: %w", err)
	}
	
	// Validate commit hash matches
	if cached.CacheMetadata.CommitHash != commitHash {
		return nil, fmt.Errorf("cache corruption: commit hash mismatch")
	}
	
	return cached.Analysis, nil
}

// SaveAnalysis saves an analysis result to cache
func (c *CacheManager) SaveAnalysis(packageName, commitHash string, analysis *types.SecurityAnalysis) error {
	// Create package-specific cache directory
	packageDir := filepath.Join(c.cacheDir, sanitizePackageName(packageName))
	if err := os.MkdirAll(packageDir, 0755); err != nil {
		return fmt.Errorf("failed to create package cache directory: %w", err)
	}
	
	// Create cached analysis with metadata
	cached := CachedAnalysis{
		CacheMetadata: CacheMetadata{
			CommitHash:       commitHash,
			PackageName:      packageName,
			CachedAt:         time.Now(),
			CacheVersion:     "1.0",
			YayFriendVersion: "1.0.0", // TODO: Get this from build info
		},
		Analysis: analysis,
	}
	
	// Marshal to JSON
	data, err := json.MarshalIndent(cached, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal cached analysis: %w", err)
	}
	
	// Write to cache file
	cacheFile := c.getCacheFilePath(packageName, commitHash)
	if err := os.WriteFile(cacheFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write cache file: %w", err)
	}
	
	return nil
}

// IsCached checks if an analysis is cached for the given package and commit hash
func (c *CacheManager) IsCached(packageName, commitHash string) bool {
	cacheFile := c.getCacheFilePath(packageName, commitHash)
	_, err := os.Stat(cacheFile)
	return err == nil
}

// CleanExpiredCache removes cache entries older than maxAge
func (c *CacheManager) CleanExpiredCache(maxAge time.Duration) error {
	cutoffTime := time.Now().Add(-maxAge)
	removedCount := 0
	
	err := filepath.Walk(c.cacheDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		
		// Skip directories and non-JSON files
		if info.IsDir() || !strings.HasSuffix(info.Name(), ".json") {
			return nil
		}
		
		// Check if file is older than cutoff
		if info.ModTime().Before(cutoffTime) {
			if err := os.Remove(path); err != nil {
				fmt.Printf("Warning: Failed to remove expired cache file %s: %v\n", path, err)
			} else {
				removedCount++
			}
		}
		
		return nil
	})
	
	if err != nil {
		return fmt.Errorf("failed to clean cache: %w", err)
	}
	
	if removedCount > 0 {
		fmt.Printf("🧹 Cleaned %d expired cache entries\n", removedCount)
	}
	
	return nil
}

// GetCacheStats returns cache statistics
func (c *CacheManager) GetCacheStats() (CacheStats, error) {
	stats := CacheStats{
		HitRate: 0.0,
	}
	
	packages := make(map[string]bool)
	var totalSize int64
	var oldestTime, newestTime time.Time
	fileCount := 0
	
	err := filepath.Walk(c.cacheDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		
		// Skip directories and non-JSON files
		if info.IsDir() || !strings.HasSuffix(info.Name(), ".json") {
			return nil
		}
		
		// Count file
		fileCount++
		totalSize += info.Size()
		
		// Track oldest and newest
		if oldestTime.IsZero() || info.ModTime().Before(oldestTime) {
			oldestTime = info.ModTime()
		}
		if newestTime.IsZero() || info.ModTime().After(newestTime) {
			newestTime = info.ModTime()
		}
		
		// Try to determine package name from path
		dir := filepath.Dir(path)
		packageName := filepath.Base(dir)
		if packageName != filepath.Base(c.cacheDir) {
			packages[packageName] = true
		}
		
		return nil
	})
	
	if err != nil {
		return stats, fmt.Errorf("failed to calculate cache stats: %w", err)
	}
	
	stats.TotalPackages = len(packages)
	stats.TotalAnalyses = fileCount
	stats.CacheSize = totalSize
	stats.OldestEntry = oldestTime
	stats.NewestEntry = newestTime
	
	return stats, nil
}

// GetPackageVersions returns all cached versions (commit hashes) for a package
func (c *CacheManager) GetPackageVersions(packageName string) ([]string, error) {
	packageDir := filepath.Join(c.cacheDir, sanitizePackageName(packageName))
	
	entries, err := os.ReadDir(packageDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil // No cached versions
		}
		return nil, fmt.Errorf("failed to read package cache directory: %w", err)
	}
	
	var versions []string
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		
		// Extract commit hash from filename (remove .json extension)
		commitHash := strings.TrimSuffix(entry.Name(), ".json")
		versions = append(versions, commitHash)
	}
	
	// Sort versions (most recent first if we can determine)
	sort.Strings(versions)
	
	return versions, nil
}

// getCacheFilePath returns the full path for a cache file
func (c *CacheManager) getCacheFilePath(packageName, commitHash string) string {
	packageDir := filepath.Join(c.cacheDir, sanitizePackageName(packageName))
	return filepath.Join(packageDir, commitHash+".json")
}

// sanitizePackageName cleans a package name for use as a directory name
func sanitizePackageName(packageName string) string {
	// Replace problematic characters with underscores
	replacer := strings.NewReplacer(
		"/", "_", "\\", "_", ":", "_", "*", "_",
		"?", "_", "\"", "_", "<", "_", ">", "_",
		"|", "_", " ", "_",
	)
	return replacer.Replace(packageName)
}

// Hash generates a consistent hash for additional validation
func (c *CacheManager) Hash(packageName, commitHash string) string {
	data := packageName + ":" + commitHash
	hash := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x", hash)[:16] // First 16 characters
}