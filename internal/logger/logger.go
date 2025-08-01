package logger

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

// getDataDir returns the XDG-compliant data directory for evaluations
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

// EvaluationLog represents a single security evaluation record
type EvaluationLog struct {
	ID             string                  `json:"id"`             // Unique identifier for this evaluation
	Timestamp      time.Time               `json:"timestamp"`
	PackageName    string                  `json:"package_name"`
	PackageVersion string                  `json:"package_version"`
	Provider       string                  `json:"provider"`
	Analysis       *types.SecurityAnalysis `json:"analysis"`
	UserAction     string                  `json:"user_action"`    // "approved", "rejected", "analyzed_only"
	YayCommand     string                  `json:"yay_command"`    // Original yay command
	PKGBUILDHash   string                  `json:"pkgbuild_hash"`  // SHA256 hash of PKGBUILD content
	ConfigSnapshot *types.Config           `json:"config_snapshot"` // Config used for evaluation
}

// Logger handles evaluation logging
type Logger struct {
	logDir string
}

// NewLogger creates a new logger instance
func NewLogger() (*Logger, error) {
	logDir := filepath.Join(getDataDir(), "evaluations")
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create log directory: %w", err)
	}

	return &Logger{logDir: logDir}, nil
}

// LogEvaluation records a security evaluation as a separate JSON file
func (l *Logger) LogEvaluation(packageName, packageVersion, provider, pkgbuildContent string, analysis *types.SecurityAnalysis, userAction, yayCommand string, config *types.Config) error {
	timestamp := time.Now()
	
	// Generate unique ID from timestamp and package name
	idHash := sha256.Sum256([]byte(fmt.Sprintf("%s-%s-%d", packageName, provider, timestamp.UnixNano())))
	id := fmt.Sprintf("%x", idHash)[:12] // Use first 12 characters
	
	// Generate PKGBUILD hash
	pkgbuildHash := fmt.Sprintf("%x", sha256.Sum256([]byte(pkgbuildContent)))
	
	log := EvaluationLog{
		ID:             id,
		Timestamp:      timestamp,
		PackageName:    packageName,
		PackageVersion: packageVersion,
		Provider:       provider,
		Analysis:       analysis,
		UserAction:     userAction,
		YayCommand:     yayCommand,
		PKGBUILDHash:   pkgbuildHash,
		ConfigSnapshot: config,
	}

	// Create filename: YYYY-MM-DD_HHMMSS_package-name_id.json
	filename := fmt.Sprintf("%s_%s_%s.json", 
		timestamp.Format("2006-01-02_150405"),
		sanitizeFilename(packageName),
		id)
	
	logFile := filepath.Join(l.logDir, filename)

	// Write log entry as JSON file
	jsonData, err := json.MarshalIndent(log, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal log entry: %w", err)
	}

	if err := os.WriteFile(logFile, jsonData, 0644); err != nil {
		return fmt.Errorf("failed to write log file: %w", err)
	}

	return nil
}

// sanitizeFilename removes or replaces characters that are problematic in filenames
func sanitizeFilename(filename string) string {
	// Replace problematic characters with underscores
	replacer := strings.NewReplacer(
		"/", "_",
		"\\", "_",
		":", "_",
		"*", "_",
		"?", "_",
		"\"", "_",
		"<", "_",
		">", "_",
		"|", "_",
		" ", "_",
	)
	return replacer.Replace(filename)
}

// GetEvaluationHistory retrieves evaluation history for a package
func (l *Logger) GetEvaluationHistory(packageName string, days int) ([]EvaluationLog, error) {
	var results []EvaluationLog
	cutoffTime := time.Now().AddDate(0, 0, -days)
	
	// Read all JSON files in the evaluations directory
	entries, err := os.ReadDir(l.logDir)
	if err != nil {
		return results, fmt.Errorf("failed to read evaluations directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		// Read and parse JSON file
		filePath := filepath.Join(l.logDir, entry.Name())
		data, err := os.ReadFile(filePath)
		if err != nil {
			continue // Skip files we can't read
		}

		var log EvaluationLog
		if err := json.Unmarshal(data, &log); err != nil {
			continue // Skip malformed files
		}

		// Filter by date and package name
		if log.Timestamp.Before(cutoffTime) {
			continue
		}
		
		if packageName != "" && log.PackageName != packageName {
			continue
		}

		results = append(results, log)
	}

	// Sort by timestamp (newest first)
	sort.Slice(results, func(i, j int) bool {
		return results[i].Timestamp.After(results[j].Timestamp)
	})

	return results, nil
}

// GetRecentEvaluations gets the most recent evaluations
func (l *Logger) GetRecentEvaluations(limit int) ([]EvaluationLog, error) {
	// Get all evaluations from the last 30 days and limit them
	allEvaluations, err := l.GetEvaluationHistory("", 30)
	if err != nil {
		return nil, err
	}

	// Limit results
	if len(allEvaluations) > limit {
		allEvaluations = allEvaluations[:limit]
	}

	return allEvaluations, nil
}

// GetSecurityStats returns security statistics
func (l *Logger) GetSecurityStats(days int) (SecurityStats, error) {
	logs, err := l.GetEvaluationHistory("", days)
	if err != nil {
		return SecurityStats{}, err
	}

	stats := SecurityStats{
		TotalEvaluations: len(logs),
		LevelCounts:      make(map[types.SecurityLevel]int),
		ProviderCounts:   make(map[string]int),
		ActionCounts:     make(map[string]int),
	}

	for _, log := range logs {
		if log.Analysis != nil {
			stats.LevelCounts[log.Analysis.OverallLevel]++
		}
		stats.ProviderCounts[log.Provider]++
		stats.ActionCounts[log.UserAction]++
	}

	return stats, nil
}

// SecurityStats represents security evaluation statistics
type SecurityStats struct {
	TotalEvaluations int                              `json:"total_evaluations"`
	LevelCounts      map[types.SecurityLevel]int      `json:"level_counts"`
	ProviderCounts   map[string]int                   `json:"provider_counts"`
	ActionCounts     map[string]int                   `json:"action_counts"`
}

// CleanOldLogs removes evaluation files older than specified days
func (l *Logger) CleanOldLogs(daysToKeep int) error {
	cutoffDate := time.Now().AddDate(0, 0, -daysToKeep)
	
	entries, err := os.ReadDir(l.logDir)
	if err != nil {
		return fmt.Errorf("failed to read evaluations directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		// Parse the timestamp from filename (YYYY-MM-DD_HHMMSS_package_id.json)
		parts := strings.Split(entry.Name(), "_")
		if len(parts) < 2 {
			continue // Skip files that don't match our naming pattern
		}

		// Try to parse the date part
		datePart := parts[0]
		timePart := parts[1]
		dateTimeStr := datePart + "_" + timePart
		
		fileTime, err := time.Parse("2006-01-02_150405", dateTimeStr)
		if err != nil {
			continue // Skip files with invalid timestamp format
		}

		if fileTime.Before(cutoffDate) {
			logFile := filepath.Join(l.logDir, entry.Name())
			if err := os.Remove(logFile); err != nil {
				fmt.Printf("Warning: Failed to remove old evaluation file %s: %v\n", entry.Name(), err)
			}
		}
	}

	return nil
}