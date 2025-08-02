package reporter

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aaronsb/yay-friend/internal/types"
)

// getDataDir returns the XDG-compliant data directory for reports
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

// MaliciousPackageReport represents a report of a potentially malicious package
type MaliciousPackageReport struct {
	ID              string                  `json:"id"`
	Timestamp       time.Time               `json:"timestamp"`
	PackageName     string                  `json:"package_name"`
	PackageVersion  string                  `json:"package_version"`
	Maintainer      string                  `json:"maintainer"`
	SecurityLevel   types.SecurityLevel     `json:"security_level"`
	Findings        []types.SecurityFinding `json:"findings"`
	PKGBUILDHash    string                  `json:"pkgbuild_hash"`
	PKGBUILDContent string                  `json:"pkgbuild_content,omitempty"` // Optional, only if user consents
	Provider        string                  `json:"provider"`
	ReporterID      string                  `json:"reporter_id"`     // Anonymous ID for the reporter
	UserConsent     bool                    `json:"user_consent"`    // Whether user consented to share PKGBUILD
	ReportReason    string                  `json:"report_reason"`   // User-provided reason
}

// ReportTarget represents where reports can be sent
type ReportTarget struct {
	Name        string `json:"name"`
	Endpoint    string `json:"endpoint"`
	Description string `json:"description"`
	Enabled     bool   `json:"enabled"`
}

// Reporter handles malicious package reporting
type Reporter struct {
	reportDir string
	config    *ReporterConfig
}

// ReporterConfig holds reporter configuration
type ReporterConfig struct {
	Targets      []ReportTarget `json:"targets"`
	AnonymousID  string         `json:"anonymous_id"`  // Persistent anonymous identifier
	AutoReport   bool           `json:"auto_report"`   // Auto-report CRITICAL findings
	SharePKGBUILD bool          `json:"share_pkgbuild"` // Whether to include PKGBUILD content
}

// NewReporter creates a new reporter instance
func NewReporter() (*Reporter, error) {
	reportDir := filepath.Join(getDataDir(), "reports")
	if err := os.MkdirAll(reportDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create reports directory: %w", err)
	}

	reporter := &Reporter{reportDir: reportDir}
	
	// Load or create config
	if err := reporter.loadConfig(); err != nil {
		return nil, fmt.Errorf("failed to load reporter config: %w", err)
	}

	return reporter, nil
}

// loadConfig loads or creates the reporter configuration
func (r *Reporter) loadConfig() error {
	configPath := filepath.Join(r.reportDir, "config.json")
	
	// Try to load existing config
	if data, err := os.ReadFile(configPath); err == nil {
		if err := json.Unmarshal(data, &r.config); err == nil {
			return nil // Successfully loaded
		}
	}

	// Create default config
	r.config = &ReporterConfig{
		Targets: []ReportTarget{
			{
				Name:        "AUR Security Database",
				Endpoint:    "https://aur-security.example.com/api/reports", // Placeholder endpoint
				Description: "Community-maintained database of AUR security issues",
				Enabled:     false, // Disabled by default
			},
			{
				Name:        "Local Archive",
				Endpoint:    "local",
				Description: "Save reports locally for manual review",
				Enabled:     true, // Always save locally
			},
		},
		AnonymousID:   generateAnonymousID(),
		AutoReport:    false, // User must opt-in
		SharePKGBUILD: false, // Privacy by default
	}

	// Save default config
	return r.saveConfig()
}

// saveConfig saves the current configuration
func (r *Reporter) saveConfig() error {
	configPath := filepath.Join(r.reportDir, "config.json")
	data, err := json.MarshalIndent(r.config, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(configPath, data, 0644)
}

// ReportMaliciousPackage creates and potentially submits a malicious package report
func (r *Reporter) ReportMaliciousPackage(packageName, packageVersion, maintainer string, 
	analysis *types.SecurityAnalysis, pkgbuildContent, reason string, userConsent bool) error {
	
	report := MaliciousPackageReport{
		ID:              generateReportID(),
		Timestamp:       time.Now(),
		PackageName:     packageName,
		PackageVersion:  packageVersion,
		Maintainer:      maintainer,
		SecurityLevel:   analysis.OverallLevel,
		Findings:        analysis.Findings,
		PKGBUILDHash:    fmt.Sprintf("%x", sha256.Sum256([]byte(pkgbuildContent))),
		Provider:        analysis.Provider,
		ReporterID:      r.config.AnonymousID,
		UserConsent:     userConsent,
		ReportReason:    reason,
	}

	// Include PKGBUILD content if user consented and config allows
	if userConsent && r.config.SharePKGBUILD {
		report.PKGBUILDContent = pkgbuildContent
	}

	// Always save locally
	if err := r.saveLocalReport(report); err != nil {
		return fmt.Errorf("failed to save local report: %w", err)
	}

	// Submit to enabled remote targets
	for _, target := range r.config.Targets {
		if target.Enabled && target.Endpoint != "local" {
			if err := r.submitReport(report, target); err != nil {
				fmt.Printf("Warning: Failed to submit report to %s: %v\n", target.Name, err)
			}
		}
	}

	return nil
}

// saveLocalReport saves a report to the local reports directory
func (r *Reporter) saveLocalReport(report MaliciousPackageReport) error {
	filename := fmt.Sprintf("report_%s_%s_%s.json",
		report.Timestamp.Format("2006-01-02_150405"),
		sanitizeFilename(report.PackageName),
		report.ID[:8])
	
	reportPath := filepath.Join(r.reportDir, filename)
	
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	
	return os.WriteFile(reportPath, data, 0644)
}

// submitReport submits a report to a remote target
func (r *Reporter) submitReport(report MaliciousPackageReport, target ReportTarget) error {
	// For now, this is a stub implementation
	fmt.Printf("📡 [STUB] Would submit report for %s to %s\n", report.PackageName, target.Name)
	fmt.Printf("   Endpoint: %s\n", target.Endpoint)
	fmt.Printf("   Security Level: %s\n", report.SecurityLevel.String())
	fmt.Printf("   Findings: %d\n", len(report.Findings))
	
	// TODO: Implement actual HTTP submission
	if target.Endpoint != "local" {
		return r.submitHTTPReport(report, target)
	}
	
	return nil
}

// submitHTTPReport submits a report via HTTP (stub implementation)
func (r *Reporter) submitHTTPReport(report MaliciousPackageReport, target ReportTarget) error {
	// This is a stub - in a real implementation, this would:
	// 1. Validate the endpoint and authentication
	// 2. Submit the report via HTTPS
	// 3. Handle rate limiting and retries
	// 4. Verify receipt
	
	jsonData, err := json.Marshal(report)
	if err != nil {
		return fmt.Errorf("failed to marshal report: %w", err)
	}

	// Simulate HTTP request (stub)
	fmt.Printf("🚫 [STUB] HTTP submission not implemented\n")
	fmt.Printf("   Would POST %d bytes to %s\n", len(jsonData), target.Endpoint)
	
	// In real implementation:
	// resp, err := http.Post(target.Endpoint, "application/json", bytes.NewBuffer(jsonData))
	// return handleHTTPResponse(resp, err)
	
	return fmt.Errorf("HTTP submission not yet implemented")
}

// GetReports retrieves local reports
func (r *Reporter) GetReports(packageName string, days int) ([]MaliciousPackageReport, error) {
	var reports []MaliciousPackageReport
	cutoffTime := time.Now().AddDate(0, 0, -days)

	entries, err := os.ReadDir(r.reportDir)
	if err != nil {
		return reports, fmt.Errorf("failed to read reports directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), "report_") || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		filePath := filepath.Join(r.reportDir, entry.Name())
		data, err := os.ReadFile(filePath)
		if err != nil {
			continue
		}

		var report MaliciousPackageReport
		if err := json.Unmarshal(data, &report); err != nil {
			continue
		}

		// Filter by date and package name
		if report.Timestamp.Before(cutoffTime) {
			continue
		}
		
		if packageName != "" && report.PackageName != packageName {
			continue
		}

		reports = append(reports, report)
	}

	return reports, nil
}

// Utility functions

func generateAnonymousID() string {
	// Generate a random 16-byte ID
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

func generateReportID() string {
	// Generate a unique report ID
	bytes := make([]byte, 8)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

func sanitizeFilename(filename string) string {
	// Reuse the sanitization logic from logger
	replacer := strings.NewReplacer(
		"/", "_", "\\", "_", ":", "_", "*", "_",
		"?", "_", "\"", "_", "<", "_", ">", "_",
		"|", "_", " ", "_",
	)
	return replacer.Replace(filename)
}