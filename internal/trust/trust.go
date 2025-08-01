package trust

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/aaronsb/yay-friend/internal/types"
)

// TrustScore represents the trust level of a package/maintainer
type TrustScore int

const (
	TrustVeryLow TrustScore = iota
	TrustLow
	TrustMedium
	TrustHigh
	TrustVeryHigh
)

func (t TrustScore) String() string {
	switch t {
	case TrustVeryLow:
		return "VERY_LOW"
	case TrustLow:
		return "LOW"
	case TrustMedium:
		return "MEDIUM"
	case TrustHigh:
		return "HIGH"
	case TrustVeryHigh:
		return "VERY_HIGH"
	}
	return "UNKNOWN"
}

// RepositoryInfo contains information about the AUR package repository
type RepositoryInfo struct {
	PackageName      string        `json:"package_name"`
	GitURL           string        `json:"git_url"`
	FirstCommit      time.Time     `json:"first_commit"`
	LastCommit       time.Time     `json:"last_commit"`
	CommitCount      int           `json:"commit_count"`
	Maintainer       string        `json:"maintainer"`
	Contributors     []string      `json:"contributors"`
	RepoAge          time.Duration `json:"repo_age"`
	CommitFrequency  float64       `json:"commit_frequency"` // commits per month
	MaintainerTenure time.Duration `json:"maintainer_tenure"`
}

// MaintainerReputation contains information about package maintainer reputation
type MaintainerReputation struct {
	Username           string    `json:"username"`
	PackageCount       int       `json:"package_count"`
	AccountAge         time.Duration `json:"account_age"`
	AverageRepoAge     time.Duration `json:"average_repo_age"`
	TotalCommits       int       `json:"total_commits"`
	LastActivity       time.Time `json:"last_activity"`
	ReputationScore    float64   `json:"reputation_score"` // 0.0 to 1.0
}

// TrustAnalysis contains the complete trust analysis
type TrustAnalysis struct {
	PackageName          string               `json:"package_name"`
	OverallTrustScore    TrustScore           `json:"overall_trust_score"`
	RepositoryInfo       RepositoryInfo       `json:"repository_info"`
	MaintainerReputation MaintainerReputation `json:"maintainer_reputation"`
	TrustFactors         []TrustFactor        `json:"trust_factors"`
	RiskIndicators       []RiskIndicator      `json:"risk_indicators"`
	AnalyzedAt           time.Time            `json:"analyzed_at"`
}

// TrustFactor represents a positive trust indicator
type TrustFactor struct {
	Type        string  `json:"type"`
	Description string  `json:"description"`
	Weight      float64 `json:"weight"` // 0.0 to 1.0
}

// RiskIndicator represents a negative trust indicator
type RiskIndicator struct {
	Type        string              `json:"type"`
	Severity    types.SecurityLevel `json:"severity"`
	Description string              `json:"description"`
	Impact      float64             `json:"impact"` // negative impact on trust
}

// TrustAnalyzer performs trust analysis on AUR packages
type TrustAnalyzer struct {
	cacheDir string
}

// NewTrustAnalyzer creates a new trust analyzer
func NewTrustAnalyzer(cacheDir string) *TrustAnalyzer {
	return &TrustAnalyzer{cacheDir: cacheDir}
}

// AnalyzePackageTrust performs comprehensive trust analysis
func (ta *TrustAnalyzer) AnalyzePackageTrust(packageName string) (*TrustAnalysis, error) {
	// Get repository information
	repoInfo, err := ta.getRepositoryInfo(packageName)
	if err != nil {
		return nil, fmt.Errorf("failed to get repository info: %w", err)
	}

	// Get maintainer reputation
	maintainerRep, err := ta.getMaintainerReputation(repoInfo.Maintainer)
	if err != nil {
		// Don't fail completely if we can't get maintainer info
		maintainerRep = &MaintainerReputation{Username: repoInfo.Maintainer}
	}

	// Calculate trust factors and risk indicators
	trustFactors := ta.calculateTrustFactors(*repoInfo, *maintainerRep)
	riskIndicators := ta.calculateRiskIndicators(*repoInfo, *maintainerRep)

	// Calculate overall trust score
	overallScore := ta.calculateOverallTrustScore(trustFactors, riskIndicators)

	analysis := &TrustAnalysis{
		PackageName:          packageName,
		OverallTrustScore:    overallScore,
		RepositoryInfo:       *repoInfo,
		MaintainerReputation: *maintainerRep,
		TrustFactors:         trustFactors,
		RiskIndicators:       riskIndicators,
		AnalyzedAt:           time.Now(),
	}

	return analysis, nil
}

// getRepositoryInfo fetches git repository information for an AUR package
func (ta *TrustAnalyzer) getRepositoryInfo(packageName string) (*RepositoryInfo, error) {
	// AUR git URL format
	gitURL := fmt.Sprintf("https://aur.archlinux.org/%s.git", packageName)
	
	// Clone to a temporary directory for analysis
	tempDir := fmt.Sprintf("/tmp/yay-friend-trust-%s", packageName)
	
	// Clean up any existing directory
	exec.Command("rm", "-rf", tempDir).Run()
	
	// Clone the repository
	cmd := exec.Command("git", "clone", gitURL, tempDir)
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("failed to clone repository: %w", err)
	}
	
	// Ensure cleanup
	defer exec.Command("rm", "-rf", tempDir).Run()

	// Change to the repository directory for git operations
	repoInfo := &RepositoryInfo{
		PackageName: packageName,
		GitURL:      gitURL,
	}

	// Get first commit
	cmd = exec.Command("git", "-C", tempDir, "log", "--reverse", "--format=%ct", "--max-count=1")
	output, err := cmd.Output()
	if err == nil {
		if timestamp, err := strconv.ParseInt(strings.TrimSpace(string(output)), 10, 64); err == nil {
			repoInfo.FirstCommit = time.Unix(timestamp, 0)
		}
	}

	// Get last commit
	cmd = exec.Command("git", "-C", tempDir, "log", "--format=%ct", "--max-count=1")
	output, err = cmd.Output()
	if err == nil {
		if timestamp, err := strconv.ParseInt(strings.TrimSpace(string(output)), 10, 64); err == nil {
			repoInfo.LastCommit = time.Unix(timestamp, 0)
		}
	}

	// Get commit count
	cmd = exec.Command("git", "-C", tempDir, "rev-list", "--count", "HEAD")
	output, err = cmd.Output()
	if err == nil {
		if count, err := strconv.Atoi(strings.TrimSpace(string(output))); err == nil {
			repoInfo.CommitCount = count
		}
	}

	// Get contributors
	cmd = exec.Command("git", "-C", tempDir, "log", "--format=%an", "--all")
	output, err = cmd.Output()
	if err == nil {
		contributors := make(map[string]bool)
		for _, line := range strings.Split(string(output), "\n") {
			if line = strings.TrimSpace(line); line != "" {
				contributors[line] = true
			}
		}
		for contributor := range contributors {
			repoInfo.Contributors = append(repoInfo.Contributors, contributor)
		}
	}

	// Get maintainer from PKGBUILD
	cmd = exec.Command("grep", "-E", "^#.*[Mm]aintainer", fmt.Sprintf("%s/PKGBUILD", tempDir))
	output, err = cmd.Output()
	if err == nil {
		// Extract maintainer name from comment
		re := regexp.MustCompile(`#\s*[Mm]aintainer:\s*(.+)`)
		if matches := re.FindStringSubmatch(string(output)); len(matches) > 1 {
			repoInfo.Maintainer = strings.TrimSpace(matches[1])
		}
	}

	// Calculate derived metrics
	if !repoInfo.FirstCommit.IsZero() {
		repoInfo.RepoAge = time.Since(repoInfo.FirstCommit)
		if repoInfo.RepoAge.Hours() > 0 {
			monthsAge := repoInfo.RepoAge.Hours() / (24 * 30)
			repoInfo.CommitFrequency = float64(repoInfo.CommitCount) / monthsAge
		}
	}

	return repoInfo, nil
}

// getMaintainerReputation calculates maintainer reputation (stub implementation)
func (ta *TrustAnalyzer) getMaintainerReputation(maintainer string) (*MaintainerReputation, error) {
	// This is a stub implementation. In a real system, this would:
	// 1. Query AUR API for maintainer information
	// 2. Analyze all packages maintained by this user
	// 3. Calculate reputation metrics
	
	reputation := &MaintainerReputation{
		Username: maintainer,
		// These would be populated from AUR API queries
		PackageCount:    1, // Placeholder
		AccountAge:      time.Hour * 24 * 365, // Placeholder: 1 year
		AverageRepoAge:  time.Hour * 24 * 180, // Placeholder: 6 months
		TotalCommits:    10, // Placeholder
		LastActivity:    time.Now().AddDate(0, 0, -7), // Placeholder: 1 week ago
		ReputationScore: 0.5, // Placeholder: neutral
	}

	return reputation, nil
}

// calculateTrustFactors identifies positive trust indicators
func (ta *TrustAnalyzer) calculateTrustFactors(repo RepositoryInfo, maintainer MaintainerReputation) []TrustFactor {
	var factors []TrustFactor

	// Repository age factor
	if repo.RepoAge > time.Hour*24*365 { // > 1 year
		factors = append(factors, TrustFactor{
			Type:        "repository_age",
			Description: fmt.Sprintf("Repository has existed for %.1f years", repo.RepoAge.Hours()/(24*365)),
			Weight:      0.3,
		})
	}

	// Commit frequency factor
	if repo.CommitFrequency > 1 && repo.CommitFrequency < 20 { // Regular but not excessive updates
		factors = append(factors, TrustFactor{
			Type:        "commit_frequency",
			Description: fmt.Sprintf("Regular update pattern (%.1f commits/month)", repo.CommitFrequency),
			Weight:      0.2,
		})
	}

	// Multiple contributors factor
	if len(repo.Contributors) > 1 {
		factors = append(factors, TrustFactor{
			Type:        "multiple_contributors",
			Description: fmt.Sprintf("Multiple contributors (%d)", len(repo.Contributors)),
			Weight:      0.15,
		})
	}

	// Maintainer reputation factor
	if maintainer.ReputationScore > 0.7 {
		factors = append(factors, TrustFactor{
			Type:        "maintainer_reputation",
			Description: fmt.Sprintf("High maintainer reputation (%.2f)", maintainer.ReputationScore),
			Weight:      0.25,
		})
	}

	// Long-term maintenance factor
	if repo.RepoAge > time.Hour*24*180 && !repo.LastCommit.Before(time.Now().AddDate(0, -6, 0)) {
		factors = append(factors, TrustFactor{
			Type:        "long_term_maintenance",
			Description: "Package has been maintained long-term with recent activity",
			Weight:      0.2,
		})
	}

	return factors
}

// calculateRiskIndicators identifies negative trust indicators
func (ta *TrustAnalyzer) calculateRiskIndicators(repo RepositoryInfo, maintainer MaintainerReputation) []RiskIndicator {
	var indicators []RiskIndicator

	// Very new repository
	if repo.RepoAge < time.Hour*24*7 { // < 1 week
		indicators = append(indicators, RiskIndicator{
			Type:        "very_new_repository",
			Severity:    types.SecurityHigh,
			Description: fmt.Sprintf("Repository created only %.1f days ago", repo.RepoAge.Hours()/24),
			Impact:      0.4,
		})
	} else if repo.RepoAge < time.Hour*24*30 { // < 1 month
		indicators = append(indicators, RiskIndicator{
			Type:        "new_repository",
			Severity:    types.SecurityMedium,
			Description: fmt.Sprintf("Repository created %.1f days ago", repo.RepoAge.Hours()/24),
			Impact:      0.2,
		})
	}

	// Single commit (possible typosquatting)
	if repo.CommitCount == 1 {
		indicators = append(indicators, RiskIndicator{
			Type:        "single_commit",
			Severity:    types.SecurityMedium,
			Description: "Package has only one commit",
			Impact:      0.3,
		})
	}

	// No recent activity
	if repo.LastCommit.Before(time.Now().AddDate(-2, 0, 0)) { // > 2 years
		indicators = append(indicators, RiskIndicator{
			Type:        "abandoned_package",
			Severity:    types.SecurityLow,
			Description: fmt.Sprintf("No updates for %.1f years", time.Since(repo.LastCommit).Hours()/(24*365)),
			Impact:      0.15,
		})
	}

	// New maintainer with low reputation
	if maintainer.ReputationScore < 0.3 && maintainer.AccountAge < time.Hour*24*90 {
		indicators = append(indicators, RiskIndicator{
			Type:        "new_low_reputation_maintainer",
			Severity:    types.SecurityMedium,
			Description: "New maintainer with low reputation score",
			Impact:      0.25,
		})
	}

	// Excessive commit frequency (possible automation/spam)
	if repo.CommitFrequency > 50 {
		indicators = append(indicators, RiskIndicator{
			Type:        "excessive_commits",
			Severity:    types.SecurityLow,
			Description: fmt.Sprintf("Unusually high commit frequency (%.1f/month)", repo.CommitFrequency),
			Impact:      0.1,
		})
	}

	return indicators
}

// calculateOverallTrustScore computes the final trust score
func (ta *TrustAnalyzer) calculateOverallTrustScore(factors []TrustFactor, indicators []RiskIndicator) TrustScore {
	baseScore := 0.5 // Start with neutral

	// Add positive factors
	for _, factor := range factors {
		baseScore += factor.Weight * 0.5 // Scale down the impact
	}

	// Subtract negative indicators
	for _, indicator := range indicators {
		baseScore -= indicator.Impact
	}

	// Clamp to valid range
	if baseScore < 0 {
		baseScore = 0
	} else if baseScore > 1 {
		baseScore = 1
	}

	// Convert to discrete trust level
	switch {
	case baseScore < 0.2:
		return TrustVeryLow
	case baseScore < 0.4:
		return TrustLow
	case baseScore < 0.6:
		return TrustMedium
	case baseScore < 0.8:
		return TrustHigh
	default:
		return TrustVeryHigh
	}
}