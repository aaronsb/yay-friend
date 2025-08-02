package aur

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/aaronsb/yay-friend/internal/types"
)

// AURFetcher handles fetching additional AUR context
type AURFetcher struct {
	client *http.Client
}

// NewAURFetcher creates a new AUR context fetcher
func NewAURFetcher() *AURFetcher {
	return &AURFetcher{
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// AURPackageInfo represents the AUR RPC response structure
type AURPackageInfo struct {
	ID             int      `json:"ID"`
	Name           string   `json:"Name"`
	PackageBaseID  int      `json:"PackageBaseID"`
	PackageBase    string   `json:"PackageBase"`
	Version        string   `json:"Version"`
	Description    string   `json:"Description"`
	URL            string   `json:"URL"`
	NumVotes       int      `json:"NumVotes"`
	Popularity     float64  `json:"Popularity"`
	OutOfDate      *int64   `json:"OutOfDate"`
	Maintainer     string   `json:"Maintainer"`
	FirstSubmitted int64    `json:"FirstSubmitted"`
	LastModified   int64    `json:"LastModified"`
	URLPath        string   `json:"URLPath"`
	Depends        []string `json:"Depends"`
	MakeDepends    []string `json:"MakeDepends"`
	OptDepends     []string `json:"OptDepends"`
	License        []string `json:"License"`
	Keywords       []string `json:"Keywords"`
}

// AURResponse represents the AUR RPC API response
type AURResponse struct {
	Version     int               `json:"version"`
	Type        string            `json:"type"`
	ResultCount int               `json:"resultcount"`
	Results     []AURPackageInfo  `json:"results"`
}

// EnrichPackageInfo fetches additional AUR context using the official RPC API
func (f *AURFetcher) EnrichPackageInfo(ctx context.Context, pkgInfo *types.PackageInfo) error {
	// Build AUR package page URL for reference
	pkgInfo.AURPageURL = fmt.Sprintf("https://aur.archlinux.org/packages/%s", pkgInfo.Name)
	
	// Try to fetch git commit hash for AUR packages
	commitHash, err := GetLatestCommitHash(ctx, pkgInfo.Name)
	if err != nil {
		// This is likely not an AUR package (could be from official repos)
		// Set a fallback hash based on package name and version for basic caching
		pkgInfo.CommitHash = fmt.Sprintf("fallback-%s-%s", pkgInfo.Name, pkgInfo.Version)
	} else {
		pkgInfo.CommitHash = commitHash
	}
	
	// Fetch AUR metadata using RPC API (only for AUR packages)
	aurData, err := f.fetchAURMetadata(ctx, pkgInfo.Name)
	if err != nil {
		// This is likely not an AUR package (could be from official repos)
		// Don't show warning for official packages, just skip AUR enrichment
		return nil
	}
	
	// Enrich package info with AUR data
	f.enrichFromAURData(aurData, pkgInfo)
	
	return nil
}

// fetchAURMetadata fetches package metadata from AUR RPC API
func (f *AURFetcher) fetchAURMetadata(ctx context.Context, packageName string) (*AURPackageInfo, error) {
	// Build RPC API URL (v5 format)
	rpcURL := fmt.Sprintf("https://aur.archlinux.org/rpc/v5/info/%s", url.QueryEscape(packageName))
	
	req, err := http.NewRequestWithContext(ctx, "GET", rpcURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	
	req.Header.Set("User-Agent", "yay-friend/1.0 (security analysis tool)")
	
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch AUR metadata: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("AUR API returned status %d", resp.StatusCode)
	}
	
	var aurResp AURResponse
	if err := json.NewDecoder(resp.Body).Decode(&aurResp); err != nil {
		return nil, fmt.Errorf("failed to decode AUR response: %w", err)
	}
	
	if aurResp.ResultCount == 0 {
		return nil, fmt.Errorf("package not found in AUR")
	}
	
	return &aurResp.Results[0], nil
}

// enrichFromAURData enriches PackageInfo with data from AUR RPC API
func (f *AURFetcher) enrichFromAURData(aurData *AURPackageInfo, pkgInfo *types.PackageInfo) {
	// Convert timestamps to readable dates
	pkgInfo.FirstSubmitted = time.Unix(aurData.FirstSubmitted, 0).Format("2006-01-02")
	pkgInfo.LastUpdated = time.Unix(aurData.LastModified, 0).Format("2006-01-02")
	
	// Set metadata
	pkgInfo.Votes = aurData.NumVotes
	pkgInfo.Popularity = aurData.Popularity
	
	// Set dependencies for analysis
	pkgInfo.Dependencies = aurData.Depends
	pkgInfo.MakeDepends = aurData.MakeDepends
	pkgInfo.OptDepends = aurData.OptDepends
	
	// Note: Comments are not available via RPC API
	// Instead, we'll use the structured data for trust analysis
	
	// For high-entropy packages, suggest manual comment review
	entropyFactors := f.calculateAUREntropyFactors(aurData)
	if len(entropyFactors) > 0 {
		// Add a note about checking comments manually for high-risk packages
		riskLevel := f.assessRiskLevel(aurData)
		if riskLevel > 2 {
			pkgInfo.Comments = []string{
				fmt.Sprintf("High-risk package detected. Manual review recommended at %s", pkgInfo.AURPageURL),
			}
		}
	}
}

// calculateAUREntropyFactors analyzes AUR metadata for entropy indicators
func (f *AURFetcher) calculateAUREntropyFactors(aurData *AURPackageInfo) []string {
	var factors []string
	
	// Low vote count for old packages
	age := time.Since(time.Unix(aurData.FirstSubmitted, 0))
	if age > 365*24*time.Hour && aurData.NumVotes < 10 {
		factors = append(factors, "old_package_low_votes")
	}
	
	// Very new packages
	if age < 30*24*time.Hour {
		factors = append(factors, "very_new_package")
	}
	
	// Orphaned packages
	if aurData.Maintainer == "" {
		factors = append(factors, "orphaned_package")
	}
	
	// Out of date
	if aurData.OutOfDate != nil {
		factors = append(factors, "flagged_out_of_date")
	}
	
	// Low popularity despite votes
	if aurData.NumVotes > 20 && aurData.Popularity < 1.0 {
		factors = append(factors, "votes_without_usage")
	}
	
	return factors
}

// assessRiskLevel provides a simple risk score based on AUR metadata
func (f *AURFetcher) assessRiskLevel(aurData *AURPackageInfo) int {
	risk := 0
	
	// Age vs votes analysis
	age := time.Since(time.Unix(aurData.FirstSubmitted, 0))
	if age > 365*24*time.Hour && aurData.NumVotes < 5 {
		risk += 2
	}
	
	// New package risk
	if age < 7*24*time.Hour {
		risk += 3
	} else if age < 30*24*time.Hour {
		risk += 1
	}
	
	// Orphaned packages
	if aurData.Maintainer == "" {
		risk += 2
	}
	
	// Out of date flag
	if aurData.OutOfDate != nil {
		risk += 1
	}
	
	// No votes at all (potential dummy package)
	if aurData.NumVotes == 0 && age > 30*24*time.Hour {
		risk += 1
	}
	
	return risk
}