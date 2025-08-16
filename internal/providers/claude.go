package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/aaronsb/yay-friend/internal/config"
	"github.com/aaronsb/yay-friend/internal/types"
)

// ClaudeProvider implements the AIProvider interface for Claude Code
type ClaudeProvider struct {
	authenticated bool
	config        *types.Config
	claudePath    string // Store the resolved path to claude command
}

// NewClaudeProvider creates a new Claude provider
func NewClaudeProvider() *ClaudeProvider {
	return &ClaudeProvider{}
}

// SetConfig sets the configuration for the provider
func (c *ClaudeProvider) SetConfig(config *types.Config) {
	c.config = config
}

// Name returns the provider name
func (c *ClaudeProvider) Name() string {
	return "claude"
}

// findClaudeCommand searches for the claude command in various locations
func (c *ClaudeProvider) findClaudeCommand() (string, error) {
	// List of possible locations for the claude command
	possiblePaths := []string{
		"claude",                           // In PATH
		"/usr/local/bin/claude",           // System-wide install
		"/usr/bin/claude",                 // System package
		"/home/" + os.Getenv("USER") + "/.claude/local/claude", // User-specific install
		"/opt/claude/claude",              // Optional location
	}
	
	// Also check XDG config directory
	if xdgConfig := os.Getenv("XDG_CONFIG_HOME"); xdgConfig != "" {
		possiblePaths = append(possiblePaths, xdgConfig+"/claude/claude")
	}
	
	// Check HOME/.config as fallback
	if home := os.Getenv("HOME"); home != "" {
		possiblePaths = append(possiblePaths, home+"/.config/claude/claude")
		possiblePaths = append(possiblePaths, home+"/.local/bin/claude")
	}
	
	for _, path := range possiblePaths {
		// For relative paths, use exec.LookPath
		if !strings.Contains(path, "/") {
			if resolvedPath, err := exec.LookPath(path); err == nil {
				return resolvedPath, nil
			}
			continue
		}
		
		// For absolute paths, check if file exists and is executable
		if info, err := os.Stat(path); err == nil {
			if info.Mode()&0111 != 0 { // Check if executable
				return path, nil
			}
		}
	}
	
	return "", fmt.Errorf("claude command not found in any expected location")
}

// Authenticate checks if Claude Code is available and authenticated
func (c *ClaudeProvider) Authenticate(ctx context.Context) error {
	// Find the claude command
	claudePath, err := c.findClaudeCommand()
	if err != nil {
		return fmt.Errorf("claude command not found: %w", err)
	}
	c.claudePath = claudePath

	// Test authentication by running a simple command
	cmd := exec.CommandContext(ctx, c.claudePath, "--version")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to run claude command at %s: %w", c.claudePath, err)
	}

	c.authenticated = true
	return nil
}

// IsAuthenticated returns whether the provider is authenticated
func (c *ClaudeProvider) IsAuthenticated() bool {
	return c.authenticated
}

// AnalyzePKGBUILD analyzes a PKGBUILD using Claude Code
func (c *ClaudeProvider) AnalyzePKGBUILD(ctx context.Context, pkgInfo types.PackageInfo) (*types.SecurityAnalysis, error) {
	return c.AnalyzePKGBUILDWithOptions(ctx, pkgInfo, false)
}

// AnalyzePKGBUILDWithOptions analyzes a PKGBUILD with additional options
func (c *ClaudeProvider) AnalyzePKGBUILDWithOptions(ctx context.Context, pkgInfo types.PackageInfo, noSpinner bool) (*types.SecurityAnalysis, error) {
	if !c.authenticated {
		return nil, fmt.Errorf("claude provider not authenticated")
	}

	prompt := c.buildSimpleSecurityPrompt(pkgInfo)
	
	// Debug: Write the full prompt to see what's being sent
	os.WriteFile("/tmp/claude-final-prompt.txt", []byte(prompt), 0644)
	
	var output []byte
	var err error
	
	if noSpinner {
		fmt.Printf("Analyzing with Claude...\n")
		// No spinner - just run claude directly
		cmd := exec.CommandContext(ctx, c.claudePath)
		cmd.Stdin = strings.NewReader(prompt)
		output, err = cmd.Output()
		fmt.Printf("Analysis complete.\n")
	} else {
		fmt.Printf("Analyzing with Claude... ")
		
		// Start spinner in a goroutine
		done := make(chan bool)
		go func() {
			spinner := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
			i := 0
			for {
				select {
				case <-done:
					fmt.Printf("\r")
					return
				default:
					fmt.Printf("\rAnalyzing with Claude... %s", spinner[i%len(spinner)])
					i++
					time.Sleep(100 * time.Millisecond)
				}
			}
		}()
		
		// Run claude with the prompt via stdin
		cmd := exec.CommandContext(ctx, c.claudePath)
		cmd.Stdin = strings.NewReader(prompt)
		output, err = cmd.Output()
		
		// Stop spinner and clear line  
		done <- true
		time.Sleep(10 * time.Millisecond) // Give spinner time to clear
		fmt.Printf("\rAnalyzing with Claude... Complete!\n")
	}
	
	if err != nil {
		return nil, fmt.Errorf("claude analysis failed: %w", err)
	}

	// Parse the response
	analysis, err := c.parseAnalysisResponse(string(output), pkgInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to parse analysis: %w", err)
	}

	return analysis, nil
}

// GetCapabilities returns the provider capabilities
func (c *ClaudeProvider) GetCapabilities() types.ProviderCapabilities {
	return types.ProviderCapabilities{
		SupportsCodeAnalysis: true,
		SupportsExplanations: true,
		RateLimitPerMinute:   20,
		MaxAnalysisSize:      100000, // 100KB
	}
}


// parseAnalysisResponse parses Claude's JSON response
func (c *ClaudeProvider) parseAnalysisResponse(response string, pkgInfo types.PackageInfo) (*types.SecurityAnalysis, error) {
	// Remove markdown code blocks if present
	response = strings.TrimSpace(response)
	if strings.Contains(response, "```json") {
		// Extract content between ```json and ```
		start := strings.Index(response, "```json")
		if start != -1 {
			start += 7 // length of "```json"
			end := strings.Index(response[start:], "```")
			if end != -1 {
				response = response[start:start+end]
			}
		}
	} else if strings.Contains(response, "```") {
		// Handle plain ``` blocks
		start := strings.Index(response, "```")
		if start != -1 {
			start += 3 // length of "```"
			end := strings.Index(response[start:], "```")
			if end != -1 {
				response = response[start:start+end]
			}
		}
	}
	
	// Extract JSON from response (Claude might include extra text)
	jsonStart := strings.Index(response, "{")
	jsonEnd := strings.LastIndex(response, "}")
	
	if jsonStart == -1 || jsonEnd == -1 {
		// Debug: show part of response to understand the issue
		responsePreview := response
		if len(responsePreview) > 500 {
			responsePreview = responsePreview[:500] + "..."
		}
		return nil, fmt.Errorf("no JSON found in response. Preview: %s", responsePreview)
	}
	
	jsonStr := response[jsonStart : jsonEnd+1]
	
	var analysisData struct {
		OverallEntropy      string   `json:"overall_entropy"`
		OverallLevel        string   `json:"overall_level"`
		EntropyFactors      []string `json:"entropy_factors"`
		PredictabilityScore float64  `json:"predictability_score"`
		EducationalSummary  string   `json:"educational_summary"`
		SecurityLessons     []string `json:"security_lessons"`
		Findings            []struct {
			Type         string `json:"type"`
			Entropy      string `json:"entropy"`
			Severity     string `json:"severity"`
			Description  string `json:"description"`
			LineNumber   int    `json:"line_number"`
			Context      string `json:"context"`
			Suggestion   string `json:"suggestion"`
			EntropyNotes string `json:"entropy_notes"`
		} `json:"findings"`
		Summary        string `json:"summary"`
		Recommendation string `json:"recommendation"`
	}
	
	if err := json.Unmarshal([]byte(jsonStr), &analysisData); err != nil {
		return nil, fmt.Errorf("failed to parse JSON response: %w", err)
	}
	
	// Convert to our types
	overallEntropy := parseSecurityEntropy(analysisData.OverallEntropy)
	if overallEntropy == types.EntropyMinimal && analysisData.OverallLevel != "" {
		// Fallback to overall_level if entropy not provided
		overallEntropy = parseSecurityEntropy(analysisData.OverallLevel)
	}

	analysis := &types.SecurityAnalysis{
		PackageName:         pkgInfo.Name,
		OverallEntropy:      overallEntropy,
		OverallLevel:        overallEntropy, // For compatibility
		Summary:             analysisData.Summary,
		Recommendation:      analysisData.Recommendation,
		AnalyzedAt:          time.Now(),
		Provider:            "claude",
		EntropyFactors:      analysisData.EntropyFactors,
		PredictabilityScore: analysisData.PredictabilityScore,
		EducationalSummary:  analysisData.EducationalSummary,
		SecurityLessons:     analysisData.SecurityLessons,
	}
	
	for _, finding := range analysisData.Findings {
		entropy := parseSecurityEntropy(finding.Entropy)
		if entropy == types.EntropyMinimal {
			// Fallback to severity if entropy not provided
			entropy = parseSecurityEntropy(finding.Severity)
		}
		
		analysis.Findings = append(analysis.Findings, types.SecurityFinding{
			Type:         finding.Type,
			Entropy:      entropy,
			Severity:     entropy, // For compatibility
			Description:  finding.Description,
			LineNumber:   finding.LineNumber,
			Context:      finding.Context,
			Suggestion:   finding.Suggestion,
			EntropyNotes: finding.EntropyNotes,
		})
	}
	
	return analysis, nil
}

// parseSecurityEntropy converts string to SecurityEntropy
func parseSecurityEntropy(level string) types.SecurityEntropy {
	switch strings.ToUpper(level) {
	case "MINIMAL", "SAFE":
		return types.EntropyMinimal
	case "LOW":
		return types.EntropyLow
	case "MODERATE", "MEDIUM":
		return types.EntropyModerate
	case "HIGH":
		return types.EntropyHigh
	case "CRITICAL":
		return types.EntropyCritical
	default:
		return types.EntropyModerate
	}
}

// parseSecurityLevel converts string to SecurityLevel (legacy compatibility)
func parseSecurityLevel(level string) types.SecurityLevel {
	return parseSecurityEntropy(level) // They're the same type now
}

// buildSimpleSecurityPrompt creates a prompt using the config template
func (c *ClaudeProvider) buildSimpleSecurityPrompt(pkgInfo types.PackageInfo) string {
	// Build dependency strings
	depends := strings.Join(pkgInfo.Dependencies, ", ")
	makeDepends := strings.Join(pkgInfo.MakeDepends, ", ")
	if len(depends) > 200 {
		depends = depends[:197] + "..."
	}
	if len(makeDepends) > 200 {
		makeDepends = makeDepends[:197] + "..."
	}

	// Get the prompt template from config, or use default if not available
	template := c.getPromptTemplate()
	
	// Replace template variables
	prompt := strings.ReplaceAll(template, "{NAME}", pkgInfo.Name)
	prompt = strings.ReplaceAll(prompt, "{VERSION}", pkgInfo.Version)
	prompt = strings.ReplaceAll(prompt, "{MAINTAINER}", pkgInfo.Maintainer)
	prompt = strings.ReplaceAll(prompt, "{VOTES}", fmt.Sprintf("%d", pkgInfo.Votes))
	prompt = strings.ReplaceAll(prompt, "{POPULARITY}", fmt.Sprintf("%.3f", pkgInfo.Popularity))
	prompt = strings.ReplaceAll(prompt, "{FIRST_SUBMITTED}", pkgInfo.FirstSubmitted)
	prompt = strings.ReplaceAll(prompt, "{LAST_UPDATED}", pkgInfo.LastUpdated)
	prompt = strings.ReplaceAll(prompt, "{DEPENDENCIES}", depends)
	prompt = strings.ReplaceAll(prompt, "{MAKE_DEPENDS}", makeDepends)
	prompt = strings.ReplaceAll(prompt, "{PKGBUILD}", pkgInfo.PKGBUILD)
	
	// Always replace install script placeholder
	if pkgInfo.InstallScript != "" {
		prompt = strings.ReplaceAll(prompt, "{INSTALL_SCRIPT}", pkgInfo.InstallScript)
	} else {
		prompt = strings.ReplaceAll(prompt, "{INSTALL_SCRIPT}", "[No install script present - this may be due to local PKGBUILD analysis limitations]")
	}
	
	// Always replace additional files placeholder
	if pkgInfo.AdditionalFiles != nil && len(pkgInfo.AdditionalFiles) > 0 {
		var filesContent []string
		for name, content := range pkgInfo.AdditionalFiles {
			filesContent = append(filesContent, fmt.Sprintf("=== %s ===\n%s", name, content))
		}
		prompt = strings.ReplaceAll(prompt, "{ADDITIONAL_FILES}", strings.Join(filesContent, "\n\n"))
	} else {
		prompt = strings.ReplaceAll(prompt, "{ADDITIONAL_FILES}", "[No additional files present - this may be due to local PKGBUILD analysis limitations]")
	}
	
	return prompt
}

// getPromptTemplate returns the security analysis prompt template from config
func (c *ClaudeProvider) getPromptTemplate() string {
	if c.config != nil && c.config.Prompts.SecurityAnalysis != "" {
		return c.config.Prompts.SecurityAnalysis
	}
	
	// Use default prompt template when config is not initialized
	return config.GetDefaultSecurityPrompt()
}