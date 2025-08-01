package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/aaronsb/yay-friend/internal/types"
)

// ClaudeProvider implements the AIProvider interface for Claude Code
type ClaudeProvider struct {
	authenticated bool
}

// NewClaudeProvider creates a new Claude provider
func NewClaudeProvider() *ClaudeProvider {
	return &ClaudeProvider{}
}

// Name returns the provider name
func (c *ClaudeProvider) Name() string {
	return "claude"
}

// Authenticate checks if Claude Code is available and authenticated
func (c *ClaudeProvider) Authenticate(ctx context.Context) error {
	// Check if claude command is available
	if _, err := exec.LookPath("claude"); err != nil {
		return fmt.Errorf("claude command not found: %w", err)
	}

	// Test authentication by running a simple command
	cmd := exec.CommandContext(ctx, "claude", "--version")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to run claude command: %w", err)
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
	if !c.authenticated {
		return nil, fmt.Errorf("claude provider not authenticated")
	}

	prompt := c.buildSecurityPrompt(pkgInfo)
	
	fmt.Printf("🤖 Analyzing with Claude...\n")
	
	// Run claude with the prompt via stdin (simple approach)
	cmd := exec.CommandContext(ctx, "claude")
	cmd.Stdin = strings.NewReader(prompt)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("claude analysis failed: %w", err)
	}
	
	fmt.Printf("🔄 Processing analysis results...\n")

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

// buildSecurityPrompt creates the security analysis prompt with content truncation
func (c *ClaudeProvider) buildSecurityPrompt(pkgInfo types.PackageInfo) string {
	// Truncate PKGBUILD if too long (200 lines max as suggested)
	pkgbuildLines := strings.Split(pkgInfo.PKGBUILD, "\n")
	if len(pkgbuildLines) > 200 {
		pkgbuildLines = pkgbuildLines[:200]
		pkgbuildLines = append(pkgbuildLines, "", "... [TRUNCATED - Original PKGBUILD longer than 200 lines]")
	}
	truncatedPKGBUILD := strings.Join(pkgbuildLines, "\n")
	
	// Limit comments to prevent prompt bloat (max 3 comments, 100 chars each)
	limitedComments := pkgInfo.Comments
	if len(limitedComments) > 3 {
		limitedComments = limitedComments[:3]
	}
	var shortComments []string
	for _, comment := range limitedComments {
		if len(comment) > 100 {
			comment = comment[:97] + "..."
		}
		shortComments = append(shortComments, comment)
	}
	
	// Build dependency strings
	depends := strings.Join(pkgInfo.Dependencies, ", ")
	makeDepends := strings.Join(pkgInfo.MakeDepends, ", ")
	if len(depends) > 200 {
		depends = depends[:197] + "..."
	}
	if len(makeDepends) > 200 {
		makeDepends = makeDepends[:197] + "..."
	}
	return fmt.Sprintf(`You are a security expert conducting a systematic analysis of PKGBUILD files from the Arch User Repository (AUR). 

Your task is to perform a comprehensive security entropy analysis following this structured template:

=== PACKAGE INFORMATION ===
Package: %s
Version: %s
Description: %s
Maintainer: %s
AUR Page: %s

=== AUR CONTEXT ===
Last Updated: %s
First Submitted: %s
Votes: %d
Popularity: %.3f
Dependencies: %s
Make Dependencies: %s
AUR Comments/Warnings: %s

=== PKGBUILD CONTENT ===
%s

=== ANALYSIS FRAMEWORK ===

You must systematically evaluate each of these security dimensions and provide specific findings:

1. **SOURCE ANALYSIS** - Examine source array and origins:
   - Official sources vs third-party/unknown sources
   - Multiple source origins (increases entropy)
   - Source URL patterns (GitHub official vs random repos)
   - Version consistency and authenticity

2. **BUILD PROCESS ANALYSIS** - Examine build() and package() functions:
   - Source compilation vs simple repackaging  
   - Custom build scripts and patches
   - Network requests during build (wget, curl, git clone)
   - System modifications during build

3. **FILE OPERATIONS ANALYSIS** - Examine file handling:
   - Files installed outside $pkgdir
   - Setuid/setgid files creation
   - System configuration modifications
   - Unusual file permissions

4. **CODE EXECUTION ANALYSIS** - Examine dynamic code:
   - eval, exec with dynamic content
   - Base64/hex encoded commands
   - Downloaded scripts being executed
   - Shell obfuscation patterns

5. **DEPENDENCY ANALYSIS** - Examine dependencies:
   - Unusual or suspicious dependencies
   - -git or -bin variant dependencies
   - Dependency confusion risks

6. **MAINTAINER TRUST ANALYSIS** - Evaluate maintainer context:
   - New vs established maintainer
   - Package update patterns
   - Maintainer reputation indicators

For each finding, provide:
- **Type**: Category of finding (source_analysis, build_process, file_operations, etc.)
- **Entropy Level**: MINIMAL/LOW/MODERATE/HIGH/CRITICAL
- **Description**: What specifically was found
- **Context**: Relevant code snippet or detail
- **Entropy Notes**: Why this increases/decreases predictability and risk
- **Suggestion**: How to mitigate or verify this finding

Respond ONLY with a JSON object in this exact format:
{
  "overall_entropy": "MINIMAL|LOW|MODERATE|HIGH|CRITICAL",
  "overall_level": "MINIMAL|LOW|MODERATE|HIGH|CRITICAL",
  "findings": [
    {
      "type": "source_analysis|build_process|file_operations|code_execution|dependency_analysis|maintainer_trust",
      "entropy": "MINIMAL|LOW|MODERATE|HIGH|CRITICAL",
      "severity": "MINIMAL|LOW|MODERATE|HIGH|CRITICAL", 
      "description": "detailed description of what was found",
      "line_number": 0,
      "context": "relevant code snippet",
      "suggestion": "specific mitigation or verification steps",
      "entropy_notes": "educational explanation of why this affects security predictability"
    }
  ],
  "summary": "comprehensive assessment with educational context",
  "recommendation": "PROCEED|REVIEW|BLOCK",
  "entropy_factors": ["specific", "factors", "that", "increase", "uncertainty"],
  "predictability_score": 0.5,
  "educational_summary": "What users should learn from this analysis - explain key security concepts, red flags to watch for, and general PKGBUILD security principles demonstrated in this package",
  "security_lessons": ["Key lesson 1", "Key lesson 2", "Key lesson 3"]
}

CRITICAL SECURITY ENTROPY ANALYSIS:

Think of "entropy" as unpredictability and uncertainty - the more unknowns and variables, the higher the entropy.

1. **SOURCE COMPILATION vs REPACKAGING (HIGH ENTROPY)**:
   - Source compilation = HIGH ENTROPY (arbitrary code execution, build-time attacks)
   - Look for: make, cmake, ./configure, cargo build, go build, npm run build, etc.
   - Simple repackaging = LOW ENTROPY (predictable file operations)
   - Entropy increases with: custom build scripts, patches, complex build processes

2. **MULTIPLE SOURCE ORIGINS (MAXIMUM ENTROPY)**:
   - Each additional source MULTIPLIES uncertainty and attack surface
   - CRITICAL ENTROPY: mixing official sources with random repos/URLs
   - Look for multiple different domains/repositories in source=() array  
   - Entropy factors: untrusted sources, different maintainers, varying trust levels

3. **NETWORK REQUEST ANALYSIS**:
   - wget, curl, git clone from untrusted sources during build()
   - Downloads during build process (not just in source=() array)
   - Downloading executable scripts and running them
   - Fetching from pastebin, raw GitHub, or URL shorteners

4. **BUILD PROCESS MANIPULATION**:
   - Modifying system files during build
   - Installing files outside of $pkgdir
   - Running commands as root or with elevated privileges
   - Patching source code with suspicious modifications

5. **OBFUSCATION AND ENCODING**:
   - Base64 encoded commands or data
   - Hex-encoded strings being decoded and executed  
   - eval, exec with dynamic content
   - Compressed or archived scripts being extracted and run

6. **PACKAGE STRUCTURE ANOMALIES**:
   - Unusual dependencies (especially -git or -bin variants)
   - Conflicting package descriptions vs actual functionality
   - Packages with generic names but specific functionality
   - Missing or incomplete metadata

7. **SUSPICIOUS FILE OPERATIONS**:
   - Writing to /tmp with predictable names (race conditions)
   - Creating setuid/setgid files
   - Modifying system configuration files
   - Installing to unusual system directories

8. **TRUST INDICATORS** (consider for severity adjustment):
   - Package age and update history (if maintainer info suggests new/untrusted)
   - Maintainer reputation (new accounts are riskier)
   - Single vs multiple contributors
   - Frequency and nature of updates

**ENTROPY SEVERITY GUIDELINES**:
- CRITICAL: Maximum chaos - multiple sources + compilation + runtime downloads + obfuscation
- HIGH: High unpredictability - source compilation + suspicious network activity + new maintainer
- MODERATE: Concerning uncertainty - compilation OR multiple sources OR obfuscation  
- LOW: Minor unpredictability - simple repackaging with minor anomalies
- MINIMAL: Highly predictable - simple repackaging from official sources, established maintainer

**ENTROPY FACTORS TO TRACK**:
- Source compilation (vs simple repackaging)
- Multiple/untrusted source origins  
- Network requests during build
- Code obfuscation/encoding
- New/unknown maintainer
- Complex build processes
- Runtime code generation
- Dependency confusion risks

Focus on UNPREDICTABILITY and UNCERTAINTY as security entropy indicators. The more variables and unknowns, the higher the entropy.

**AUR CONTEXT ANALYSIS GUIDELINES:**
- Recent updates indicate active maintenance (good) vs abandonment (concerning)
- High vote counts and popularity suggest community trust
- Comments may reveal security concerns, build issues, or user experiences
- Long-established packages (older first submitted dates) tend to be more stable
- Rapid update frequency could indicate instability or active development
- Dependencies can reveal complexity and attack surface
- Make dependencies show build-time requirements and potential risks`, 
		pkgInfo.Name, 
		pkgInfo.Version,
		pkgInfo.Description,
		pkgInfo.Maintainer,
		pkgInfo.AURPageURL,
		pkgInfo.LastUpdated,
		pkgInfo.FirstSubmitted,
		pkgInfo.Votes,
		pkgInfo.Popularity,
		depends,
		makeDepends,
		strings.Join(shortComments, " | "),
		truncatedPKGBUILD)
}

// parseAnalysisResponse parses Claude's JSON response
func (c *ClaudeProvider) parseAnalysisResponse(response string, pkgInfo types.PackageInfo) (*types.SecurityAnalysis, error) {
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