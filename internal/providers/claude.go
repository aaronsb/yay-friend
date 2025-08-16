package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

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
	
	// Fallback to hardcoded default if config is not available
	return `You are a security expert analyzing AUR packages for malicious behavior. Your PRIMARY goal is to detect and flag dangerous code patterns.

<critical_patterns>
SCAN FOR THESE MALICIOUS PATTERNS FIRST:
1. curl/wget piped to shell: curl URL | sh, wget -O- URL | bash
2. Downloading and executing code: python -c "$(curl ...)", eval "$(wget ...)"
3. Base64/hex encoded commands: echo BASE64 | base64 -d | sh
4. Commands in install hooks: post_install() running executables
5. Suspicious URLs: URL shorteners, paste sites, non-official domains
6. Hidden network activity: Background downloads, data exfiltration
7. System modification: Writing to /usr/bin during build, modifying system files
8. Obfuscated scripts: Encoded strings, complex redirections, hidden commands
</critical_patterns>

<package_context>
Name: {NAME} | Version: {VERSION} | Maintainer: {MAINTAINER}
Votes: {VOTES} | Popularity: {POPULARITY}
First Submitted: {FIRST_SUBMITTED} | Last Updated: {LAST_UPDATED}
Dependencies: {DEPENDENCIES}
Build Dependencies: {MAKE_DEPENDS}
</package_context>

<pkgbuild_content>
{PKGBUILD}
</pkgbuild_content>

<install_script>
{INSTALL_SCRIPT}
</install_script>

<additional_files>
{ADDITIONAL_FILES}
</additional_files>

<analysis_instructions>
1. FIRST check ALL files for the critical patterns listed above
2. Pay special attention to .install scripts and helper scripts
3. Look for ANY network activity (curl, wget, git clone during runtime)
4. Check for code execution during install/upgrade hooks
5. Verify all URLs point to official/trusted sources
6. Flag ANY obfuscation or encoding of commands
</analysis_instructions>

<response_format>
Provide ONLY a JSON response:
{
  "overall_entropy": "MINIMAL|LOW|MODERATE|HIGH|CRITICAL",
  "summary": "Clear statement of findings, especially any malicious code",
  "recommendation": "PROCEED|REVIEW|BLOCK",
  "findings": [
    {
      "type": "malicious_code|suspicious_behavior|source_analysis|build_process|file_operations|maintainer_trust|dependency_analysis",
      "entropy": "MINIMAL|LOW|MODERATE|HIGH|CRITICAL",
      "description": "Specific description of the threat",
      "context": "Exact code snippet showing the issue",
      "line_number": 0,
      "file": "filename where found (PKGBUILD, .install, etc)",
      "suggestion": "Remove this package immediately / Review before installing / etc"
    }
  ],
  "entropy_factors": ["list of specific risk factors found"],
  "educational_summary": "What this attack vector teaches about AUR security",
  "security_lessons": ["Key takeaways for users"]
}
</response_format>

REMEMBER: Any code execution during installation, hidden network requests, or obfuscated commands should result in CRITICAL entropy and BLOCK recommendation.`
}