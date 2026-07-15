package providers

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/aaronsb/yay-friend/internal/config"
	"github.com/aaronsb/yay-friend/internal/types"
)

// deniedTools lists the built-in Claude Code tools yay-friend forbids during
// analysis. A PKGBUILD is untrusted input that may attempt prompt injection, so
// the model should only read and classify the text we hand it — not execute,
// write, or fetch anything.
//
// NOTE: this is an enumerated deny-list, current as of Claude Code 2.1.x. It is
// best-effort, not a hard sandbox: a built-in tool added in a future Claude
// release would not be covered until added here. It is one layer of
// defense-in-depth alongside headless mode's own permission checks. If Claude
// Code ever supports an empty allow-list that fails closed, prefer that.
var deniedTools = []string{
	"Bash", "Edit", "Write", "NotebookEdit", "Read", "Glob", "Grep",
	"WebFetch", "WebSearch", "Task", "TodoWrite",
}

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

	// Get or create a dedicated directory for claude executions. Running from a
	// neutral directory keeps claude from auto-discovering a project CLAUDE.md or
	// polluting other conversation histories.
	claudeWorkDir := c.getClaudeWorkDir()
	if err := os.MkdirAll(claudeWorkDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create claude work directory: %w", err)
	}

	// Opt-in prompt dump for debugging, kept out of world-readable /tmp.
	if os.Getenv("YAYFRIEND_DEBUG") != "" {
		_ = os.WriteFile(filepath.Join(claudeWorkDir, "last-prompt.txt"), []byte(prompt), 0600)
	}

	// On an interactive terminal, stream the analysis so the user gets live
	// progress. When output is piped/redirected or a caller asked for no spinner
	// (automation, CI), fall back to a single quiet one-shot call.
	var resultText string
	var err error
	if noSpinner || !isTerminal(os.Stdout) {
		resultText, err = c.runClaudeOneShot(ctx, prompt, claudeWorkDir)
	} else {
		resultText, err = c.runClaudeStreaming(ctx, prompt, claudeWorkDir)
	}
	if err != nil {
		return nil, err
	}

	// Parse the response
	analysis, err := c.parseAnalysisResponse(resultText, pkgInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to parse analysis: %w", err)
	}

	return analysis, nil
}

// baseClaudeArgs holds the hardened, isolated flags common to every invocation:
//   - --model: pinned so analysis is reproducible rather than drifting with the
//     user's interactive default
//   - --strict-mcp-config + empty --mcp-config: ignore the user's MCP servers so
//     analysis can't reach Slack, Google, etc.
//   - --disallowedTools: deny every built-in tool (see deniedTools)
//
// Authentication is intentionally left untouched: this inherits whatever the
// local `claude` is logged into (subscription OAuth or ANTHROPIC_API_KEY).
// yay-friend never reads, extracts, or forwards credentials.
func (c *ClaudeProvider) baseClaudeArgs() []string {
	return []string{
		"--model", c.getModel(),
		"--strict-mcp-config",
		"--mcp-config", `{"mcpServers":{}}`,
		"--disallowedTools", strings.Join(deniedTools, ","),
	}
}

// runClaudeOneShot runs a single non-interactive analysis and returns the model's
// text result, unwrapped from the `--output-format json` envelope.
func (c *ClaudeProvider) runClaudeOneShot(ctx context.Context, prompt, workDir string) (string, error) {
	args := append([]string{"--print", "--output-format", "json"}, c.baseClaudeArgs()...)

	// Status goes to stderr so stdout stays clean for callers capturing output.
	fmt.Fprintln(os.Stderr, "Analyzing with Claude...")
	cmd := exec.CommandContext(ctx, c.claudePath, args...)
	cmd.Dir = workDir
	cmd.Stdin = strings.NewReader(prompt)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	output, err := cmd.Output()
	fmt.Fprintln(os.Stderr, "Analysis complete.")

	if err != nil {
		if stderr.Len() > 0 {
			return "", fmt.Errorf("claude analysis failed: %w: %s", err, strings.TrimSpace(stderr.String()))
		}
		return "", fmt.Errorf("claude analysis failed: %w", err)
	}
	return extractClaudeResult(output)
}

// runClaudeStreaming runs the analysis with `--output-format stream-json` and
// renders a live progress line (elapsed time + phase) as newline-delimited JSON
// events arrive, while capturing the final result event for parsing. stdout and
// stderr are handled on separate pipes so a chatty stderr can't deadlock reads.
func (c *ClaudeProvider) runClaudeStreaming(ctx context.Context, prompt, workDir string) (string, error) {
	args := append([]string{"--print", "--output-format", "stream-json", "--verbose"}, c.baseClaudeArgs()...)

	cmd := exec.CommandContext(ctx, c.claudePath, args...)
	cmd.Dir = workDir
	cmd.Stdin = strings.NewReader(prompt)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return "", fmt.Errorf("failed to open claude output: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("failed to start claude: %w", err)
	}

	start := time.Now()
	var mu sync.Mutex
	phase := "starting"

	// Progress ticker: repaint the elapsed/phase line a few times a second.
	// wg lets us join the goroutine before printing the final line, so a stale
	// in-progress repaint can never land after "complete".
	doneTick := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-doneTick:
				return
			case <-ticker.C:
				mu.Lock()
				p := phase
				mu.Unlock()
				fmt.Printf("\r\033[KAnalyzing with Claude (%ds, %s)…", int(time.Since(start).Seconds()), p)
			}
		}
	}()

	// Read events as they arrive. Use a Reader (not Scanner) so a large result
	// line can't blow past a fixed token limit. We also accumulate the assistant
	// message text: it carries the same JSON as the result event, so it's a
	// fallback if the result event is missing or unparseable (parity with the
	// one-shot path, which falls back to raw text).
	var resultEvent *claudeEvent
	var assistantText strings.Builder
	reader := bufio.NewReader(stdout)
	for {
		line, rerr := reader.ReadString('\n')
		if trimmed := strings.TrimSpace(line); trimmed != "" {
			var ev claudeEvent
			if json.Unmarshal([]byte(trimmed), &ev) == nil {
				switch ev.Type {
				case "assistant":
					mu.Lock()
					phase = "receiving"
					mu.Unlock()
					for _, block := range ev.Message.Content {
						if block.Type == "text" {
							assistantText.WriteString(block.Text)
						}
					}
				case "result":
					e := ev
					resultEvent = &e
				}
			}
		}
		if rerr != nil {
			break // io.EOF on clean close, or a read error
		}
	}

	close(doneTick)
	wg.Wait()
	waitErr := cmd.Wait()
	fmt.Printf("\r\033[KAnalyzing with Claude… complete (%ds).\n", int(time.Since(start).Seconds()))

	if resultEvent != nil {
		if resultEvent.IsError {
			msg := resultEvent.Result
			if msg == "" {
				msg = resultEvent.Subtype
			}
			return "", fmt.Errorf("claude reported an error: %s", msg)
		}
		return resultEvent.Result, nil
	}
	// No usable result event; fall back to the assistant text if we captured any.
	if text := strings.TrimSpace(assistantText.String()); text != "" {
		return text, nil
	}
	if waitErr != nil {
		if stderr.Len() > 0 {
			return "", fmt.Errorf("claude analysis failed: %w: %s", waitErr, strings.TrimSpace(stderr.String()))
		}
		return "", fmt.Errorf("claude analysis failed: %w", waitErr)
	}
	return "", fmt.Errorf("claude produced no result event")
}

// isTerminal reports whether f is an interactive character device (a TTY),
// as opposed to a pipe or regular file.
func isTerminal(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

// getModel returns the configured model alias, or the default.
func (c *ClaudeProvider) getModel() string {
	if c.config != nil && c.config.Claude.Model != "" {
		return c.config.Claude.Model
	}
	return config.DefaultClaudeModel
}

// claudeEvent captures the fields we need from `claude --output-format json`.
// That format emits either a single result object or (in richer environments) a
// JSON array of events ending in a result event; extractClaudeResult handles both.
type claudeEvent struct {
	Type    string `json:"type"`
	Subtype string `json:"subtype"`
	IsError bool   `json:"is_error"`
	Result  string `json:"result"`
	// Message is populated only on "assistant" events in the stream-json format;
	// its text blocks carry the model's output.
	Message struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	} `json:"message"`
}

// extractClaudeResult unwraps the JSON envelope from `claude --output-format json`
// and returns the model's text result. It tolerates three shapes: a JSON array of
// events, a single result object, or (defensively) raw non-JSON text.
func extractClaudeResult(output []byte) (string, error) {
	trimmed := bytes.TrimSpace(output)
	if len(trimmed) == 0 {
		return "", fmt.Errorf("claude returned empty output")
	}

	var result *claudeEvent
	switch trimmed[0] {
	case '[':
		var events []claudeEvent
		if err := json.Unmarshal(trimmed, &events); err != nil {
			return "", fmt.Errorf("failed to parse claude event stream: %w", err)
		}
		for i := range events {
			if events[i].Type == "result" {
				result = &events[i]
			}
		}
	case '{':
		var ev claudeEvent
		if err := json.Unmarshal(trimmed, &ev); err != nil {
			return "", fmt.Errorf("failed to parse claude result: %w", err)
		}
		if ev.Type == "result" || ev.Result != "" {
			result = &ev
		}
	default:
		// Not a JSON envelope (e.g. plain --print text); use as-is.
		return string(trimmed), nil
	}

	if result == nil {
		// No result event found; fall back to raw output so parsing can still try.
		return string(trimmed), nil
	}
	if result.IsError {
		msg := result.Result
		if msg == "" {
			msg = result.Subtype
		}
		return "", fmt.Errorf("claude reported an error: %s", msg)
	}
	return result.Result, nil
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

// getClaudeWorkDir returns a dedicated directory for claude executions
func (c *ClaudeProvider) getClaudeWorkDir() string {
	// Use the same logic as cache to get XDG-compliant directory
	if xdgData := os.Getenv("XDG_DATA_HOME"); xdgData != "" {
		return filepath.Join(xdgData, "yay-friend", "claude-work")
	}

	home, err := os.UserHomeDir()
	if err != nil {
		// Fallback to current directory if we can't determine home
		return ".yay-friend-claude"
	}

	return filepath.Join(home, ".local", "share", "yay-friend", "claude-work")
}