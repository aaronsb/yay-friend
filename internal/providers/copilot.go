package providers

import (
	"context"
	"fmt"

	"github.com/aaronsb/yay-friend/internal/types"
)

// CopilotProvider implements the AIProvider interface for GitHub Copilot CLI
type CopilotProvider struct {
	authenticated bool
}

// NewCopilotProvider creates a new Copilot provider
func NewCopilotProvider() *CopilotProvider {
	return &CopilotProvider{}
}

// Name returns the provider name
func (c *CopilotProvider) Name() string {
	return "copilot"
}

// Authenticate checks if GitHub Copilot CLI is available and authenticated
func (c *CopilotProvider) Authenticate(ctx context.Context) error {
	// TODO: Implement Copilot authentication
	return fmt.Errorf("copilot provider not implemented yet")
}

// IsAuthenticated returns whether the provider is authenticated
func (c *CopilotProvider) IsAuthenticated() bool {
	return c.authenticated
}

// AnalyzePKGBUILD analyzes a PKGBUILD using GitHub Copilot CLI
func (c *CopilotProvider) AnalyzePKGBUILD(ctx context.Context, pkgInfo types.PackageInfo) (*types.SecurityAnalysis, error) {
	// TODO: Implement Copilot analysis
	return nil, fmt.Errorf("copilot provider not implemented yet")
}

// GetCapabilities returns the provider capabilities
func (c *CopilotProvider) GetCapabilities() types.ProviderCapabilities {
	return types.ProviderCapabilities{
		SupportsCodeAnalysis: true,
		SupportsExplanations: true,
		RateLimitPerMinute:   10,
		MaxAnalysisSize:      75000,
	}
}