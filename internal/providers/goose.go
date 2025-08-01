package providers

import (
	"context"
	"fmt"

	"github.com/aaronsb/yay-friend/internal/types"
)

// GooseProvider implements the AIProvider interface for Goose AI
type GooseProvider struct {
	authenticated bool
}

// NewGooseProvider creates a new Goose provider
func NewGooseProvider() *GooseProvider {
	return &GooseProvider{}
}

// Name returns the provider name
func (g *GooseProvider) Name() string {
	return "goose"
}

// Authenticate checks if Goose AI is available and authenticated
func (g *GooseProvider) Authenticate(ctx context.Context) error {
	// TODO: Implement Goose authentication
	return fmt.Errorf("goose provider not implemented yet")
}

// IsAuthenticated returns whether the provider is authenticated
func (g *GooseProvider) IsAuthenticated() bool {
	return g.authenticated
}

// AnalyzePKGBUILD analyzes a PKGBUILD using Goose AI
func (g *GooseProvider) AnalyzePKGBUILD(ctx context.Context, pkgInfo types.PackageInfo) (*types.SecurityAnalysis, error) {
	// TODO: Implement Goose analysis
	return nil, fmt.Errorf("goose provider not implemented yet")
}

// GetCapabilities returns the provider capabilities
func (g *GooseProvider) GetCapabilities() types.ProviderCapabilities {
	return types.ProviderCapabilities{
		SupportsCodeAnalysis: true,
		SupportsExplanations: true,
		RateLimitPerMinute:   20,
		MaxAnalysisSize:      80000,
	}
}