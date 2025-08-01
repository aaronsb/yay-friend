package providers

import (
	"context"
	"fmt"

	"github.com/aaronsb/yay-friend/internal/types"
)

// QwenProvider implements the AIProvider interface for Qwen Code
type QwenProvider struct {
	authenticated bool
}

// NewQwenProvider creates a new Qwen provider
func NewQwenProvider() *QwenProvider {
	return &QwenProvider{}
}

// Name returns the provider name
func (q *QwenProvider) Name() string {
	return "qwen"
}

// Authenticate checks if Qwen Code is available and authenticated
func (q *QwenProvider) Authenticate(ctx context.Context) error {
	// TODO: Implement Qwen authentication
	return fmt.Errorf("qwen provider not implemented yet")
}

// IsAuthenticated returns whether the provider is authenticated
func (q *QwenProvider) IsAuthenticated() bool {
	return q.authenticated
}

// AnalyzePKGBUILD analyzes a PKGBUILD using Qwen Code
func (q *QwenProvider) AnalyzePKGBUILD(ctx context.Context, pkgInfo types.PackageInfo) (*types.SecurityAnalysis, error) {
	// TODO: Implement Qwen analysis
	return nil, fmt.Errorf("qwen provider not implemented yet")
}

// GetCapabilities returns the provider capabilities
func (q *QwenProvider) GetCapabilities() types.ProviderCapabilities {
	return types.ProviderCapabilities{
		SupportsCodeAnalysis: true,
		SupportsExplanations: true,
		RateLimitPerMinute:   15,
		MaxAnalysisSize:      50000,
	}
}