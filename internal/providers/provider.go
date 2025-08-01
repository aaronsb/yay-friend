package providers

import (
	"context"
	"fmt"

	"github.com/aaronsb/yay-friend/internal/types"
)

// ProviderRegistry manages all available AI providers
type ProviderRegistry struct {
	providers       map[string]types.AIProvider
	defaultProvider string
}

// NewProviderRegistry creates a new provider registry
func NewProviderRegistry() *ProviderRegistry {
	return &ProviderRegistry{
		providers: make(map[string]types.AIProvider),
	}
}

// Register adds a provider to the registry
func (pr *ProviderRegistry) Register(name string, provider types.AIProvider) {
	pr.providers[name] = provider
}

// Get retrieves a provider by name
func (pr *ProviderRegistry) Get(name string) (types.AIProvider, error) {
	if provider, exists := pr.providers[name]; exists {
		return provider, nil
	}
	return nil, fmt.Errorf("provider '%s' not found", name)
}

// SetDefault sets the default provider
func (pr *ProviderRegistry) SetDefault(name string) error {
	if _, exists := pr.providers[name]; !exists {
		return fmt.Errorf("provider '%s' not found", name)
	}
	pr.defaultProvider = name
	return nil
}

// GetDefault returns the default provider
func (pr *ProviderRegistry) GetDefault() (types.AIProvider, error) {
	if pr.defaultProvider == "" {
		return nil, fmt.Errorf("no default provider set")
	}
	return pr.Get(pr.defaultProvider)
}

// List returns all registered provider names
func (pr *ProviderRegistry) List() []string {
	names := make([]string, 0, len(pr.providers))
	for name := range pr.providers {
		names = append(names, name)
	}
	return names
}

// AuthenticateAll attempts to authenticate all providers
func (pr *ProviderRegistry) AuthenticateAll(ctx context.Context) map[string]error {
	results := make(map[string]error)
	for name, provider := range pr.providers {
		results[name] = provider.Authenticate(ctx)
	}
	return results
}