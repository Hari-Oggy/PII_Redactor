// Package provider implements the Provider Adapter pattern for normalising
// request/response bodies across different LLM API providers (OpenAI,
// Anthropic, Azure). Each adapter also wraps a per-provider circuit breaker.
package provider

import (
	"fmt"

	"github.com/enterprise/pii-gateway/pkg/models"
)

// Adapter normalises provider-specific request/response JSON into a
// generic format for PII scanning, and denormalises back after redaction.
type Adapter interface {
	// Name returns the provider identifier.
	Name() models.ProviderType

	// ExtractText extracts all text fields from a request body that
	// should be scanned for PII. Returns a map of field paths to text.
	ExtractText(body []byte) (map[string]string, error)

	// ReplaceText takes the original body and a map of field paths to
	// their redacted text, rebuilding the provider-specific JSON.
	ReplaceText(body []byte, replacements map[string]string) ([]byte, error)

	// ExtractResponseText extracts text fields from a response body
	// for PII scanning (both success and error responses).
	ExtractResponseText(body []byte) (map[string]string, error)

	// ReplaceResponseText replaces text fields in a response body.
	ReplaceResponseText(body []byte, replacements map[string]string) ([]byte, error)
}

// Registry maps provider names to their adapters.
type Registry struct {
	adapters map[models.ProviderType]Adapter
}

// NewRegistry creates a provider registry with all known adapters.
func NewRegistry() *Registry {
	r := &Registry{
		adapters: make(map[models.ProviderType]Adapter),
	}
	r.Register(&OpenAIAdapter{})
	r.Register(&AnthropicAdapter{})
	r.Register(&AzureAdapter{})
	r.Register(&GeminiAdapter{})
	return r
}

// Register adds an adapter to the registry.
func (r *Registry) Register(a Adapter) {
	r.adapters[a.Name()] = a
}

// Get returns the adapter for the given provider.
func (r *Registry) Get(name models.ProviderType) (Adapter, error) {
	a, ok := r.adapters[name]
	if !ok {
		return nil, fmt.Errorf("unknown provider: %s", name)
	}
	return a, nil
}
