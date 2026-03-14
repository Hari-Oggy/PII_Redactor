package provider

import (
	"github.com/enterprise/pii-gateway/pkg/models"
)

// AzureAdapter normalises Azure OpenAI API request/response bodies.
// Azure OpenAI uses the same format as OpenAI, so we delegate to OpenAIAdapter.
type AzureAdapter struct {
	delegate OpenAIAdapter
}

func (a *AzureAdapter) Name() models.ProviderType {
	return models.ProviderAzure
}

func (a *AzureAdapter) ExtractText(body []byte) (map[string]string, error) {
	return a.delegate.ExtractText(body)
}

func (a *AzureAdapter) ReplaceText(body []byte, replacements map[string]string) ([]byte, error) {
	return a.delegate.ReplaceText(body, replacements)
}

func (a *AzureAdapter) ExtractResponseText(body []byte) (map[string]string, error) {
	return a.delegate.ExtractResponseText(body)
}

func (a *AzureAdapter) ReplaceResponseText(body []byte, replacements map[string]string) ([]byte, error) {
	return a.delegate.ReplaceResponseText(body, replacements)
}
