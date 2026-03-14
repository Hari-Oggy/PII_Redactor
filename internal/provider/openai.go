package provider

import (
	"encoding/json"
	"fmt"

	"github.com/enterprise/pii-gateway/pkg/models"
)

// OpenAIAdapter normalises OpenAI API request/response bodies.
// OpenAI format: {"messages": [{"role": "...", "content": "..."}]}
type OpenAIAdapter struct{}

func (a *OpenAIAdapter) Name() models.ProviderType {
	return models.ProviderOpenAI
}

type openAIRequest struct {
	Messages []openAIMessage `json:"messages"`
	Model    string          `json:"model,omitempty"`
}

type openAIMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type openAIResponse struct {
	Choices []openAIChoice `json:"choices,omitempty"`
	Error   *openAIError   `json:"error,omitempty"`
}

type openAIChoice struct {
	Message openAIMessage `json:"message"`
	Index   int           `json:"index"`
}

type openAIError struct {
	Message string `json:"message"`
	Type    string `json:"type"`
}

func (a *OpenAIAdapter) ExtractText(body []byte) (map[string]string, error) {
	var req openAIRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, fmt.Errorf("parse OpenAI request: %w", err)
	}

	fields := make(map[string]string)
	for i, msg := range req.Messages {
		if msg.Content != "" {
			key := fmt.Sprintf("messages.%d.content", i)
			fields[key] = msg.Content
		}
	}
	return fields, nil
}

func (a *OpenAIAdapter) ReplaceText(body []byte, replacements map[string]string) ([]byte, error) {
	var req openAIRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, fmt.Errorf("parse OpenAI request: %w", err)
	}

	for i := range req.Messages {
		key := fmt.Sprintf("messages.%d.content", i)
		if redacted, ok := replacements[key]; ok {
			req.Messages[i].Content = redacted
		}
	}

	return json.Marshal(req)
}

func (a *OpenAIAdapter) ExtractResponseText(body []byte) (map[string]string, error) {
	var resp openAIResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parse OpenAI response: %w", err)
	}

	fields := make(map[string]string)

	// Extract from choices.
	for i, choice := range resp.Choices {
		if choice.Message.Content != "" {
			key := fmt.Sprintf("choices.%d.message.content", i)
			fields[key] = choice.Message.Content
		}
	}

	// Extract from error messages too (may echo PII).
	if resp.Error != nil && resp.Error.Message != "" {
		fields["error.message"] = resp.Error.Message
	}

	return fields, nil
}

func (a *OpenAIAdapter) ReplaceResponseText(body []byte, replacements map[string]string) ([]byte, error) {
	var resp openAIResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parse OpenAI response: %w", err)
	}

	for i := range resp.Choices {
		key := fmt.Sprintf("choices.%d.message.content", i)
		if redacted, ok := replacements[key]; ok {
			resp.Choices[i].Message.Content = redacted
		}
	}
	if resp.Error != nil {
		if redacted, ok := replacements["error.message"]; ok {
			resp.Error.Message = redacted
		}
	}

	return json.Marshal(resp)
}
