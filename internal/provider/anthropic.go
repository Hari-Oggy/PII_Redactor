package provider

import (
	"encoding/json"
	"fmt"

	"github.com/enterprise/pii-gateway/pkg/models"
)

// AnthropicAdapter normalises Anthropic API request/response bodies.
// Anthropic format: {"messages": [{"role": "...", "content": "..."}]}
type AnthropicAdapter struct{}

func (a *AnthropicAdapter) Name() models.ProviderType {
	return models.ProviderAnthropic
}

type anthropicRequest struct {
	Messages []anthropicMessage `json:"messages"`
	Model    string             `json:"model,omitempty"`
	System   string             `json:"system,omitempty"`
}

type anthropicMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type anthropicResponse struct {
	Content []anthropicContent `json:"content,omitempty"`
	Error   *anthropicError    `json:"error,omitempty"`
}

type anthropicContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type anthropicError struct {
	Type    string `json:"type"`
	Message string `json:"message"`
}

func (a *AnthropicAdapter) ExtractText(body []byte) (map[string]string, error) {
	var req anthropicRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, fmt.Errorf("parse Anthropic request: %w", err)
	}

	fields := make(map[string]string)
	if req.System != "" {
		fields["system"] = req.System
	}
	for i, msg := range req.Messages {
		if msg.Content != "" {
			key := fmt.Sprintf("messages.%d.content", i)
			fields[key] = msg.Content
		}
	}
	return fields, nil
}

func (a *AnthropicAdapter) ReplaceText(body []byte, replacements map[string]string) ([]byte, error) {
	var req anthropicRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, fmt.Errorf("parse Anthropic request: %w", err)
	}

	if redacted, ok := replacements["system"]; ok {
		req.System = redacted
	}
	for i := range req.Messages {
		key := fmt.Sprintf("messages.%d.content", i)
		if redacted, ok := replacements[key]; ok {
			req.Messages[i].Content = redacted
		}
	}

	return json.Marshal(req)
}

func (a *AnthropicAdapter) ExtractResponseText(body []byte) (map[string]string, error) {
	var resp anthropicResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parse Anthropic response: %w", err)
	}

	fields := make(map[string]string)
	for i, c := range resp.Content {
		if c.Text != "" {
			key := fmt.Sprintf("content.%d.text", i)
			fields[key] = c.Text
		}
	}
	if resp.Error != nil && resp.Error.Message != "" {
		fields["error.message"] = resp.Error.Message
	}
	return fields, nil
}

func (a *AnthropicAdapter) ReplaceResponseText(body []byte, replacements map[string]string) ([]byte, error) {
	var resp anthropicResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parse Anthropic response: %w", err)
	}

	for i := range resp.Content {
		key := fmt.Sprintf("content.%d.text", i)
		if redacted, ok := replacements[key]; ok {
			resp.Content[i].Text = redacted
		}
	}
	if resp.Error != nil {
		if redacted, ok := replacements["error.message"]; ok {
			resp.Error.Message = redacted
		}
	}

	return json.Marshal(resp)
}
