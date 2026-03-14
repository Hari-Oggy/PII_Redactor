package provider

import (
	"encoding/json"
	"fmt"

	"github.com/enterprise/pii-gateway/pkg/models"
)

// GeminiAdapter normalises Google Gemini API request/response bodies.
//
// Gemini request format:
//
//	{
//	  "contents": [
//	    {"role": "user", "parts": [{"text": "..."}]}
//	  ],
//	  "systemInstruction": {"parts": [{"text": "..."}]}
//	}
//
// Gemini response format:
//
//	{
//	  "candidates": [
//	    {"content": {"role": "model", "parts": [{"text": "..."}]}}
//	  ],
//	  "error": {"message": "..."}
//	}
type GeminiAdapter struct{}

func (a *GeminiAdapter) Name() models.ProviderType {
	return models.ProviderGemini
}

// --- Request types ---

type geminiRequest struct {
	Contents          []geminiContent       `json:"contents"`
	SystemInstruction *geminiSystemInstruct `json:"systemInstruction,omitempty"`
}

type geminiContent struct {
	Role  string       `json:"role"`
	Parts []geminiPart `json:"parts"`
}

type geminiPart struct {
	Text string `json:"text,omitempty"`
}

type geminiSystemInstruct struct {
	Parts []geminiPart `json:"parts"`
}

// --- Response types ---

type geminiResponse struct {
	Candidates []geminiCandidate `json:"candidates,omitempty"`
	Error      *geminiError      `json:"error,omitempty"`
}

type geminiCandidate struct {
	Content geminiContent `json:"content"`
	Index   int           `json:"index"`
}

type geminiError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Status  string `json:"status"`
}

// --- Adapter methods ---

func (a *GeminiAdapter) ExtractText(body []byte) (map[string]string, error) {
	var req geminiRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, fmt.Errorf("parse Gemini request: %w", err)
	}

	fields := make(map[string]string)

	// Extract system instruction.
	if req.SystemInstruction != nil {
		for i, part := range req.SystemInstruction.Parts {
			if part.Text != "" {
				key := fmt.Sprintf("systemInstruction.parts.%d.text", i)
				fields[key] = part.Text
			}
		}
	}

	// Extract content parts.
	for i, content := range req.Contents {
		for j, part := range content.Parts {
			if part.Text != "" {
				key := fmt.Sprintf("contents.%d.parts.%d.text", i, j)
				fields[key] = part.Text
			}
		}
	}

	return fields, nil
}

func (a *GeminiAdapter) ReplaceText(body []byte, replacements map[string]string) ([]byte, error) {
	var req geminiRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, fmt.Errorf("parse Gemini request: %w", err)
	}

	// Replace system instruction parts.
	if req.SystemInstruction != nil {
		for i := range req.SystemInstruction.Parts {
			key := fmt.Sprintf("systemInstruction.parts.%d.text", i)
			if redacted, ok := replacements[key]; ok {
				req.SystemInstruction.Parts[i].Text = redacted
			}
		}
	}

	// Replace content parts.
	for i := range req.Contents {
		for j := range req.Contents[i].Parts {
			key := fmt.Sprintf("contents.%d.parts.%d.text", i, j)
			if redacted, ok := replacements[key]; ok {
				req.Contents[i].Parts[j].Text = redacted
			}
		}
	}

	return json.Marshal(req)
}

func (a *GeminiAdapter) ExtractResponseText(body []byte) (map[string]string, error) {
	var resp geminiResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parse Gemini response: %w", err)
	}

	fields := make(map[string]string)

	// Extract from candidates.
	for i, candidate := range resp.Candidates {
		for j, part := range candidate.Content.Parts {
			if part.Text != "" {
				key := fmt.Sprintf("candidates.%d.content.parts.%d.text", i, j)
				fields[key] = part.Text
			}
		}
	}

	// Extract from error messages (may echo PII).
	if resp.Error != nil && resp.Error.Message != "" {
		fields["error.message"] = resp.Error.Message
	}

	return fields, nil
}

func (a *GeminiAdapter) ReplaceResponseText(body []byte, replacements map[string]string) ([]byte, error) {
	var resp geminiResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parse Gemini response: %w", err)
	}

	for i := range resp.Candidates {
		for j := range resp.Candidates[i].Content.Parts {
			key := fmt.Sprintf("candidates.%d.content.parts.%d.text", i, j)
			if redacted, ok := replacements[key]; ok {
				resp.Candidates[i].Content.Parts[j].Text = redacted
			}
		}
	}

	if resp.Error != nil {
		if redacted, ok := replacements["error.message"]; ok {
			resp.Error.Message = redacted
		}
	}

	return json.Marshal(resp)
}
