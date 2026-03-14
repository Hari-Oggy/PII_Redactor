// Package proxy implements the reverse-proxy handler that intercepts
// requests to external LLM APIs, applies PII redaction, and re-hydrates
// responses.
package proxy

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"os"
	"strings"
	"time"

	"github.com/enterprise/pii-gateway/internal/audit"
	"github.com/enterprise/pii-gateway/internal/config"
	"github.com/enterprise/pii-gateway/internal/middleware"
	"github.com/enterprise/pii-gateway/internal/pii"
	"github.com/enterprise/pii-gateway/internal/provider"
	"github.com/enterprise/pii-gateway/pkg/models"
	"github.com/sony/gobreaker"
)

// Handler holds the dependencies for the proxy handler.
type Handler struct {
	registry      *provider.Registry
	pipeline      *pii.Pipeline
	redactor      *pii.Redactor
	rehydrator    *pii.Rehydrator
	streaming     *StreamingProxy
	auditLogger   *audit.Logger
	breakers      map[string]*gobreaker.CircuitBreaker
	httpClient    *http.Client
}

// NewHandler creates a proxy handler with all dependencies.
func NewHandler(
	registry *provider.Registry,
	pipeline *pii.Pipeline,
	redactor *pii.Redactor,
	rehydrator *pii.Rehydrator,
	auditLogger *audit.Logger,
	transport *http.Transport,
	cfg *config.Config,
) *Handler {
	breakers := make(map[string]*gobreaker.CircuitBreaker)
	for _, p := range cfg.Proxy.Providers {
		breakers[p.Name] = provider.NewCircuitBreaker(
			p.Name,
			p.CircuitBreaker.MaxFailures,
			p.CircuitBreaker.Timeout,
		)
	}

	streaming := NewStreamingProxy(pipeline, redactor, rehydrator, cfg.PII.OverlapBufferSize)

	return &Handler{
		registry:    registry,
		pipeline:    pipeline,
		redactor:    redactor,
		rehydrator:  rehydrator,
		streaming:   streaming,
		auditLogger: auditLogger,
		breakers:    breakers,
		httpClient: &http.Client{
			Timeout:   cfg.Proxy.UpstreamTimeout,
			Transport: transport,
		},
	}
}

// ServeHTTP handles proxied requests: detects PII, redacts, forwards,
// scans response, re-hydrates, and returns.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	requestID := r.Header.Get(middleware.CorrelationIDHeader)
	cfg := config.Get()

	// Determine which provider this request is for based on path prefix.
	providerName, providerCfg := h.resolveProvider(r.URL.Path, cfg)
	if providerCfg == nil {
		http.Error(w, `{"error":"unknown provider route"}`, http.StatusBadRequest)
		return
	}

	// Get the provider adapter.
	adapter, err := h.registry.Get(models.ProviderType(providerName))
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusBadRequest)
		return
	}

	// Read request body.
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, `{"error":"failed to read request body"}`, http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	// Get per-request token map from context (created by TokenMapMiddleware).
	tokenMap := pii.GetTokenMap(r.Context())
	if tokenMap == nil {
		// Fallback: create one if middleware wasn't wired (defensive).
		tokenMap, err = pii.NewTokenMap()
		if err != nil {
			http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
			return
		}
		defer tokenMap.Clear()
	}

	// === INBOUND PIPELINE ===
	// 1. Extract text fields from provider-specific format.
	fields, err := adapter.ExtractText(body)
	if err != nil {
		log.Printf("[%s] WARN: failed to parse request body: %v", requestID, err)
		// Fallback: scan raw body.
		fields = map[string]string{"raw": string(body)}
	}

	// 2. Detect and redact PII in each field.
	replacements := make(map[string]string)
	totalPII := 0
	for key, text := range fields {
		matches := h.pipeline.Detect(text)
		if len(matches) > 0 {
			redacted, spans := h.redactor.Redact(text, matches, tokenMap)
			replacements[key] = redacted
			totalPII += len(spans)

			// Record metrics.
			for _, s := range spans {
				middleware.RecordPIIDetection(s.Type, s.DetectorName)
			}
		}
	}

	// 3. Rebuild request body with redacted text.
	var sanitisedBody []byte
	if len(replacements) > 0 {
		sanitisedBody, err = adapter.ReplaceText(body, replacements)
		if err != nil {
			log.Printf("[%s] WARN: failed to rebuild request: %v", requestID, err)
			sanitisedBody = body // fallback to original
		}
	} else {
		sanitisedBody = body
	}

	log.Printf("[%s] PII detected: %d items, redacted and forwarding to %s",
		requestID, totalPII, providerName)

	// === OUTBOUND PIPELINE ===
	// 4. Circuit breaker check.
	cb := h.breakers[providerName]
	if cb == nil {
		http.Error(w, `{"error":"no circuit breaker for provider"}`, http.StatusInternalServerError)
		return
	}

	// 5. Forward to upstream via circuit breaker.
	result, err := cb.Execute(func() (interface{}, error) {
		return h.forwardRequest(r, providerCfg, sanitisedBody, requestID)
	})
	if err != nil {
		if err == gobreaker.ErrOpenState || err == gobreaker.ErrTooManyRequests {
			log.Printf("[%s] Circuit breaker OPEN for %s", requestID, providerName)
			http.Error(w, `{"error":"service temporarily unavailable"}`, http.StatusServiceUnavailable)
			return
		}
		log.Printf("[%s] Upstream error: %v", requestID, err)
		http.Error(w, `{"error":"upstream request failed"}`, http.StatusBadGateway)
		return
	}

	upstreamResp := result.(*upstreamResponse)
	defer upstreamResp.Body.Close()

	// === RESPONSE PIPELINE ===
	// 6. Check if this is a streaming (SSE) response.
	contentType := upstreamResp.Header.Get("Content-Type")
	if strings.Contains(contentType, "text/event-stream") {
		// Route SSE responses through the streaming proxy with overlap buffer.
		for key, values := range upstreamResp.Header {
			for _, v := range values {
				w.Header().Add(key, v)
			}
		}
		w.Header().Set(middleware.CorrelationIDHeader, requestID)
		if err := h.streaming.ProxySSE(w, upstreamResp.Body, tokenMap, requestID); err != nil {
			log.Printf("[%s] SSE proxy error: %v", requestID, err)
		}
		return
	}

	// Non-streaming response: buffer and process.
	respBody, err := io.ReadAll(upstreamResp.Body)
	if err != nil {
		http.Error(w, `{"error":"failed to read upstream response"}`, http.StatusBadGateway)
		return
	}

	// 7. Scan ALL responses (2xx and errors) for PII.
	respFields, err := adapter.ExtractResponseText(respBody)
	if err == nil && len(respFields) > 0 {
		respReplacements := make(map[string]string)
		for key, text := range respFields {
			// First scan for NEW PII generated by the LLM.
			matches := h.pipeline.Detect(text)
			if len(matches) > 0 {
				redacted, _ := h.redactor.Redact(text, matches, tokenMap)
				text = redacted
			}
			// Then re-hydrate our HMAC-verified tokens.
			rehydrated := h.rehydrator.Rehydrate(text, tokenMap)
			if rehydrated != respFields[key] {
				respReplacements[key] = rehydrated
			}
		}
		if len(respReplacements) > 0 {
			respBody, _ = adapter.ReplaceResponseText(respBody, respReplacements)
		}
	}

	// 8. Copy upstream response headers and body to client.
	for key, values := range upstreamResp.Header {
		for _, v := range values {
			w.Header().Add(key, v)
		}
	}
	w.Header().Set(middleware.CorrelationIDHeader, requestID)
	w.WriteHeader(upstreamResp.StatusCode)
	w.Write(respBody)

	// 9. Write audit log entry.
	h.writeAuditEntry(requestID, r, providerName, totalPII, upstreamResp.StatusCode, sanitisedBody, startTime)
}

// upstreamResponse wraps the HTTP response from the LLM API.
type upstreamResponse struct {
	StatusCode int
	Header     http.Header
	Body       io.ReadCloser
}

// forwardRequest sends the sanitised request to the upstream LLM API.
func (h *Handler) forwardRequest(
	originalReq *http.Request,
	providerCfg *config.ProviderConfig,
	body []byte,
	requestID string,
) (*upstreamResponse, error) {
	// Build upstream URL.
	upstreamPath := strings.TrimPrefix(originalReq.URL.Path, providerCfg.PathPrefix)
	upstreamURL := providerCfg.BaseURL + upstreamPath
	if originalReq.URL.RawQuery != "" {
		upstreamURL += "?" + originalReq.URL.RawQuery
	}

	// Create upstream request.
	ctx, cancel := context.WithTimeout(originalReq.Context(), h.httpClient.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, originalReq.Method, upstreamURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create upstream request: %w", err)
	}

	// Copy relevant headers.
	req.Header.Set("Content-Type", originalReq.Header.Get("Content-Type"))
	req.Header.Set(middleware.CorrelationIDHeader, requestID)

	// Set API key from environment variable.
	if providerCfg.APIKeyEnv != "" {
		apiKey := os.Getenv(providerCfg.APIKeyEnv)
		if apiKey != "" {
			// Different providers use different auth mechanisms.
			switch providerCfg.Name {
			case "anthropic":
				req.Header.Set("x-api-key", apiKey)
				req.Header.Set("anthropic-version", "2023-06-01")
			case "azure":
				req.Header.Set("api-key", apiKey)
			case "gemini":
				// Gemini uses API key as query parameter.
				q := req.URL.Query()
				q.Set("key", apiKey)
				req.URL.RawQuery = q.Encode()
			default: // openai and others use Bearer token
				req.Header.Set("Authorization", "Bearer "+apiKey)
			}
		} else {
			// Fallback: pass through original Authorization header.
			if auth := originalReq.Header.Get("Authorization"); auth != "" {
				req.Header.Set("Authorization", auth)
			}
		}
	}

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("upstream request: %w", err)
	}

	return &upstreamResponse{
		StatusCode: resp.StatusCode,
		Header:     resp.Header,
		Body:       resp.Body,
	}, nil
}

// resolveProvider matches a request path to a configured provider.
func (h *Handler) resolveProvider(path string, cfg *config.Config) (string, *config.ProviderConfig) {
	if cfg == nil {
		return "", nil
	}
	for i, p := range cfg.Proxy.Providers {
		if strings.HasPrefix(path, p.PathPrefix) {
			return p.Name, &cfg.Proxy.Providers[i]
		}
	}
	return "", nil
}

// writeAuditEntry records a structured audit log entry for the request.
func (h *Handler) writeAuditEntry(
	requestID string,
	r *http.Request,
	providerName string,
	piiCount int,
	statusCode int,
	sanitisedBody []byte,
	startTime time.Time,
) {
	if h.auditLogger == nil {
		return
	}

	// Collect PII types from the token map.
	var piiTypes []string
	tokenMap := pii.GetTokenMap(r.Context())
	if tokenMap != nil && tokenMap.Count() > 0 {
		// Types are embedded in token format: __PII_{type}_{uuid}_{hmac}__
		// For simplicity, just report the count.
		piiTypes = []string{fmt.Sprintf("%d types detected", piiCount)}
	}

	h.auditLogger.Log(models.AuditEntry{
		RequestID:       requestID,
		Timestamp:       startTime.UTC().Format(time.RFC3339),
		UserID:          middleware.GetUserID(r),
		Provider:        models.ProviderType(providerName),
		PIIDetected:     piiCount,
		PIITypes:        piiTypes,
		RequestRedacted: string(sanitisedBody),
		StatusCode:      statusCode,
		LatencyMs:       time.Since(startTime).Milliseconds(),
	})
}

// Ensure Handler is unused in this context but available for httputil.
var _ http.Handler = (*httputil.ReverseProxy)(nil)

