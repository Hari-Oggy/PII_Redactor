package proxy

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/enterprise/pii-gateway/internal/pii"
)

// StreamingProxy handles Server-Sent Events (SSE) streaming responses
// with overlap buffer to catch PII spanning chunk boundaries.
type StreamingProxy struct {
	pipeline   *pii.Pipeline
	redactor   *pii.Redactor
	rehydrator *pii.Rehydrator
	bufferSize int
}

// NewStreamingProxy creates a streaming proxy with the given overlap buffer size.
func NewStreamingProxy(pipeline *pii.Pipeline, redactor *pii.Redactor, rehydrator *pii.Rehydrator, bufferSize int) *StreamingProxy {
	return &StreamingProxy{
		pipeline:   pipeline,
		redactor:   redactor,
		rehydrator: rehydrator,
		bufferSize: bufferSize,
	}
}

// ProxySSE streams an SSE response from the upstream, scanning each chunk
// for PII with an overlap buffer to handle boundary-split patterns.
func (sp *StreamingProxy) ProxySSE(w http.ResponseWriter, upstream io.Reader, tokenMap *pii.TokenMap, requestID string) error {
	flusher, ok := w.(http.Flusher)
	if !ok {
		return fmt.Errorf("streaming not supported")
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	overlap := pii.NewOverlapBuffer(sp.bufferSize)
	scanner := bufio.NewScanner(upstream)

	for scanner.Scan() {
		line := scanner.Text()

		// SSE data lines start with "data: "
		if strings.HasPrefix(line, "data: ") {
			data := strings.TrimPrefix(line, "data: ")

			// Process through overlap buffer.
			scanWindow, overlapLen := overlap.Process([]byte(data))
			windowStr := string(scanWindow)

			// Detect PII in the scan window.
			matches := sp.pipeline.Detect(windowStr)

			output := data
			if len(matches) > 0 {
				// Redact PII in the full scan window.
				redacted, _ := sp.redactor.Redact(windowStr, matches, tokenMap)

				// Extract only the non-overlap portion from the redacted result.
				// The overlap portion will be re-scanned with the next chunk.
				if overlapLen > 0 && overlapLen < len(redacted) {
					output = redacted[overlapLen:]
				} else {
					output = redacted
				}
			}

			// Re-hydrate tokens in output.
			output = sp.rehydrator.Rehydrate(output, tokenMap)
			fmt.Fprintf(w, "data: %s\n", output)
		} else {
			// Non-data lines (event:, id:, retry:, empty lines) pass through.
			fmt.Fprintf(w, "%s\n", line)
		}

		flusher.Flush()
	}

	if err := scanner.Err(); err != nil {
		log.Printf("[%s] SSE scan error: %v", requestID, err)
		return err
	}

	return nil
}

