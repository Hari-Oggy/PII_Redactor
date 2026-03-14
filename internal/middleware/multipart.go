// Package middleware — multipart.go scans multipart file uploads for PII.
// Employees may upload files containing PII (.csv, .txt, etc.) via
// multipart/form-data requests. This middleware parses the multipart body,
// extracts text content from file parts, and runs PII detection on them.
package middleware

import (
	"bytes"
	"encoding/base64"
	"io"
	"log"
	"mime"
	"mime/multipart"
	"net/http"
	"strings"

	"github.com/enterprise/pii-gateway/internal/pii"
)

// MultipartScanner returns middleware that scans multipart/form-data
// uploads for PII in file content. Text-based files (.txt, .csv, .json,
// .xml, .md) are scanned directly. Base64-encoded content is decoded
// before scanning.
func MultipartScanner(pipeline *pii.Pipeline) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			contentType := r.Header.Get("Content-Type")

			// Only process multipart requests.
			if !strings.HasPrefix(contentType, "multipart/form-data") {
				next.ServeHTTP(w, r)
				return
			}

			requestID := r.Header.Get(CorrelationIDHeader)

			// Parse the boundary from Content-Type.
			_, params, err := mime.ParseMediaType(contentType)
			if err != nil || params["boundary"] == "" {
				next.ServeHTTP(w, r)
				return
			}

			// Read the body so we can parse and then restore it.
			body, err := io.ReadAll(r.Body)
			if err != nil {
				next.ServeHTTP(w, r)
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))

			// Parse multipart form.
			reader := multipart.NewReader(bytes.NewReader(body), params["boundary"])
			totalPII := 0

			for {
				part, err := reader.NextPart()
				if err == io.EOF {
					break
				}
				if err != nil {
					break
				}

				// Read part content.
				partContent, err := io.ReadAll(part)
				part.Close()
				if err != nil {
					continue
				}

				// Determine if this is a file upload.
				filename := part.FileName()
				if filename == "" {
					// Form field, not a file — skip.
					continue
				}

				// Extract text content based on file type.
				text := extractTextContent(filename, partContent)
				if text == "" {
					continue
				}

				// Run PII detection on the extracted text.
				matches := pipeline.Detect(text)
				if len(matches) > 0 {
					totalPII += len(matches)
					log.Printf("[%s] MULTIPART PII: %d items found in file %q",
						requestID, len(matches), filename)
				}
			}

			if totalPII > 0 {
				log.Printf("[%s] MULTIPART SCAN: total %d PII items in uploaded files",
					requestID, totalPII)
				// Add header so the proxy handler can include this in audit.
				r.Header.Set("X-Multipart-PII-Count", strings.Repeat("1", totalPII))
			}

			// Restore body and continue.
			r.Body = io.NopCloser(bytes.NewReader(body))
			next.ServeHTTP(w, r)
		})
	}
}

// extractTextContent extracts scannable text from a file based on its
// filename extension. Returns empty string for binary/unsupported formats.
func extractTextContent(filename string, content []byte) string {
	lower := strings.ToLower(filename)

	// Text-based formats we can scan directly.
	textExtensions := []string{
		".txt", ".csv", ".json", ".xml", ".md",
		".yaml", ".yml", ".log", ".tsv", ".html",
		".htm", ".sql", ".env", ".conf", ".ini",
	}

	for _, ext := range textExtensions {
		if strings.HasSuffix(lower, ext) {
			return string(content)
		}
	}

	// Try to decode base64 content (some APIs send files as base64).
	if isLikelyBase64(content) {
		decoded, err := base64.StdEncoding.DecodeString(string(content))
		if err == nil && isLikelyText(decoded) {
			return string(decoded)
		}
	}

	return ""
}

// isLikelyBase64 checks if content looks like base64-encoded data.
func isLikelyBase64(content []byte) bool {
	if len(content) < 20 || len(content) > 10*1024*1024 { // skip very small or very large
		return false
	}
	// Base64 alphabet: A-Z, a-z, 0-9, +, /, =
	for _, b := range content[:min(1000, len(content))] {
		if !((b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') ||
			(b >= '0' && b <= '9') || b == '+' || b == '/' || b == '=' ||
			b == '\n' || b == '\r') {
			return false
		}
	}
	return true
}

// isLikelyText checks if decoded content appears to be text (not binary).
func isLikelyText(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	sample := data[:min(500, len(data))]
	printable := 0
	for _, b := range sample {
		if (b >= 32 && b <= 126) || b == '\n' || b == '\r' || b == '\t' {
			printable++
		}
	}
	return float64(printable)/float64(len(sample)) > 0.85
}
