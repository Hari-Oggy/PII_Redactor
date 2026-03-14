package middleware

import (
	"net/http"
	"strings"

	"github.com/enterprise/pii-gateway/internal/config"
	"github.com/enterprise/pii-gateway/internal/pii"
)

// HeaderScan scans configured HTTP headers and query parameters for PII,
// replacing detected PII with redacted placeholders.
func HeaderScan(pipeline *pii.Pipeline, redactor *pii.Redactor, tokenMap func(r *http.Request) *pii.TokenMap) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cfg := config.Get()
			if cfg == nil {
				next.ServeHTTP(w, r)
				return
			}

			// Scan configured headers.
			for _, header := range cfg.PII.ScanHeaders {
				val := r.Header.Get(header)
				if val == "" {
					continue
				}
				matches := pipeline.Detect(val)
				if len(matches) > 0 {
					tm := tokenMap(r)
					redacted, _ := redactor.Redact(val, matches, tm)
					r.Header.Set(header, redacted)
				}
			}

			// Scan query parameters if enabled.
			if cfg.PII.ScanQueryParams {
				q := r.URL.Query()
				modified := false
				for key, values := range q {
					for i, val := range values {
						matches := pipeline.Detect(val)
						if len(matches) > 0 {
							tm := tokenMap(r)
							redacted, _ := redactor.Redact(val, matches, tm)
							values[i] = redacted
							modified = true
						}
						_ = key // used in range
					}
				}
				if modified {
					r.URL.RawQuery = q.Encode()
					// Also update RequestURI.
					r.RequestURI = r.URL.RequestURI()
				}
			}

			// Remove any Authorization header PII leakage warning headers.
			if auth := r.Header.Get("Authorization"); auth != "" {
				if strings.HasPrefix(auth, "Bearer ") {
					// Don't scan the auth token itself — it's supposed to be opaque.
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}
