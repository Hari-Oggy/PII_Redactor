// Package middleware provides HTTP middleware for the PII gateway.
package middleware

import (
	"net/http"

	"github.com/google/uuid"
)

// CorrelationIDHeader is the header name for request correlation.
const CorrelationIDHeader = "X-Request-ID"

// Correlation generates a unique X-Request-ID for each request and
// propagates it to the response and upstream requests.
func Correlation(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Use existing ID if provided, otherwise generate one.
		requestID := r.Header.Get(CorrelationIDHeader)
		if requestID == "" {
			requestID = uuid.New().String()
		}

		// Set on request for downstream handlers.
		r.Header.Set(CorrelationIDHeader, requestID)

		// Set on response.
		w.Header().Set(CorrelationIDHeader, requestID)

		next.ServeHTTP(w, r)
	})
}
