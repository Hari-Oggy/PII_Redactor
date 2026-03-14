package middleware

import (
	"net/http"

	"github.com/enterprise/pii-gateway/internal/config"
)

// BodyLimit enforces a maximum request body size to prevent OOM attacks.
func BodyLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg := config.Get()
		maxBytes := int64(10 * 1024 * 1024) // 10 MB default
		if cfg != nil && cfg.Server.MaxBodyBytes > 0 {
			maxBytes = cfg.Server.MaxBodyBytes
		}

		r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
		next.ServeHTTP(w, r)
	})
}
