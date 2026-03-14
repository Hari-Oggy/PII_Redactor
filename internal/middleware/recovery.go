package middleware

import (
	"log"
	"net/http"
	"runtime/debug"
)

// Recovery recovers from panics in downstream handlers,
// logs the stack trace, and returns a 500 error.
func Recovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				requestID := r.Header.Get(CorrelationIDHeader)
				log.Printf("[%s] PANIC: %v\n%s", requestID, err, debug.Stack())
				http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}
