// Package pii — context.go provides middleware and helpers to store/retrieve
// a per-request TokenMap via context.Context.
package pii

import (
	"context"
	"log"
	"net/http"
)

// tmKey is the context key for the per-request TokenMap.
type tmKey struct{}

// TokenMapMiddleware creates a per-request TokenMap and stores it in the
// request context. This enables shared access from both middleware (HeaderScan)
// and the proxy handler without duplicating the token map.
func TokenMapMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tm, err := NewTokenMap()
		if err != nil {
			log.Printf("ERROR: failed to create token map: %v", err)
			http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
			return
		}
		defer tm.Clear()

		ctx := context.WithValue(r.Context(), tmKey{}, tm)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// GetTokenMap retrieves the per-request TokenMap from the context.
// Returns nil if no TokenMap is stored (should not happen if middleware is wired).
func GetTokenMap(ctx context.Context) *TokenMap {
	if tm, ok := ctx.Value(tmKey{}).(*TokenMap); ok {
		return tm
	}
	return nil
}
