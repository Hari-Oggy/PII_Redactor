package middleware

import (
	"context"
	"net/http"
	"os"
	"strings"

	"github.com/enterprise/pii-gateway/internal/config"
	"github.com/golang-jwt/jwt/v5"
)

// contextKey is a private type for context keys in this package.
type contextKey string

// UserIDKey is the context key for the authenticated user ID (from JWT sub claim).
const UserIDKey contextKey = "user_id"

// Auth validates requests using JWT tokens or static API keys.
func Auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg := config.Get()
		if cfg == nil || !cfg.Auth.Enabled {
			next.ServeHTTP(w, r)
			return
		}

		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, `{"error":"missing Authorization header"}`, http.StatusUnauthorized)
			return
		}

		// Check Bearer token.
		if strings.HasPrefix(authHeader, "Bearer ") {
			token := strings.TrimPrefix(authHeader, "Bearer ")

			// Check against static API keys first.
			for _, key := range cfg.Auth.APIKeys {
				if token == key {
					next.ServeHTTP(w, r)
					return
				}
			}

			// JWT validation using golang-jwt/jwt/v5.
			claims, err := validateJWT(token, cfg)
			if err != nil {
				http.Error(w, `{"error":"invalid token: `+err.Error()+`"}`, http.StatusUnauthorized)
				return
			}

			// Extract user ID from "sub" claim and store in context.
			if sub, ok := claims["sub"].(string); ok {
				ctx := context.WithValue(r.Context(), UserIDKey, sub)
				r = r.WithContext(ctx)
			}

			next.ServeHTTP(w, r)
			return
		}

		http.Error(w, `{"error":"unsupported auth scheme"}`, http.StatusUnauthorized)
	})
}

// validateJWT parses and validates a JWT token using either:
// - Symmetric key (HMAC) from cfg.Auth.JWTSecret, or
// - Asymmetric key (RSA/ECDSA) from cfg.Auth.JWTPublicKeyFile
func validateJWT(tokenStr string, cfg *config.Config) (jwt.MapClaims, error) {
	claims := jwt.MapClaims{}

	_, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		// If a public key file is configured, use asymmetric verification.
		if cfg.Auth.JWTPublicKeyFile != "" {
			keyData, err := os.ReadFile(cfg.Auth.JWTPublicKeyFile)
			if err != nil {
				return nil, err
			}

			// Try RSA first, then ECDSA.
			if rsaKey, err := jwt.ParseRSAPublicKeyFromPEM(keyData); err == nil {
				return rsaKey, nil
			}
			if ecKey, err := jwt.ParseECPublicKeyFromPEM(keyData); err == nil {
				return ecKey, nil
			}
			return nil, jwt.ErrTokenSignatureInvalid
		}

		// Fall back to symmetric (HMAC) verification.
		if cfg.Auth.JWTSecret != "" {
			return []byte(cfg.Auth.JWTSecret), nil
		}

		return nil, jwt.ErrTokenSignatureInvalid
	})

	if err != nil {
		return nil, err
	}

	return claims, nil
}

// GetUserID extracts the authenticated user ID from the request context.
func GetUserID(r *http.Request) string {
	if userID, ok := r.Context().Value(UserIDKey).(string); ok {
		return userID
	}
	return ""
}

