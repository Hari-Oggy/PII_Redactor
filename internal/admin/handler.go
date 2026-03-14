// Package admin provides the admin API served on a separate port.
package admin

import (
	"encoding/json"
	"net/http"

	"github.com/enterprise/pii-gateway/internal/config"
	"github.com/enterprise/pii-gateway/internal/pii"
)

// Handler serves admin API endpoints on a separate port.
type Handler struct {
	blocklist *pii.BlocklistDetector
	pipeline  *pii.Pipeline
}

// NewHandler creates an admin handler with references to the live PII engine.
func NewHandler(blocklist *pii.BlocklistDetector, pipeline *pii.Pipeline) *Handler {
	return &Handler{
		blocklist: blocklist,
		pipeline:  pipeline,
	}
}

// RegisterRoutes registers admin API routes on the given mux.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/healthz", h.healthz)
	mux.HandleFunc("/readyz", h.readyz)
	mux.HandleFunc("/admin/blocklist", h.adminAuth(h.handleBlocklist))
	mux.HandleFunc("/admin/config/reload", h.adminAuth(h.handleConfigReload))
}

// adminAuth wraps a handler with admin API key authentication.
func (h *Handler) adminAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := config.Get()
		if cfg != nil && cfg.Admin.Enabled {
			apiKey := r.Header.Get("X-Admin-Key")
			if apiKey != cfg.Admin.APIKey {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}
		}
		next(w, r)
	}
}

// healthz is a liveness probe — returns 200 if the process is running.
func (h *Handler) healthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "alive"})
}

// readyz is a readiness probe — returns 200 if config is loaded and
// the gateway is ready to accept traffic.
func (h *Handler) readyz(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, `{"status":"not ready","reason":"config not loaded"}`, http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "ready"})
}

// handleBlocklist handles GET/POST/DELETE for blocklist management.
// Operations directly affect the live BlocklistDetector in the PII engine.
func (h *Handler) handleBlocklist(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		terms := h.blocklist.GetTerms()
		json.NewEncoder(w).Encode(map[string]interface{}{
			"blocklist": terms,
		})

	case http.MethodPost:
		var req struct {
			Terms []string `json:"terms"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error":"invalid JSON"}`, http.StatusBadRequest)
			return
		}
		h.blocklist.AddTerms(req.Terms)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "updated",
			"count":  len(h.blocklist.GetTerms()),
		})

	case http.MethodDelete:
		h.blocklist.ClearTerms()
		json.NewEncoder(w).Encode(map[string]string{"status": "cleared"})

	default:
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
	}
}

// handleConfigReload triggers a config reload.
func (h *Handler) handleConfigReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	// Viper's WatchConfig handles reload automatically via fsnotify.
	// This endpoint confirms the current config is valid.
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, `{"error":"no config loaded"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":     "ok",
		"proxy_addr": cfg.Server.ProxyAddr,
		"admin_addr": cfg.Server.AdminAddr,
	})
}

