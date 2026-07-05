package audit

import (
	"context"
	"net/http"
	"time"

	"github.com/google/uuid"
)

// APIHandler handles HTTP requests related to audit logging.
type APIHandler struct {
	db DBClient
}

// NewAPIHandler creates a new APIHandler with the injected DBClient.
func NewAPIHandler(db DBClient) *APIHandler {
	return &APIHandler{
		db: db,
	}
}

// LogRequest is a middleware/handler that logs incoming HTTP requests as audit events.
func (h *APIHandler) LogRequest(w http.ResponseWriter, r *http.Request) {
	// Generate a mock audit event for the incoming request
	event := AuditEvent{
		ID:        uuid.New().String(),
		UserID:    r.Header.Get("X-User-ID"),
		Action:    "API_REQUEST_" + r.Method,
		Timestamp: time.Now(),
	}

	// Persist the event explicitly to track blast radius
	_ = h.db.SaveEvent(context.Background(), event)

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Request logged successfully"))
}
