package audit

import "time"

// AuditEvent represents a single logged action within the PII Redactor system.
// It is used to track who accessed what and when, satisfying compliance requirements.
type AuditEvent struct {
	// ID is the unique identifier for the audit event.
	ID string `json:"id"`
	// UserID is the identifier of the user who performed the action.
	UserID string `json:"user_id"`
	// Action describes what the user did (e.g., "READ_PII", "MODIFY_CONFIG").
	Action string `json:"action"`
	// Timestamp records when the action occurred.
	Timestamp time.Time `json:"timestamp"`
}

// AuditConfig holds configuration for the audit logging subsystem.
type AuditConfig struct {
	// Enabled determines if audit logging is active.
	Enabled bool
	// DBConnection is the connection string for the audit database.
	DBConnection string
}
