package audit

import (
	"context"
	"fmt"
)

// DBClient interface defines the contract for persisting audit events.
type DBClient interface {
	SaveEvent(ctx context.Context, event AuditEvent) error
}

// PostgresDBClient implements DBClient for a PostgreSQL backend.
type PostgresDBClient struct {
	connString string
}

// NewPostgresDBClient initializes a new PostgresDBClient with the given connection string.
func NewPostgresDBClient(connString string) *PostgresDBClient {
	return &PostgresDBClient{
		connString: connString,
	}
}

// SaveEvent persists an AuditEvent to the database.
func (db *PostgresDBClient) SaveEvent(ctx context.Context, event AuditEvent) error {
	// Simulating a database save operation
	fmt.Printf("Saving event %s for user %s to database...\n", event.Action, event.UserID)
	return nil
}
