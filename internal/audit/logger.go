// Package audit provides audit trail logging for PII detection events.
package audit

import (
	"encoding/json"
	"log"
	"os"
	"sync"

	"github.com/enterprise/pii-gateway/pkg/models"
)

// Logger writes audit entries to a file or stdout.
type Logger struct {
	mu     sync.Mutex
	file   *os.File
	encoder *json.Encoder
}

// NewLogger creates an audit logger. If path is empty, logs to stdout.
func NewLogger(path string) (*Logger, error) {
	var file *os.File
	var err error

	if path != "" {
		file, err = os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return nil, err
		}
	} else {
		file = os.Stdout
	}

	return &Logger{
		file:    file,
		encoder: json.NewEncoder(file),
	}, nil
}

// Log writes an audit entry.
func (l *Logger) Log(entry models.AuditEntry) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if err := l.encoder.Encode(entry); err != nil {
		log.Printf("WARN: failed to write audit entry: %v", err)
	}
}

// Close closes the audit log file.
func (l *Logger) Close() error {
	if l.file != os.Stdout {
		return l.file.Close()
	}
	return nil
}
