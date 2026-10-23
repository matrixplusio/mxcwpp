package rule

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"go.uber.org/zap"
)

// DefaultAuditLogPath is the default path for response audit logs.
const DefaultAuditLogPath = "/var/log/mxcwpp/response_audit.log"

// AuditEntry records a single response action execution.
type AuditEntry struct {
	Timestamp string            `json:"timestamp"`
	RuleID    string            `json:"rule_id"`
	RuleName  string            `json:"rule_name"`
	Severity  string            `json:"severity"`
	Action    string            `json:"action"`
	Enforce   bool              `json:"enforce"`
	EventType string            `json:"event_type"`
	Target    string            `json:"target"`           // PID, file path, or IP
	Result    string            `json:"result"`           // "executed", "skipped", "failed"
	Error     string            `json:"error,omitempty"`  // Error detail if failed.
	Fields    map[string]string `json:"fields,omitempty"` // Relevant event fields.
}

// AuditLogger writes structured audit entries to a log file.
// All response actions must be recorded for forensic and compliance purposes.
type AuditLogger struct {
	logger *zap.Logger
	mu     sync.Mutex
	file   *os.File
	path   string
}

// NewAuditLogger creates an audit logger that writes to the given path.
// Creates the parent directory if it does not exist.
func NewAuditLogger(logger *zap.Logger, path string) (*AuditLogger, error) {
	if path == "" {
		path = DefaultAuditLogPath
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return nil, fmt.Errorf("create audit log directory %s: %w", dir, err)
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0640)
	if err != nil {
		return nil, fmt.Errorf("open audit log %s: %w", path, err)
	}

	return &AuditLogger{
		logger: logger,
		file:   f,
		path:   path,
	}, nil
}

// Log records an audit entry to the log file and the structured logger.
func (a *AuditLogger) Log(entry AuditEntry) {
	entry.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)

	// Write JSON line to audit file.
	data, err := json.Marshal(entry)
	if err != nil {
		a.logger.Error("failed to marshal audit entry", zap.Error(err))
		return
	}
	data = append(data, '\n')

	a.mu.Lock()
	_, writeErr := a.file.Write(data)
	a.mu.Unlock()

	if writeErr != nil {
		a.logger.Error("failed to write audit entry",
			zap.String("path", a.path),
			zap.Error(writeErr),
		)
	}

	// Also emit structured log for centralized logging.
	a.logger.Info("response action",
		zap.String("rule_id", entry.RuleID),
		zap.String("action", entry.Action),
		zap.Bool("enforce", entry.Enforce),
		zap.String("target", entry.Target),
		zap.String("result", entry.Result),
	)
}

// Close closes the audit log file.
func (a *AuditLogger) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.file != nil {
		return a.file.Close()
	}
	return nil
}
