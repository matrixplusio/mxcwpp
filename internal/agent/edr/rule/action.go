//go:build linux

package rule

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"go.uber.org/zap"
)

// protectedPaths lists directories that must never be quarantined.
// Prevents the agent from crippling the host or itself.
var protectedPaths = []string{
	"/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/lib", "/usr/lib64",
	"/lib", "/lib64", "/etc/init.d", "/etc/systemd",
	// Agent self-protection.
	"/usr/local/mxcwpp",
	"/var/mxcwpp",
	"/var/lib/mxcwpp",
	"/var/log/mxcwpp",
}

// DefaultQuarantineDir is where quarantined files are stored.
const DefaultQuarantineDir = "/var/mxcwpp/quarantine"

// ActionExecutor handles response actions (kill, suspend, quarantine).
// All executions are gated by the rule's enforce flag, circuit breaker, and audited.
type ActionExecutor struct {
	logger        *zap.Logger
	audit         *AuditLogger
	quarantineDir string
	breaker       *circuitBreaker
}

// NewActionExecutor creates a new action executor.
func NewActionExecutor(logger *zap.Logger, audit *AuditLogger, quarantineDir string) *ActionExecutor {
	if quarantineDir == "" {
		quarantineDir = DefaultQuarantineDir
	}
	return &ActionExecutor{
		logger:        logger,
		audit:         audit,
		quarantineDir: quarantineDir,
		breaker:       newCircuitBreaker(logger.Named("breaker")),
	}
}

// Execute runs the appropriate action for a matched rule.
// If enforce is false, the action is logged but not executed ("dry run").
// Destructive actions (kill/suspend/quarantine) are gated by the circuit breaker.
func (a *ActionExecutor) Execute(r *Rule, fields map[string]string) {
	action := r.Agent.Action
	enforce := r.Agent.Enforce

	switch action {
	case ActionAlert:
		// Alert is always "executed" — it just means reporting.
		a.audit.Log(AuditEntry{
			RuleID:    r.ID,
			RuleName:  r.Name,
			Severity:  string(r.Severity),
			Action:    string(action),
			Enforce:   enforce,
			EventType: r.Agent.Match.EventType,
			Target:    fields["pid"],
			Result:    "executed",
			Fields:    fields,
		})

	case ActionSuspend, ActionKill, ActionQuarantine:
		// Circuit breaker: prevent runaway destructive actions.
		if enforce && !a.breaker.Allow() {
			a.logAction(r, fields, "circuit_breaker", "action rate exceeded threshold, downgraded to alert")
			return
		}

		switch action {
		case ActionSuspend:
			a.executeSuspend(r, fields, enforce)
		case ActionKill:
			a.executeKill(r, fields, enforce)
		case ActionQuarantine:
			a.executeQuarantine(r, fields, enforce)
		}
	}
}

// BreakerStats returns circuit breaker status for heartbeat reporting.
func (a *ActionExecutor) BreakerStats() (tripped bool, tripCount int, windowActions int) {
	return a.breaker.Stats()
}

// executeSuspend sends SIGSTOP to a process (reversible via SIGCONT).
func (a *ActionExecutor) executeSuspend(r *Rule, fields map[string]string, enforce bool) {
	pid, err := strconv.Atoi(fields["pid"])
	if err != nil {
		a.logAction(r, fields, "failed", fmt.Sprintf("invalid pid: %s", fields["pid"]))
		return
	}

	if !enforce {
		a.logAction(r, fields, "skipped", "")
		return
	}

	// TOCTOU verification: check the process is still the same one.
	if !a.verifyProcess(pid, fields) {
		a.logAction(r, fields, "aborted", "PID reuse detected, process identity mismatch")
		return
	}

	if err := syscall.Kill(pid, syscall.SIGSTOP); err != nil {
		a.logAction(r, fields, "failed", err.Error())
		return
	}

	a.logAction(r, fields, "executed", "")
}

// executeKill sends SIGKILL to a process (irreversible).
func (a *ActionExecutor) executeKill(r *Rule, fields map[string]string, enforce bool) {
	pid, err := strconv.Atoi(fields["pid"])
	if err != nil {
		a.logAction(r, fields, "failed", fmt.Sprintf("invalid pid: %s", fields["pid"]))
		return
	}

	if !enforce {
		a.logAction(r, fields, "skipped", "")
		return
	}

	// TOCTOU verification: check the process is still the same one.
	if !a.verifyProcess(pid, fields) {
		a.logAction(r, fields, "aborted", "PID reuse detected, process identity mismatch")
		return
	}

	if err := syscall.Kill(pid, syscall.SIGKILL); err != nil {
		a.logAction(r, fields, "failed", err.Error())
		return
	}

	a.logAction(r, fields, "executed", "")
}

// executeQuarantine moves a file to the quarantine directory.
func (a *ActionExecutor) executeQuarantine(r *Rule, fields map[string]string, enforce bool) {
	filePath := fields["file_path"]
	if filePath == "" {
		filePath = fields["exe"]
	}
	if filePath == "" {
		a.logAction(r, fields, "failed", "no file_path or exe in event fields")
		return
	}

	// Check protected paths.
	if a.isProtectedPath(filePath) {
		a.logAction(r, fields, "aborted", fmt.Sprintf("protected path: %s", filePath))
		return
	}

	if !enforce {
		a.logAction(r, fields, "skipped", "")
		return
	}

	// Create quarantine directory.
	if err := os.MkdirAll(a.quarantineDir, 0700); err != nil {
		a.logAction(r, fields, "failed", fmt.Sprintf("create quarantine dir: %v", err))
		return
	}

	// Use original filename + timestamp to avoid collisions.
	baseName := filepath.Base(filePath)
	destPath := filepath.Join(a.quarantineDir, fmt.Sprintf("%s.%d", baseName, os.Getpid()))

	// Move file to quarantine.
	if err := os.Rename(filePath, destPath); err != nil {
		a.logAction(r, fields, "failed", fmt.Sprintf("move to quarantine: %v", err))
		return
	}

	// Remove all permissions.
	if err := os.Chmod(destPath, 0); err != nil {
		a.logger.Warn("failed to chmod quarantined file", zap.Error(err))
	}

	a.logAction(r, fields, "executed", "")
}

// verifyProcess checks that the PID still refers to the same process
// by comparing the exe path and process start time from /proc.
// This mitigates TOCTOU race conditions from PID reuse.
func (a *ActionExecutor) verifyProcess(pid int, fields map[string]string) bool {
	// Check 1: exe path.
	exePath, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		// Process already gone — safe to skip action.
		return false
	}

	expectedExe := fields["exe"]
	if expectedExe != "" && exePath != expectedExe && !strings.HasSuffix(exePath, " (deleted)") {
		a.logger.Warn("PID exe mismatch",
			zap.Int("pid", pid),
			zap.String("expected", expectedExe),
			zap.String("actual", exePath),
		)
		return false
	}

	// Check 2: start time (field 22 of /proc/<pid>/stat).
	// BPF events carry start_ts; compare if available.
	if eventStartTime := fields["start_ts"]; eventStartTime != "" {
		procStartTime := readProcStartTime(pid)
		if procStartTime != "" && procStartTime != eventStartTime {
			a.logger.Warn("PID start_time mismatch",
				zap.Int("pid", pid),
				zap.String("event_start_ts", eventStartTime),
				zap.String("proc_start_ts", procStartTime),
			)
			return false
		}
	}

	return true
}

// readProcStartTime reads field 22 (starttime) from /proc/<pid>/stat.
func readProcStartTime(pid int) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return ""
	}

	// Format: pid (comm) state fields...
	// Field 22 is starttime. Find closing paren of comm to avoid parsing issues.
	content := string(data)
	idx := strings.LastIndex(content, ") ")
	if idx < 0 {
		return ""
	}
	rest := content[idx+2:]
	parts := strings.Fields(rest)
	// Field 22 is at index 19 in the remaining fields (fields 3-52, 0-indexed = 22-3=19).
	if len(parts) > 19 {
		return parts[19]
	}
	return ""
}

// isProtectedPath checks if a file path falls within any protected directory.
func (a *ActionExecutor) isProtectedPath(path string) bool {
	cleanPath := filepath.Clean(path)
	for _, protected := range protectedPaths {
		if cleanPath == protected || strings.HasPrefix(cleanPath, protected+"/") {
			return true
		}
	}
	return false
}

// logAction records an action to the audit log.
func (a *ActionExecutor) logAction(r *Rule, fields map[string]string, result, errMsg string) {
	target := fields["pid"]
	if r.Agent.Action == ActionQuarantine {
		target = fields["file_path"]
		if target == "" {
			target = fields["exe"]
		}
	}

	a.audit.Log(AuditEntry{
		RuleID:    r.ID,
		RuleName:  r.Name,
		Severity:  string(r.Severity),
		Action:    string(r.Agent.Action),
		Enforce:   r.Agent.Enforce,
		EventType: r.Agent.Match.EventType,
		Target:    target,
		Result:    result,
		Error:     errMsg,
		Fields:    fields,
	})
}
