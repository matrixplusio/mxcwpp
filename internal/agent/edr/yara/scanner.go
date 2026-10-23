//go:build linux

// Package yara provides an async YARA-X scanner for the EDR engine.
// It wraps the `yr` CLI binary (same approach as the scanner plugin)
// and triggers on-demand scans for suspicious executables.
package yara

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"go.uber.org/zap"

	"github.com/matrixplusio/mxcwpp/internal/agent/edr/event"
)

const (
	defaultRulesDir = "/var/lib/mxcwpp/yara-rules"
	yaraBinary      = "yr"

	// Scan dedup: skip files scanned within this window.
	dedupWindow = 5 * time.Minute

	// Per-scan timeout.
	scanTimeout = 30 * time.Second

	// Max pending scan queue depth.
	scanQueueSize = 128
)

// suspiciousDirs are directories where executables are considered suspicious
// and warrant YARA scanning on process_exec.
var suspiciousDirs = []string{
	"/tmp/",
	"/var/tmp/",
	"/dev/shm/",
	"/run/user/",
	"/home/",
}

// Result holds a single YARA match result.
type Result struct {
	FilePath   string
	RuleName   string
	ThreatType string
	Severity   string
	Tags       []string
}

// preBlockWhitelist contains exe basenames that must never be SIGSTOP'd.
var preBlockWhitelist = map[string]bool{
	"systemd":      true,
	"init":         true,
	"sshd":         true,
	"mxcwpp-agent": true,
	"mxcsec-agent": true,
	"dockerd":      true,
	"containerd":   true,
	"kubelet":      true,
	"journald":     true,
	"dbus-daemon":  true,
	"agetty":       true,
}

// Scanner wraps the YARA-X CLI for async file scanning.
type Scanner struct {
	logger   *zap.Logger
	rulesDir string
	binPath  string

	// Pre-block mode: SIGSTOP process before scan, SIGCONT/SIGKILL after.
	preBlock bool

	// Dedup: track recently scanned files.
	mu      sync.Mutex
	scanned map[string]time.Time

	// Async scan queue.
	scanCh  chan scanRequest
	eventCh chan<- *event.Event

	// Counters.
	scansTotal   uint64
	scansMatched uint64
	preBlocked   uint64
}

type scanRequest struct {
	filePath string
	pid      int               // PID to SIGSTOP/SIGCONT (0 = async mode)
	fields   map[string]string // original event fields for annotation
}

// yaraOutput matches YARA-X v1.15+ JSON output.
type yaraOutput struct {
	Version string          `json:"version"`
	Matches []yaraMatchItem `json:"matches"`
}

type yaraMatchItem struct {
	Rule      string            `json:"rule"`
	File      string            `json:"file"`
	Namespace string            `json:"namespace,omitempty"`
	Tags      []string          `json:"tags,omitempty"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

// NewScanner creates a YARA scanner. Returns nil if yr binary or rules dir unavailable.
func NewScanner(logger *zap.Logger, eventCh chan<- *event.Event) *Scanner {
	rulesDir := defaultRulesDir
	if envDir := os.Getenv("YARA_RULES_DIR"); envDir != "" {
		rulesDir = envDir
	}

	// Check rules directory exists.
	if info, err := os.Stat(rulesDir); err != nil || !info.IsDir() {
		logger.Info("YARA rules directory not found, YARA scanner disabled",
			zap.String("rules_dir", rulesDir))
		return nil
	}

	binPath := findBinary()
	if binPath == "" {
		logger.Info("yr (YARA-X) binary not found, YARA scanner disabled")
		return nil
	}

	// Verify binary is executable.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(ctx, binPath, "--version").CombinedOutput(); err != nil {
		logger.Warn("yr binary found but not executable",
			zap.String("path", binPath),
			zap.String("output", string(out)),
			zap.Error(err))
		return nil
	}

	return &Scanner{
		logger:   logger,
		rulesDir: rulesDir,
		binPath:  binPath,
		scanned:  make(map[string]time.Time),
		scanCh:   make(chan scanRequest, scanQueueSize),
		eventCh:  eventCh,
	}
}

// Start launches the async scan worker goroutine.
func (s *Scanner) Start(ctx context.Context, wg *sync.WaitGroup) {
	wg.Add(1)
	go s.scanLoop(ctx, wg)

	// Dedup cleanup goroutine.
	wg.Add(1)
	go s.cleanupLoop(ctx, wg)

	s.logger.Info("YARA scanner started",
		zap.String("rules_dir", s.rulesDir),
		zap.String("binary", s.binPath))
}

// ShouldScan checks if a process_exec event warrants YARA scanning.
// Criteria: exe path is in a suspicious directory.
func (s *Scanner) ShouldScan(evt *event.Event) bool {
	if evt.EventType != event.ProcessExec {
		return false
	}

	exe := evt.Fields["exe"]
	if exe == "" {
		return false
	}

	for _, dir := range suspiciousDirs {
		if strings.HasPrefix(exe, dir) {
			return true
		}
	}

	return false
}

// EnablePreBlock enables pre-block mode (SIGSTOP before scan).
func (s *Scanner) EnablePreBlock(enabled bool) {
	s.preBlock = enabled
	s.logger.Info("YARA pre-block mode", zap.Bool("enabled", enabled))
}

// PreBlockEnabled returns whether pre-block mode is active.
func (s *Scanner) PreBlockEnabled() bool {
	return s.preBlock
}

// Enqueue submits a file for async YARA scanning. Non-blocking; drops if queue full.
func (s *Scanner) Enqueue(filePath string, fields map[string]string) {
	s.enqueue(filePath, 0, fields)
}

// EnqueuePreBlock submits a file for YARA scanning with pre-block (SIGSTOP).
// The process PID is stopped before scanning and resumed/killed after.
// Falls back to async mode for whitelisted or critical processes.
func (s *Scanner) EnqueuePreBlock(filePath string, pid int, fields map[string]string) {
	if !s.preBlock || pid <= 1 || s.isWhitelisted(filePath) {
		s.enqueue(filePath, 0, fields)
		return
	}

	// SIGSTOP the process immediately.
	if err := syscall.Kill(pid, syscall.SIGSTOP); err != nil {
		s.logger.Debug("pre-block SIGSTOP failed, falling back to async",
			zap.Int("pid", pid), zap.Error(err))
		s.enqueue(filePath, 0, fields)
		return
	}

	s.preBlocked++
	s.logger.Debug("pre-block: process stopped",
		zap.Int("pid", pid), zap.String("exe", filePath))

	s.enqueue(filePath, pid, fields)
}

func (s *Scanner) enqueue(filePath string, pid int, fields map[string]string) {
	// Dedup check.
	s.mu.Lock()
	if t, ok := s.scanned[filePath]; ok && time.Since(t) < dedupWindow {
		s.mu.Unlock()
		// If pre-blocked, must resume — dedup means no scan needed.
		if pid > 0 {
			_ = syscall.Kill(pid, syscall.SIGCONT)
		}
		return
	}
	s.scanned[filePath] = time.Now()
	s.mu.Unlock()

	// Check file still exists (process may have already exited).
	if _, err := os.Stat(filePath); err != nil {
		if pid > 0 {
			_ = syscall.Kill(pid, syscall.SIGCONT)
		}
		return
	}

	select {
	case s.scanCh <- scanRequest{filePath: filePath, pid: pid, fields: fields}:
	default:
		s.logger.Warn("YARA scan queue full, dropping request",
			zap.String("file", filePath))
		// Must resume if pre-blocked.
		if pid > 0 {
			_ = syscall.Kill(pid, syscall.SIGCONT)
		}
	}
}

// isWhitelisted returns true if the exe should never be SIGSTOP'd.
func (s *Scanner) isWhitelisted(exe string) bool {
	base := filepath.Base(exe)
	return preBlockWhitelist[base]
}

// PreBlockStats returns the number of processes that were pre-blocked.
func (s *Scanner) PreBlockStats() uint64 {
	return s.preBlocked
}

// Stats returns scan counters.
func (s *Scanner) Stats() (total, matched uint64) {
	return s.scansTotal, s.scansMatched
}

// scanLoop processes scan requests from the queue.
func (s *Scanner) scanLoop(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()

	for {
		select {
		case <-ctx.Done():
			// On shutdown, resume any pre-blocked processes still in queue.
			s.drainAndResume()
			return
		case req, ok := <-s.scanCh:
			if !ok {
				return
			}
			s.scansTotal++
			results, err := s.scan(ctx, req.filePath)
			if err != nil {
				s.logger.Warn("YARA scan failed",
					zap.String("file", req.filePath),
					zap.Error(err))
				// Fail-open: resume pre-blocked process on scan error.
				if req.pid > 0 {
					_ = syscall.Kill(req.pid, syscall.SIGCONT)
					s.logger.Warn("pre-block: resumed after scan error",
						zap.Int("pid", req.pid))
				}
				continue
			}

			if len(results) > 0 {
				s.scansMatched++
				s.emitDetection(req, results)

				// Pre-block mode: kill the malicious process.
				if req.pid > 0 {
					_ = syscall.Kill(req.pid, syscall.SIGKILL)
					s.logger.Warn("pre-block: killed malicious process",
						zap.Int("pid", req.pid),
						zap.String("rule", results[0].RuleName))
				}
			} else {
				// No match — resume pre-blocked process.
				if req.pid > 0 {
					_ = syscall.Kill(req.pid, syscall.SIGCONT)
					s.logger.Debug("pre-block: resumed clean process",
						zap.Int("pid", req.pid))
				}
			}
		}
	}
}

// drainAndResume resumes all pre-blocked processes remaining in the queue on shutdown.
func (s *Scanner) drainAndResume() {
	for {
		select {
		case req := <-s.scanCh:
			if req.pid > 0 {
				_ = syscall.Kill(req.pid, syscall.SIGCONT)
			}
		default:
			return
		}
	}
}

// scan runs yr scan against a single file and returns matches.
func (s *Scanner) scan(ctx context.Context, filePath string) ([]Result, error) {
	scanCtx, cancel := context.WithTimeout(ctx, scanTimeout)
	defer cancel()

	args := []string{
		"scan",
		"--output-format=json",
		s.rulesDir,
		filePath,
	}

	cmd := exec.CommandContext(scanCtx, s.binPath, args...)
	output, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			if len(output) > 0 {
				// Has output — likely matches with non-zero exit.
				return s.parseOutput(output)
			}
			return nil, fmt.Errorf("yr exit %d: %s", exitErr.ExitCode(), string(exitErr.Stderr))
		}
		return nil, fmt.Errorf("yr exec: %w", err)
	}

	return s.parseOutput(output)
}

// parseOutput parses YARA-X JSON output.
func (s *Scanner) parseOutput(output []byte) ([]Result, error) {
	if len(output) == 0 {
		return nil, nil
	}

	var out yaraOutput
	if err := json.Unmarshal(output, &out); err != nil {
		return nil, fmt.Errorf("parse YARA JSON: %w", err)
	}

	results := make([]Result, 0, len(out.Matches))
	for _, m := range out.Matches {
		results = append(results, Result{
			FilePath:   m.File,
			RuleName:   m.Rule,
			ThreatType: extractThreatType(m.Tags, m.Metadata),
			Severity:   extractSeverity(m.Metadata),
			Tags:       m.Tags,
		})
	}

	return results, nil
}

// emitDetection creates a new EDR event for a YARA match.
func (s *Scanner) emitDetection(req scanRequest, results []Result) {
	// Use the highest-severity match.
	best := results[0]
	for _, r := range results[1:] {
		if sevRank(r.Severity) > sevRank(best.Severity) {
			best = r
		}
	}

	evt := &event.Event{
		DataType:  event.DataTypeProcess,
		EventType: event.ProcessExec,
		Timestamp: time.Now(),
		Fields:    make(map[string]string, len(req.fields)+8),
	}

	// Copy original event fields.
	for k, v := range req.fields {
		evt.Fields[k] = v
	}

	// Annotate with YARA match info.
	evt.SetField("yara_match", "true")
	evt.SetField("yara_rule", best.RuleName)
	evt.SetField("yara_threat_type", best.ThreatType)
	evt.SetField("yara_severity", best.Severity)
	evt.SetField("threat_name", best.RuleName)

	if len(results) > 1 {
		names := make([]string, len(results))
		for i, r := range results {
			names[i] = r.RuleName
		}
		evt.SetField("yara_rules", strings.Join(names, ","))
	}

	s.logger.Warn("YARA match detected",
		zap.String("file", req.filePath),
		zap.String("rule", best.RuleName),
		zap.String("threat_type", best.ThreatType),
		zap.String("severity", best.Severity),
	)

	select {
	case s.eventCh <- evt:
	default:
		s.logger.Warn("event channel full, dropping YARA detection event")
	}
}

// cleanupLoop periodically removes stale dedup entries.
func (s *Scanner) cleanupLoop(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()

	ticker := time.NewTicker(dedupWindow)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.mu.Lock()
			now := time.Now()
			for k, t := range s.scanned {
				if now.Sub(t) > dedupWindow {
					delete(s.scanned, k)
				}
			}
			s.mu.Unlock()
		}
	}
}

// findBinary locates the yr binary.
func findBinary() string {
	// 1. Agent binary directory.
	if exe, err := os.Executable(); err == nil {
		local := filepath.Join(filepath.Dir(exe), "yr")
		if _, err := os.Stat(local); err == nil {
			return local
		}
	}
	// 2. /var/lib/mxcwpp/bin/yr
	if _, err := os.Stat("/var/lib/mxcwpp/bin/yr"); err == nil {
		return "/var/lib/mxcwpp/bin/yr"
	}
	// 3. System PATH.
	if p, err := exec.LookPath(yaraBinary); err == nil {
		return p
	}
	return ""
}

// extractThreatType determines threat type from rule tags/metadata.
func extractThreatType(tags []string, metadata map[string]string) string {
	for _, tag := range tags {
		lower := strings.ToLower(tag)
		switch lower {
		case "ransomware", "rootkit", "backdoor", "trojan", "worm", "virus":
			return lower
		case "miner", "coinminer":
			return "miner"
		}
	}
	if v, ok := metadata["threat_type"]; ok {
		return v
	}
	return "malware"
}

// extractSeverity determines severity from rule metadata.
func extractSeverity(metadata map[string]string) string {
	if v, ok := metadata["severity"]; ok {
		return v
	}
	return "high"
}

// sevRank returns numeric rank for severity comparison.
func sevRank(s string) int {
	switch s {
	case "info":
		return 0
	case "low":
		return 1
	case "medium":
		return 2
	case "high":
		return 3
	case "critical":
		return 4
	default:
		return 2
	}
}
