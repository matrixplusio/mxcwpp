//go:build linux

package collector

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/matrixplusio/mxcwpp/internal/agent/edr/event"
)

// procEntry holds minimal info about a known process for reconciliation.
type procEntry struct {
	pid     int
	ppid    int
	uid     int
	exe     string
	cmdline string
	cwd     string
}

// procScanner scans /proc for process snapshots and periodic reconciliation.
//
// On startup, it scans all /proc/[pid] entries and emits process_exec events
// with source=proc_snapshot for every running process. This ensures the server
// has a complete picture of processes that started before the agent.
//
// Every reconcileInterval, it rescans /proc and diffs against the known map:
//   - In known but not in /proc → emit synthetic process_exit (source=reconciliation)
//   - In /proc but not in known → emit synthetic process_exec (source=reconciliation)
type procScanner struct {
	logger  *zap.Logger
	eventCh chan<- *event.Event
	known   map[int]procEntry
	mu      sync.Mutex
}

// newProcScanner creates a new /proc scanner.
func newProcScanner(logger *zap.Logger, eventCh chan<- *event.Event) *procScanner {
	return &procScanner{
		logger:  logger,
		eventCh: eventCh,
		known:   make(map[int]procEntry),
	}
}

// initialSnapshot scans all processes in /proc and emits process_exec events.
// Call before starting BPF perf readers to avoid race conditions.
func (s *procScanner) initialSnapshot() error {
	entries, err := s.scanProc()
	if err != nil {
		return err
	}

	s.mu.Lock()
	for pid, entry := range entries {
		s.known[pid] = entry
	}
	s.mu.Unlock()

	emitted := 0
	for _, entry := range entries {
		evt := event.NewProcessExec(entry.pid, entry.ppid, entry.exe, entry.cmdline)
		evt.SetField("uid", fmt.Sprintf("%d", entry.uid))
		evt.SetField("cwd", entry.cwd)
		evt.SetField("source", "proc_snapshot")

		select {
		case s.eventCh <- evt:
			emitted++
		default:
			// Channel full, stop emitting to avoid blocking startup
			s.logger.Warn("event channel full during /proc snapshot, stopping early",
				zap.Int("emitted", emitted),
				zap.Int("total", len(entries)),
			)
			return nil
		}
	}

	s.logger.Info("/proc initial snapshot complete",
		zap.Int("processes", emitted),
	)
	return nil
}

// reconcileLoop periodically scans /proc and emits synthetic events for diffs.
func (s *procScanner) reconcileLoop(ctx context.Context, wg *sync.WaitGroup, interval time.Duration) {
	defer wg.Done()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.reconcile()
		}
	}
}

// reconcile performs a single /proc diff cycle.
func (s *procScanner) reconcile() {
	current, err := s.scanProc()
	if err != nil {
		s.logger.Warn("reconciliation /proc scan failed", zap.Error(err))
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	exitCount := 0
	execCount := 0

	// Detect exits: in known but not in current /proc
	for pid, entry := range s.known {
		if _, exists := current[pid]; !exists {
			delete(s.known, pid)
			evt := event.NewProcessExit(entry.pid, -1) // exit code unknown
			evt.SetField("source", "reconciliation")
			evt.SetField("comm", filepath.Base(entry.exe))
			s.trySend(evt)
			exitCount++
		}
	}

	// Detect new processes: in current /proc but not in known
	for pid, entry := range current {
		if _, exists := s.known[pid]; !exists {
			s.known[pid] = entry
			evt := event.NewProcessExec(entry.pid, entry.ppid, entry.exe, entry.cmdline)
			evt.SetField("uid", fmt.Sprintf("%d", entry.uid))
			evt.SetField("cwd", entry.cwd)
			evt.SetField("source", "reconciliation")
			s.trySend(evt)
			execCount++
		}
	}

	if exitCount > 0 || execCount > 0 {
		s.logger.Debug("reconciliation complete",
			zap.Int("synthetic_exits", exitCount),
			zap.Int("synthetic_execs", execCount),
		)
	}
}

// addKnown records a process from a live BPF event.
func (s *procScanner) addKnown(pid int, entry procEntry) {
	s.mu.Lock()
	s.known[pid] = entry
	s.mu.Unlock()
}

// removeKnown removes a process from the known map (on exit event).
func (s *procScanner) removeKnown(pid int) {
	s.mu.Lock()
	delete(s.known, pid)
	s.mu.Unlock()
}

// trySend attempts a non-blocking send to the event channel.
func (s *procScanner) trySend(evt *event.Event) {
	select {
	case s.eventCh <- evt:
	default:
	}
}

// scanProc reads /proc to enumerate running processes.
// Returns a map of pid → procEntry.
func (s *procScanner) scanProc() (map[int]procEntry, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("read /proc: %w", err)
	}

	result := make(map[int]procEntry, len(entries)/2)

	for _, dirEntry := range entries {
		if !dirEntry.IsDir() {
			continue
		}

		pid, err := strconv.Atoi(dirEntry.Name())
		if err != nil {
			continue // not a PID directory
		}

		entry := procEntry{pid: pid}

		// Read exe (symlink)
		exePath, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
		if err == nil {
			entry.exe = exePath
		}

		// Read cmdline (NUL-separated)
		cmdlineData, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
		if err == nil && len(cmdlineData) > 0 {
			// Replace NUL with space
			for i := range cmdlineData {
				if cmdlineData[i] == 0 {
					cmdlineData[i] = ' '
				}
			}
			entry.cmdline = strings.TrimSpace(string(cmdlineData))
		}

		// Read stat for ppid (field 4)
		statData, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
		if err == nil {
			entry.ppid = parsePPIDFromStat(string(statData))
		}

		// Read status for uid
		statusData, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
		if err == nil {
			entry.uid = parseUIDFromStatus(string(statusData))
		}

		// Read cwd (symlink)
		cwdPath, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid))
		if err == nil {
			entry.cwd = cwdPath
		}

		result[pid] = entry
	}

	return result, nil
}

// parsePPIDFromStat extracts PPID (field 4) from /proc/[pid]/stat.
// Format: "pid (comm) state ppid ..."
// The comm field can contain spaces and parentheses, so we find the last ')'.
func parsePPIDFromStat(stat string) int {
	// Find the last ')' to skip the comm field
	idx := strings.LastIndex(stat, ")")
	if idx < 0 || idx+2 >= len(stat) {
		return 0
	}

	// Fields after ')': " state ppid ..."
	fields := strings.Fields(stat[idx+2:])
	if len(fields) < 2 {
		return 0
	}

	ppid, err := strconv.Atoi(fields[1]) // fields[0]=state, fields[1]=ppid
	if err != nil {
		return 0
	}
	return ppid
}

// parseUIDFromStatus extracts the real UID from /proc/[pid]/status.
// Looks for "Uid:\t<real>\t<effective>\t<saved>\t<fs>"
func parseUIDFromStatus(status string) int {
	for _, line := range strings.Split(status, "\n") {
		if !strings.HasPrefix(line, "Uid:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			uid, err := strconv.Atoi(fields[1]) // real UID
			if err == nil {
				return uid
			}
		}
		break
	}
	return 0
}
