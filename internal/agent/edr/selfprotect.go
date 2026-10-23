//go:build linux

package edr

import (
	"context"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"go.uber.org/zap"
)

// SelfProtect implements agent self-protection mechanisms:
//   - systemd sd_notify integration (READY + WATCHDOG heartbeat)
//   - chattr +i file immutability for critical files and directories
type SelfProtect struct {
	logger     *zap.Logger
	notifyConn net.Conn
}

// NewSelfProtect creates a new self-protection manager.
func NewSelfProtect(logger *zap.Logger) *SelfProtect {
	return &SelfProtect{
		logger: logger,
	}
}

// Start initializes self-protection: sd_notify READY + watchdog loop + chattr.
func (sp *SelfProtect) Start(ctx context.Context, wg *sync.WaitGroup) {
	// 1. sd_notify READY=1
	sp.sdNotify("READY=1")

	// 2. Apply file immutability to critical paths (directories + files within).
	sp.applyImmutable()

	// 3. Start watchdog heartbeat goroutine.
	wg.Add(1)
	go sp.watchdogLoop(ctx, wg)
}

// Stop cleans up self-protection resources.
func (sp *SelfProtect) Stop() {
	sp.sdNotify("STOPPING=1")
	if sp.notifyConn != nil {
		_ = sp.notifyConn.Close()
	}
}

// TemporaryUnlock temporarily removes the immutable flag for file operations
// (e.g., rule updates, agent upgrades). If path is a directory, all files
// within are also unlocked recursively. Caller must call the returned
// function to re-apply immutability.
func (sp *SelfProtect) TemporaryUnlock(path string) func() {
	sp.removeImmutableRecursive(path)
	return func() {
		sp.setImmutableRecursive(path)
	}
}

// sdNotify sends a notification to systemd via the NOTIFY_SOCKET.
// No-op if not running under systemd (NOTIFY_SOCKET not set).
func (sp *SelfProtect) sdNotify(state string) {
	socketPath := os.Getenv("NOTIFY_SOCKET")
	if socketPath == "" {
		return
	}

	conn, err := net.Dial("unixgram", socketPath)
	if err != nil {
		sp.logger.Debug("sd_notify dial failed (not running under systemd)",
			zap.Error(err),
		)
		return
	}

	_, err = conn.Write([]byte(state))
	if err != nil {
		sp.logger.Warn("sd_notify write failed",
			zap.String("state", state),
			zap.Error(err),
		)
	}

	// Keep connection for WATCHDOG=1 heartbeats; reuse avoids opening
	// a new socket every tick.
	if state == "READY=1" {
		sp.notifyConn = conn
	} else {
		_ = conn.Close()
	}
}

// watchdogInterval returns the interval for sending WATCHDOG=1 heartbeats.
// Reads WATCHDOG_USEC set by systemd and uses half that value, per the
// sd_watchdog_enabled(3) recommendation. Falls back to 30s if unset.
func watchdogInterval() time.Duration {
	usecStr := os.Getenv("WATCHDOG_USEC")
	if usec, err := strconv.ParseInt(usecStr, 10, 64); err == nil && usec > 0 {
		return time.Duration(usec) * time.Microsecond / 2
	}
	return 30 * time.Second
}

// watchdogLoop sends WATCHDOG=1 to systemd at half the configured interval.
// systemd restarts the agent if it stops receiving heartbeats.
func (sp *SelfProtect) watchdogLoop(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()

	if sp.notifyConn == nil {
		sp.logger.Debug("no notify connection, watchdog loop skipped")
		return
	}

	interval := watchdogInterval()
	sp.logger.Info("watchdog heartbeat started", zap.Duration("interval", interval))

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if _, err := sp.notifyConn.Write([]byte("WATCHDOG=1")); err != nil {
				sp.logger.Warn("watchdog heartbeat failed", zap.Error(err))
			}
		}
	}
}

// protectedDirs are directories that get chattr +i protection.
var protectedDirs = []string{
	"/var/lib/mxcwpp/rules",
	"/usr/local/mxcwpp",
}

// applyImmutable sets the immutable attribute on protected directories
// and all files within them recursively.
func (sp *SelfProtect) applyImmutable() {
	for _, dir := range protectedDirs {
		sp.setImmutableRecursive(dir)
	}
}

// setImmutableRecursive applies chattr +i to a path. If the path is a
// directory, all entries within are protected first, then the directory
// itself (so the walk completes before the directory entry is locked).
func (sp *SelfProtect) setImmutableRecursive(path string) {
	info, err := os.Stat(path)
	if err != nil {
		return // Path doesn't exist yet, skip.
	}

	if info.IsDir() {
		_ = filepath.WalkDir(path, func(p string, _ fs.DirEntry, walkErr error) error {
			if walkErr != nil || p == path {
				return nil // handle root dir after the walk
			}
			sp.setImmutable(p)
			return nil
		})
	}

	sp.setImmutable(path)
}

// removeImmutableRecursive removes chattr +i from a path. If the path is a
// directory, the directory is unlocked first, then all entries within.
func (sp *SelfProtect) removeImmutableRecursive(path string) {
	// Remove directory +i first so the walk can proceed.
	sp.removeImmutable(path)

	info, err := os.Stat(path)
	if err != nil {
		return
	}

	if info.IsDir() {
		_ = filepath.WalkDir(path, func(p string, _ fs.DirEntry, walkErr error) error {
			if walkErr != nil || p == path {
				return nil
			}
			sp.removeImmutable(p)
			return nil
		})
	}
}

// setImmutable applies chattr +i to a single path.
func (sp *SelfProtect) setImmutable(path string) {
	if _, err := os.Stat(path); err != nil {
		return
	}

	cmd := exec.Command("chattr", "+i", path)
	if output, err := cmd.CombinedOutput(); err != nil {
		sp.logger.Debug("chattr +i failed (may lack capability)",
			zap.String("path", path),
			zap.String("output", string(output)),
			zap.Error(err),
		)
	} else {
		sp.logger.Info("file protection applied",
			zap.String("path", path),
		)
	}
}

// removeImmutable removes chattr +i from a single path.
func (sp *SelfProtect) removeImmutable(path string) {
	if _, err := os.Stat(path); err != nil {
		return
	}

	cmd := exec.Command("chattr", "-i", path)
	if output, err := cmd.CombinedOutput(); err != nil {
		sp.logger.Warn("chattr -i failed",
			zap.String("path", path),
			zap.String("output", string(output)),
			zap.Error(err),
		)
	}
}

// GenerateSystemdUnit returns a recommended systemd unit file content
// for the MxCwpp Agent with self-protection features.
func GenerateSystemdUnit() string {
	return `[Unit]
Description=MxCwpp Security Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
ExecStart=/usr/local/mxcwpp/mxcwpp-agent
Restart=on-failure
RestartSec=3s
StartLimitBurst=5
StartLimitIntervalSec=3600
WatchdogSec=60
NotifyAccess=main
LimitNOFILE=65536
LimitMEMLOCK=infinity

[Install]
WantedBy=multi-user.target
`
}
