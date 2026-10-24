//go:build linux

package edr

import (
	"context"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

// SelfProtect implements agent self-protection mechanisms:
//   - systemd sd_notify integration (READY + WATCHDOG heartbeat)
//   - immutable attribute (as chattr +i) on critical files and directories
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

// setImmutableRecursive protects a path. Directory entries are locked
// before the directory itself so the walk completes first.
func (sp *SelfProtect) setImmutableRecursive(path string) {
	sp.applyTree(path, true)
}

// removeImmutableRecursive unprotects a path. The directory is unlocked
// first so the walk can proceed.
func (sp *SelfProtect) removeImmutableRecursive(path string) {
	sp.applyTree(path, false)
}

// applyTree sets or clears the immutable attribute on path and everything
// beneath it, then logs one summary per root. Failures are counted and
// surfaced at Warn: a lock that silently fails (no CAP_LINUX_IMMUTABLE,
// unsupported filesystem) leaves the agent unprotected with nothing in the log.
func (sp *SelfProtect) applyTree(path string, on bool) {
	info, err := os.Stat(path)
	if err != nil {
		if !os.IsNotExist(err) {
			sp.logger.Warn("protected path not accessible", zap.String("path", path), zap.Error(err))
		}
		return
	}

	var applied, failed int
	var firstErr error
	var firstPath string
	record := func(p string, err error) {
		if err == nil {
			applied++
			return
		}
		if failed == 0 {
			firstPath, firstErr = p, err
		}
		failed++
	}

	if !on {
		record(path, setImmutableFlag(path, false))
	}
	if info.IsDir() {
		_ = filepath.WalkDir(path, func(p string, _ fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				record(p, walkErr)
				return nil
			}
			if p != path {
				record(p, setImmutableFlag(p, on))
			}
			return nil
		})
	}
	if on {
		record(path, setImmutableFlag(path, true))
	}

	action := "file protection applied"
	if !on {
		action = "file protection removed"
	}
	if failed > 0 {
		sp.logger.Warn(action+" with failures",
			zap.String("path", path),
			zap.Int("applied", applied),
			zap.Int("failed", failed),
			zap.String("first_failed_path", firstPath),
			zap.Error(firstErr),
		)
		return
	}
	sp.logger.Info(action, zap.String("path", path), zap.Int("entries", applied))
}

// fsImmutableFL is FS_IMMUTABLE_FL from linux/fs.h (not exported by x/sys).
const fsImmutableFL = 0x00000010

// setImmutableFlag toggles the immutable attribute via ioctl instead of
// spawning chattr: a chattr child per file trips our own "chattr +i" rule and
// resolves chattr through PATH. O_NOFOLLOW + the type check keep a symlink or
// device planted in a protected dir from redirecting the lock elsewhere.
// Intermediate path components are still resolved normally; tampering with
// them requires root over the protected dirs already.
func setImmutableFlag(path string, on bool) error {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)

	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	mode := st.Mode & unix.S_IFMT
	if mode != unix.S_IFREG && mode != unix.S_IFDIR {
		return unix.EINVAL
	}
	// A hard link planted in a protected dir would lock (or unlock) the
	// original inode elsewhere, e.g. /etc/shadow.
	if mode == unix.S_IFREG && st.Nlink > 1 {
		return unix.EMLINK
	}

	flags, err := unix.IoctlGetUint32(fd, unix.FS_IOC_GETFLAGS)
	if err != nil {
		return err
	}
	next := flags &^ fsImmutableFL
	if on {
		next = flags | fsImmutableFL
	}
	if next == flags {
		return nil
	}
	return unix.IoctlSetPointerInt(fd, unix.FS_IOC_SETFLAGS, int(int32(next)))
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
