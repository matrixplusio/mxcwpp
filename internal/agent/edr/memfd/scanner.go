//go:build linux

// Package memfd detects fileless attack techniques by scanning /proc for:
//   - memfd_create: processes with memfd-backed file descriptors
//   - deleted executables: processes running from deleted ELF files
//   - anonymous executable memory: suspicious rwx memory mappings
package memfd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"

	"github.com/matrixplusio/mxcwpp/internal/agent/edr/event"
)

const (
	// scanInterval controls how often the /proc scan runs.
	scanInterval = 30 * time.Second

	// dedupWindow prevents duplicate alerts for the same exe + threat type.
	// 2026-06-04 调整 10min → 24h:prod 实测同 exe 长跑进程每 10min 重发一次,7d 累积 34w 个 alert,
	// 几乎全是误报(systemd/sshd/node_exporter 等系统进程升级后的 deleted_exe)。
	// dedup key 也从 (pid, threat_type) → (exe, threat_type),避免进程重启又触发。
	dedupWindow = 24 * time.Hour

	// deletedExeGracePeriod:exe 被删后等多久才报。OS 包升级会 unlink 旧 binary 但旧进程仍在跑,
	// 给一段窗口让管理员重启相关服务(如 systemctl restart sshd)。
	deletedExeGracePeriod = 30 * time.Minute
)

// whitelistedExes 白名单:这些进程合法使用 memfd / 经常出现 deleted_exe(包升级)。
// 2026-06-04 扩充:加入 prod 实测 top 误报源(dbus-broker-launch / sshd / node_exporter /
// systemd 系列 / NetworkManager / cron / chronyd)。系统服务进程升级是常态,告警价值低。
var whitelistedExes = map[string]bool{
	// 容器/沙箱 runtime — 用 memfd 传 seccomp / OCI spec
	"runc":            true,
	"crun":            true,
	"containerd":      true,
	"dockerd":         true,
	"docker-init":     true,
	"containerd-shim": true,

	// 桌面 / 音频 / 显示 — 用 memfd 共享缓冲
	"pulseaudio": true,
	"pipewire":   true,
	"Xwayland":   true,

	// 内核自测
	"memfd_test": true,

	// dbus 系列 — 现代 dbus-broker 用 memfd 跨进程通信
	"dbus-broker":        true,
	"dbus-broker-launch": true,
	"dbus-daemon":        true,

	// systemd 系列 — yum/dnf/apt 升级 systemd 后旧实例继续跑,常报 deleted_exe
	"systemd":           true,
	"systemd-logind":    true,
	"systemd-resolved":  true,
	"systemd-networkd":  true,
	"systemd-udevd":     true,
	"systemd-journald":  true,
	"systemd-machined":  true,
	"systemd-timesyncd": true,
	"systemd-hostnamed": true,

	// 网络 / 时间 — 同样升级常态
	"NetworkManager": true,
	"chronyd":        true,
	"ntpd":           true,
	"sshd":           true,
	"cron":           true,
	"crond":          true,
	"rsyslogd":       true,

	// 监控 agent — node_exporter 升级后 deleted_exe
	"node_exporter":         true,
	"prometheus":            true,
	"google-osconfig-agent": true,
	"google_guest_agent":    true,
	"google_compat_agent":   true,
}

// systemBinDirs:可信系统目录。deleted_exe 落在这些目录大概率是包升级,confidence 低。
// 非这些目录的 deleted_exe(如 /tmp/foo / /dev/shm/x)更可疑。
var systemBinDirs = []string{
	"/usr/bin/",
	"/usr/sbin/",
	"/usr/lib/",
	"/usr/libexec/",
	"/usr/local/bin/",
	"/usr/local/sbin/",
	"/bin/",
	"/sbin/",
	"/lib/",
	"/lib64/",
	"/opt/",
}

// dedupKey 以 exe + threat_type 为粒度:同 binary 即便重启 pid 变化仍 dedup,
// 与 prod 长跑系统进程的反复触发抗衡。
type dedupKey struct {
	exe        string
	threatType string
}

// Scanner detects fileless threats by scanning /proc.
type Scanner struct {
	logger  *zap.Logger
	eventCh chan<- *event.Event

	mu             sync.Mutex
	seen           map[dedupKey]time.Time // dedup (exe, threat_type) -> last_seen
	deletedExeSeen map[int]time.Time      // pid -> first_seen for grace period

	// Counters.
	scansTotal   atomic.Uint64
	threatsFound atomic.Uint64
}

// NewScanner creates a memory threat scanner.
func NewScanner(logger *zap.Logger, eventCh chan<- *event.Event) *Scanner {
	return &Scanner{
		logger:         logger,
		eventCh:        eventCh,
		seen:           make(map[dedupKey]time.Time),
		deletedExeSeen: make(map[int]time.Time),
	}
}

// Start launches the periodic scan goroutine.
func (s *Scanner) Start(ctx context.Context, wg *sync.WaitGroup) {
	wg.Add(2)
	go s.scanLoop(ctx, wg)
	go s.cleanupLoop(ctx, wg)
	s.logger.Info("memory threat scanner started", zap.Duration("interval", scanInterval))
}

// Stats returns scan counters.
func (s *Scanner) Stats() (scans, threats uint64) {
	return s.scansTotal.Load(), s.threatsFound.Load()
}

func (s *Scanner) scanLoop(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()

	// Initial scan after short delay to let process table stabilize.
	select {
	case <-ctx.Done():
		return
	case <-time.After(5 * time.Second):
	}
	s.scan()

	ticker := time.NewTicker(scanInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.scan()
		}
	}
}

func (s *Scanner) cleanupLoop(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()

	// 每小时跑一次 cleanup,过滤 24h 内的 entry。
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.mu.Lock()
			now := time.Now()
			for k, t := range s.seen {
				if now.Sub(t) > dedupWindow {
					delete(s.seen, k)
				}
			}
			// deletedExeSeen 同样按 dedupWindow 清
			for pid, t := range s.deletedExeSeen {
				if now.Sub(t) > dedupWindow {
					delete(s.deletedExeSeen, pid)
				}
			}
			s.mu.Unlock()
		}
	}
}

// scan performs a single pass over /proc.
func (s *Scanner) scan() {
	s.scansTotal.Add(1)

	entries, err := os.ReadDir("/proc")
	if err != nil {
		s.logger.Warn("failed to read /proc", zap.Error(err))
		return
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 2 {
			continue // skip non-PID dirs and kernel threads
		}

		s.checkProcess(pid)
	}
}

// checkProcess inspects a single process for memory threats.
func (s *Scanner) checkProcess(pid int) {
	procDir := fmt.Sprintf("/proc/%d", pid)

	// Read exe link first — needed for whitelisting and event fields.
	exeLink, err := os.Readlink(procDir + "/exe")
	if err != nil {
		return // process likely exited
	}

	// Skip self.
	if isSelf(pid) {
		return
	}

	baseName := filepath.Base(strings.TrimSuffix(exeLink, " (deleted)"))
	if whitelistedExes[baseName] {
		return
	}

	// Check 1: deleted executable(加 grace period + 系统目录降级)
	if strings.HasSuffix(exeLink, " (deleted)") {
		s.handleDeletedExe(pid, exeLink, baseName, procDir)
	}

	// Check 2: memfd-backed file descriptors.
	s.checkMemfd(pid, baseName, procDir)

	// Check 3: anonymous executable memory regions (suspicious rwx).
	s.checkAnonExec(pid, baseName, procDir)
}

// handleDeletedExe 处理 deleted_exe 告警:加 grace period(30min) + 系统目录 demotion。
func (s *Scanner) handleDeletedExe(pid int, exeLink, baseName, procDir string) {
	// 1. Grace period:首次看到 exe 删除时不立即告警,等 30min 给 OS 升级/手动 restart 窗口。
	s.mu.Lock()
	if firstSeen, ok := s.deletedExeSeen[pid]; ok {
		if time.Since(firstSeen) < deletedExeGracePeriod {
			s.mu.Unlock()
			return
		}
	} else {
		s.deletedExeSeen[pid] = time.Now()
		s.mu.Unlock()
		return // 首次见 — 记录但不告警
	}
	s.mu.Unlock()

	// 2. 系统目录降级:/usr/bin /usr/sbin 等路径下的 deleted_exe 大概率是包升级,confidence 极低,
	// 直接不告警(只有非系统目录的 deleted_exe 才告警)。
	// strip " (deleted)" 后比对路径前缀。
	cleanPath := strings.TrimSuffix(exeLink, " (deleted)")
	for _, dir := range systemBinDirs {
		if strings.HasPrefix(cleanPath, dir) {
			return // 系统包升级,不告警
		}
	}

	s.emitIfNew(pid, "deleted_exe", exeLink, baseName, procDir)
}

// checkMemfd scans /proc/[pid]/fd for memfd: links.
func (s *Scanner) checkMemfd(pid int, baseName, procDir string) {
	fdDir := procDir + "/fd"
	fds, err := os.ReadDir(fdDir)
	if err != nil {
		return
	}

	for _, fd := range fds {
		target, err := os.Readlink(fdDir + "/" + fd.Name())
		if err != nil {
			continue
		}
		if strings.HasPrefix(target, "/memfd:") {
			s.emitIfNew(pid, "memfd_exec", target, baseName, procDir)
			return // one memfd detection per PID is enough
		}
	}
}

// checkAnonExec looks for suspicious anonymous executable memory mappings.
func (s *Scanner) checkAnonExec(pid int, baseName, procDir string) {
	mapsPath := procDir + "/maps"
	data, err := os.ReadFile(mapsPath)
	if err != nil {
		return
	}

	// Count anonymous rwx regions. Normal processes have 0-1.
	// Malware with injected shellcode typically has multiple.
	var anonRWXCount int
	for line := range strings.SplitSeq(string(data), "\n") {
		if len(line) < 50 {
			continue
		}
		// Format: address perms offset dev inode pathname
		// Example: 7f1234000000-7f1234001000 rwxp 00000000 00:00 0
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		perms := fields[1]
		if len(perms) < 4 || perms[0] != 'r' || perms[1] != 'w' || perms[2] != 'x' {
			continue
		}
		// Anonymous = no pathname or [heap]/[stack] (inode == 0 and no path)
		inode := fields[4]
		hasPath := len(fields) >= 6 && fields[5] != ""
		if inode == "0" && !hasPath {
			anonRWXCount++
		}
	}

	// 3+ anonymous rwx regions is suspicious (JIT engines like Node/JVM have some).
	if anonRWXCount >= 3 {
		s.emitIfNew(pid, "anonymous_exec", fmt.Sprintf("anon_rwx_count=%d", anonRWXCount), baseName, procDir)
	}
}

// emitIfNew emits a memory threat event if not seen recently (dedup by exe, not pid).
func (s *Scanner) emitIfNew(pid int, threatType, detail, exeName, procDir string) {
	key := dedupKey{exe: exeName, threatType: threatType}
	s.mu.Lock()
	if t, ok := s.seen[key]; ok && time.Since(t) < dedupWindow {
		s.mu.Unlock()
		return
	}
	s.seen[key] = time.Now()
	s.mu.Unlock()

	s.threatsFound.Add(1)

	// Read additional process info.
	ppid, uid, cmdline := readProcStatus(procDir)

	evt := &event.Event{
		DataType:  event.DataTypeMemory,
		EventType: event.EventType(threatType),
		Timestamp: time.Now(),
		Fields: map[string]string{
			"event_type":  threatType,
			"pid":         strconv.Itoa(pid),
			"ppid":        ppid,
			"uid":         uid,
			"exe":         exeName,
			"cmdline":     cmdline,
			"threat_type": threatType,
			"detail":      detail,
		},
	}

	s.logger.Warn("memory threat detected",
		zap.String("threat_type", threatType),
		zap.Int("pid", pid),
		zap.String("exe", exeName),
		zap.String("detail", detail),
	)

	select {
	case s.eventCh <- evt:
	default:
		s.logger.Warn("event channel full, dropping memory threat event")
	}
}

// readProcStatus reads ppid, uid, and cmdline from /proc/[pid]/.
func readProcStatus(procDir string) (ppid, uid, cmdline string) {
	// Read status for ppid and uid.
	data, err := os.ReadFile(procDir + "/status")
	if err == nil {
		for line := range strings.SplitSeq(string(data), "\n") {
			if val, ok := strings.CutPrefix(line, "PPid:\t"); ok {
				ppid = val
			} else if val, ok := strings.CutPrefix(line, "Uid:\t"); ok {
				parts := strings.Fields(val)
				if len(parts) > 0 {
					uid = parts[0] // real UID
				}
			}
		}
	}

	// Read cmdline.
	cmdData, err := os.ReadFile(procDir + "/cmdline")
	if err == nil && len(cmdData) > 0 {
		// cmdline is null-separated.
		cmdline = strings.ReplaceAll(string(cmdData), "\x00", " ")
		cmdline = strings.TrimSpace(cmdline)
		if len(cmdline) > 512 {
			cmdline = cmdline[:512]
		}
	}

	return
}

// isSelf checks if the PID belongs to this process.
func isSelf(pid int) bool {
	return pid == os.Getpid()
}
