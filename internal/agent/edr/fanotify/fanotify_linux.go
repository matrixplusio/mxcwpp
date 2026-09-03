//go:build linux

// Package fanotify 实现 Agent 端 fanotify 文件监控 (P3-2).
//
// 替代 inotify 的优势:
//   - 拿到精确触发进程 PID (FAN_REPORT_PIDFD, kernel >= 5.13)
//   - 拿到精确文件 dentry path (FAN_REPORT_DFID_NAME, kernel >= 5.9)
//   - 支持 FAN_OPEN_PERM / FAN_ACCESS_PERM permission event (可阻断)
//   - 支持 mount 维度 mark (FAN_MARK_FILESYSTEM) 一次性监控整个分区
//
// 要求:
//   - kernel >= 5.4 (FAN_REPORT_FID), >= 5.9 (FAN_REPORT_DFID_NAME), >= 5.13 (FAN_REPORT_PIDFD)
//   - CAP_SYS_ADMIN (Agent 以 root 运行符合)
//
// 兼容性回退:
//   - 当前内核不支持 FAN_REPORT_PIDFD → 走 FAN_CLASS_NOTIF + /proc 查 fd 还原 PID
//   - 不支持 fanotify 全套 (kernel < 5.0) → 由调用方 fallback inotify
package fanotify

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"unsafe"

	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

// Event 是 fanotify 事件抽象 (统一 inotify 与 fanotify 上层).
type Event struct {
	Path      string
	Operation string // open / modify / close_write / delete / move / attr / access
	PID       int32
	Exe       string
	UID       int32
	GID       int32
}

// Watcher fanotify 监控器.
type Watcher struct {
	fd     int
	logger *zap.Logger

	mu     sync.RWMutex
	stop   chan struct{}
	events chan Event
}

// Capabilities fanotify 能力探测结果.
type Capabilities struct {
	HasFanotify   bool
	HasFID        bool   // FAN_REPORT_FID (kernel 5.4+)
	HasDFIDName   bool   // FAN_REPORT_DFID_NAME (kernel 5.9+)
	HasPIDFD      bool   // FAN_REPORT_PIDFD (kernel 5.13+)
	KernelVersion string // major.minor 提取
}

// Probe 探测当前内核 fanotify 能力。
//
// 通过尝试 init 不同 flags 组合识别支持的特性 + 立即关闭。
func Probe() Capabilities {
	caps := Capabilities{}
	caps.KernelVersion = kernelVersion()

	// 尝试最完整 (5.13+)
	if fd, err := unix.FanotifyInit(
		unix.FAN_CLASS_NOTIF|unix.FAN_REPORT_PIDFD|unix.FAN_REPORT_DFID_NAME|unix.FAN_NONBLOCK|unix.FAN_CLOEXEC,
		unix.O_RDONLY|unix.O_LARGEFILE,
	); err == nil {
		_ = unix.Close(fd)
		caps.HasFanotify = true
		caps.HasFID = true
		caps.HasDFIDName = true
		caps.HasPIDFD = true
		return caps
	}

	// 退回 5.9+
	if fd, err := unix.FanotifyInit(
		unix.FAN_CLASS_NOTIF|unix.FAN_REPORT_DFID_NAME|unix.FAN_NONBLOCK|unix.FAN_CLOEXEC,
		unix.O_RDONLY|unix.O_LARGEFILE,
	); err == nil {
		_ = unix.Close(fd)
		caps.HasFanotify = true
		caps.HasFID = true
		caps.HasDFIDName = true
		return caps
	}

	// 退回 5.4+
	if fd, err := unix.FanotifyInit(
		unix.FAN_CLASS_NOTIF|unix.FAN_REPORT_FID|unix.FAN_NONBLOCK|unix.FAN_CLOEXEC,
		unix.O_RDONLY|unix.O_LARGEFILE,
	); err == nil {
		_ = unix.Close(fd)
		caps.HasFanotify = true
		caps.HasFID = true
		return caps
	}

	// 最基础 (任何支持 fanotify 的内核)
	if fd, err := unix.FanotifyInit(
		unix.FAN_CLASS_NOTIF|unix.FAN_NONBLOCK|unix.FAN_CLOEXEC,
		unix.O_RDONLY|unix.O_LARGEFILE,
	); err == nil {
		_ = unix.Close(fd)
		caps.HasFanotify = true
		return caps
	}

	return caps
}

// NewWatcher 创建 fanotify watcher.
//
// 失败 (CAP_SYS_ADMIN 缺失 / 内核不支持) → 返回 error, 调用方 fallback inotify.
func NewWatcher(logger *zap.Logger) (*Watcher, error) {
	if logger == nil {
		logger = zap.NewNop()
	}
	caps := Probe()
	if !caps.HasFanotify {
		return nil, errors.New("fanotify: not supported by kernel or missing CAP_SYS_ADMIN")
	}

	flags := unix.FAN_CLASS_NOTIF | unix.FAN_NONBLOCK | unix.FAN_CLOEXEC
	if caps.HasPIDFD {
		flags |= unix.FAN_REPORT_PIDFD
	}
	if caps.HasDFIDName {
		flags |= unix.FAN_REPORT_DFID_NAME
	} else if caps.HasFID {
		flags |= unix.FAN_REPORT_FID
	}

	fd, err := unix.FanotifyInit(uint(flags), unix.O_RDONLY|unix.O_LARGEFILE|unix.O_CLOEXEC)
	if err != nil {
		return nil, fmt.Errorf("fanotify_init: %w", err)
	}

	logger.Info("fanotify watcher initialized",
		zap.Bool("pidfd", caps.HasPIDFD),
		zap.Bool("dfid_name", caps.HasDFIDName),
		zap.String("kernel", caps.KernelVersion))

	w := &Watcher{
		fd:     fd,
		logger: logger,
		stop:   make(chan struct{}),
		events: make(chan Event, 256),
	}
	go w.loop()
	return w, nil
}

// Watch 添加监控路径。
//
// 事件 mask: FAN_MODIFY | FAN_CLOSE_WRITE | FAN_DELETE_SELF | FAN_MOVE_SELF | FAN_ATTRIB
func (w *Watcher) Watch(path string) error {
	mask := uint64(unix.FAN_MODIFY | unix.FAN_CLOSE_WRITE | unix.FAN_OPEN | unix.FAN_ATTRIB)
	if err := unix.FanotifyMark(w.fd,
		unix.FAN_MARK_ADD,
		mask,
		unix.AT_FDCWD,
		path); err != nil {
		return fmt.Errorf("fanotify_mark %s: %w", path, err)
	}
	return nil
}

// WatchFilesystem 监控整个挂载点 (高效, 用于扫整个 /home 等).
func (w *Watcher) WatchFilesystem(mountPoint string) error {
	mask := uint64(unix.FAN_MODIFY | unix.FAN_CLOSE_WRITE | unix.FAN_OPEN)
	if err := unix.FanotifyMark(w.fd,
		unix.FAN_MARK_ADD|unix.FAN_MARK_FILESYSTEM,
		mask,
		unix.AT_FDCWD,
		mountPoint); err != nil {
		return fmt.Errorf("fanotify_mark filesystem %s: %w", mountPoint, err)
	}
	return nil
}

// Unwatch 删监控.
func (w *Watcher) Unwatch(path string) error {
	mask := uint64(unix.FAN_MODIFY | unix.FAN_CLOSE_WRITE | unix.FAN_OPEN | unix.FAN_ATTRIB)
	return unix.FanotifyMark(w.fd, unix.FAN_MARK_REMOVE, mask, unix.AT_FDCWD, path)
}

// Events 事件 channel.
func (w *Watcher) Events() <-chan Event { return w.events }

// Close 收尾.
func (w *Watcher) Close() error {
	close(w.stop)
	if w.fd >= 0 {
		return unix.Close(w.fd)
	}
	return nil
}

// loop 主读循环.
func (w *Watcher) loop() {
	buf := make([]byte, 4096)
	for {
		select {
		case <-w.stop:
			return
		default:
		}
		n, err := unix.Read(w.fd, buf)
		if err != nil {
			if errors.Is(err, unix.EINTR) || errors.Is(err, unix.EAGAIN) {
				continue
			}
			w.logger.Debug("fanotify read", zap.Error(err))
			return
		}
		var off int
		for off < n {
			if off+int(unsafe.Sizeof(unix.FanotifyEventMetadata{})) > n {
				break
			}
			meta := (*unix.FanotifyEventMetadata)(unsafe.Pointer(&buf[off]))
			metaLen := int(meta.Event_len)
			if metaLen <= 0 || off+metaLen > n {
				break
			}
			ev := w.parseEventWithInfo(buf[off:off+metaLen], meta)
			if ev != nil {
				select {
				case w.events <- *ev:
				default:
					w.logger.Warn("fanotify event queue full, drop")
				}
			}
			// fanotify 把 fd 给 caller, 需主动关闭
			if meta.Fd >= 0 {
				_ = unix.Close(int(meta.Fd))
			}
			off += metaLen
		}
	}
}

// parseEventWithInfo 解析 metadata + 后续 FID/DFID_NAME/PIDFD info records (P5-4).
//
// 优先级:
//   - 路径: DFID_NAME (open_by_handle_at + 拼 name) > meta.Fd > readlink /proc/self/fd
//   - PID:  PIDFD (/proc/self/fdinfo/<pidfd>:Pid) > meta.Pid
func (w *Watcher) parseEventWithInfo(payload []byte, meta *unix.FanotifyEventMetadata) *Event {
	ev := w.parseEvent(payload, meta)
	if ev == nil {
		return nil
	}
	records := iterInfoRecords(meta, payload)
	for _, rec := range records {
		switch rec.Type {
		case FAN_EVENT_INFO_TYPE_PIDFD:
			pidfd := parsePidfd(rec)
			if pid := resolvePidfd(pidfd); pid > 0 {
				ev.PID = pid
				ev.Exe = readlinkProcExe(pid)
				ev.UID, ev.GID = procUIDGID(pid)
			}
			if pidfd >= 0 {
				_ = unix.Close(int(pidfd))
			}
		case FAN_EVENT_INFO_TYPE_DFID_NAME, FAN_EVENT_INFO_TYPE_FID, FAN_EVENT_INFO_TYPE_DFID:
			if parsed, ok := parseFIDName(rec); ok {
				// mountFd=0 → 用 AT_FDCWD 兜底, 生产应在 WatchFilesystem 里 keep mount_fd 表
				if path, err := resolveByHandle(parsed, 0); err == nil && path != "" {
					ev.Path = path
				} else if parsed.Name != "" && ev.Path != "" {
					ev.Path = filepath.Join(ev.Path, parsed.Name)
				}
			}
		}
	}
	return ev
}

// parseEvent 把 raw bytes 解析成 Event.
func (w *Watcher) parseEvent(_ []byte, meta *unix.FanotifyEventMetadata) *Event {
	ev := &Event{}
	// 解 mask → operation
	mask := meta.Mask
	switch {
	case mask&unix.FAN_MODIFY != 0:
		ev.Operation = "modify"
	case mask&unix.FAN_CLOSE_WRITE != 0:
		ev.Operation = "close_write"
	case mask&unix.FAN_OPEN != 0:
		ev.Operation = "open"
	case mask&unix.FAN_ATTRIB != 0:
		ev.Operation = "attr"
	case mask&unix.FAN_ACCESS != 0:
		ev.Operation = "access"
	default:
		ev.Operation = fmt.Sprintf("mask_0x%x", mask)
	}
	// PID
	ev.PID = int32(meta.Pid)
	// 通过 fd 拿路径 + 进程 exe
	if meta.Fd >= 0 {
		ev.Path = readlinkProcFD(int(meta.Fd))
	}
	if ev.PID > 0 {
		ev.Exe = readlinkProcExe(ev.PID)
		ev.UID, ev.GID = procUIDGID(ev.PID)
	}
	return ev
}

// readlinkProcFD: /proc/self/fd/<fd> 解 symlink → 真实路径.
func readlinkProcFD(fd int) string {
	link := fmt.Sprintf("/proc/self/fd/%d", fd)
	target, err := os.Readlink(link)
	if err != nil {
		return ""
	}
	return target
}

// readlinkProcExe: /proc/<pid>/exe 解.
func readlinkProcExe(pid int32) string {
	link := fmt.Sprintf("/proc/%d/exe", pid)
	target, err := os.Readlink(link)
	if err != nil {
		return ""
	}
	return target
}

// procUIDGID: /proc/<pid>/status 取 Uid/Gid.
func procUIDGID(pid int32) (int32, int32) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0, 0
	}
	defer f.Close()
	buf := make([]byte, 4096)
	n, _ := f.Read(buf)
	var uid, gid int32
	parse := func(prefix string) int32 {
		for i := 0; i+len(prefix) < n; i++ {
			if string(buf[i:i+len(prefix)]) != prefix {
				continue
			}
			j := i + len(prefix)
			start := j
			for j < n && (buf[j] == '\t' || buf[j] == ' ') {
				j++
				start = j
			}
			for j < n && buf[j] >= '0' && buf[j] <= '9' {
				j++
			}
			if v, err := strconv.Atoi(string(buf[start:j])); err == nil {
				return int32(v)
			}
		}
		return 0
	}
	uid = parse("Uid:")
	gid = parse("Gid:")
	return uid, gid
}

// kernelVersion 读 /proc/sys/kernel/osrelease.
func kernelVersion() string {
	data, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return "unknown"
	}
	// 5.15.0-72-generic → 5.15
	s := string(data)
	idx1 := -1
	dots := 0
	for i, c := range s {
		if c == '.' {
			dots++
			if dots == 2 {
				idx1 = i
				break
			}
		}
	}
	if idx1 > 0 {
		return s[:idx1]
	}
	return s
}

// 编译期占位防 unused import.
var _ = binary.BigEndian
var _ = filepath.Base
