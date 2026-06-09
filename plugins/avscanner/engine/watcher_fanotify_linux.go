//go:build linux

package engine

// fanotify 替代 inotify (M1-8 增强):
//
// 优势:
//   - 通过 FAN_REPORT_PIDFD 直接拿触发进程 PID (vs inotify 用 /proc fd 扫描近似)
//   - 通过 FAN_REPORT_DFID_NAME 拿精确文件路径 + dentry
//   - FAN_OPEN_PERM / FAN_ACCESS_PERM 支持 permission event (可阻断, observe 模式不用)
//
// 要求:
//   - CAP_SYS_ADMIN (Agent 通常以 root 运行)
//   - kernel >= 5.4 (FAN_REPORT_PIDFD 需要 5.13, 老内核走 FAN_CLASS_NOTIF + 进程 hint)
//
// 当前实现 (Sprint 5 完整化) 仅提供骨架 + 接口契约。
// 默认 fallback 到 inotify watcher (PR64 已实现, 见 watcher_linux.go)。

import (
	"errors"
	"go.uber.org/zap"
)

// FanotifyWatcher 高精度 fanotify 监控 (M1-8 骨架)。
type FanotifyWatcher struct {
	logger *zap.Logger
	events chan decoyEvent
}

// NewFanotifyWatcher 构造。返回 error 表示当前内核/权限不支持, 调用方应 fallback。
func NewFanotifyWatcher(_ *zap.Logger) (*FanotifyWatcher, error) {
	// Sprint 5 完整实现:
	// fd, err := unix.FanotifyInit(unix.FAN_CLASS_NOTIF|unix.FAN_REPORT_PIDFD|unix.FAN_NONBLOCK,
	//                              unix.O_RDONLY|unix.O_CLOEXEC|unix.O_LARGEFILE)
	// if err != nil { return nil, err }
	// unix.FanotifyMark(fd, FAN_MARK_ADD|FAN_MARK_FILESYSTEM,
	//                   FAN_MODIFY|FAN_CLOSE_WRITE|FAN_OPEN_PERM, AT_FDCWD, path)
	// 解析 fanotify_event_metadata + fanotify_event_info_pidfd
	return nil, errors.New("fanotify watcher not yet implemented (skeleton); use inotify fallback")
}

// Events 输出 channel.
func (w *FanotifyWatcher) Events() <-chan decoyEvent { return w.events }

// Watch 添加监控路径。
func (w *FanotifyWatcher) Watch(_ string) error { return errors.New("not implemented") }

// Close 收尾。
func (w *FanotifyWatcher) Close() error { return nil }
