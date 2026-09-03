//go:build linux

package engine

import (
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

// decoyWatcher Linux 实现:
//
// 简化用 inotify (IN_MODIFY | IN_CLOSE_WRITE | IN_DELETE | IN_MOVED_FROM)。
// 优点: 不需要 CAP_SYS_ADMIN。
// 缺点: 拿不到触发进程精确 PID/EXE, 用 /proc fd 扫描近似还原。
//
// 后续 Sprint 升级 fanotify (CAP_SYS_ADMIN) 拿精确 PID。
type decoyWatcher struct {
	fd     int
	logger *zap.Logger

	mu     sync.RWMutex
	paths  map[int]string // wd -> path
	stop   chan struct{}
	events chan decoyEvent
}

type decoyEvent struct {
	Path      string
	Operation string
	PID       int32
	Exe       string
	UID       int32
}

func newDecoyWatcher(logger *zap.Logger) *decoyWatcher {
	if logger == nil {
		logger = zap.NewNop()
	}
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC)
	if err != nil {
		logger.Error("inotify init failed", zap.Error(err))
		return &decoyWatcher{fd: -1, logger: logger, paths: map[int]string{},
			stop: make(chan struct{}), events: make(chan decoyEvent, 32)}
	}
	w := &decoyWatcher{
		fd:     fd,
		logger: logger,
		paths:  make(map[int]string),
		stop:   make(chan struct{}),
		events: make(chan decoyEvent, 64),
	}
	go w.loop()
	return w
}

func (w *decoyWatcher) Watch(path string) error {
	if w.fd < 0 {
		return errors.New("watcher unavailable")
	}
	wd, err := unix.InotifyAddWatch(w.fd, path,
		unix.IN_MODIFY|unix.IN_CLOSE_WRITE|unix.IN_DELETE_SELF|unix.IN_MOVE_SELF|unix.IN_ATTRIB)
	if err != nil {
		return fmt.Errorf("inotify_add_watch %s: %w", path, err)
	}
	w.mu.Lock()
	w.paths[wd] = path
	w.mu.Unlock()
	return nil
}

func (w *decoyWatcher) Events() <-chan decoyEvent { return w.events }

func (w *decoyWatcher) Close() error {
	close(w.stop)
	if w.fd >= 0 {
		return unix.Close(w.fd)
	}
	return nil
}

func (w *decoyWatcher) loop() {
	buf := make([]byte, 4096)
	for {
		select {
		case <-w.stop:
			return
		default:
		}
		n, err := unix.Read(w.fd, buf)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			w.logger.Debug("inotify read", zap.Error(err))
			return
		}
		var i int
		for i+unix.SizeofInotifyEvent <= n {
			raw := (*unix.InotifyEvent)(unsafe.Pointer(&buf[i]))
			wd := int(raw.Wd)
			mask := raw.Mask
			w.mu.RLock()
			path, ok := w.paths[wd]
			w.mu.RUnlock()
			if ok {
				op := decodeMask(mask)
				if op != "" {
					ev := decoyEvent{Path: path, Operation: op}
					guessTriggerProcess(path, &ev)
					select {
					case w.events <- ev:
					default:
					}
				}
			}
			i += unix.SizeofInotifyEvent + int(raw.Len)
		}
	}
}

func decodeMask(mask uint32) string {
	switch {
	case mask&unix.IN_MODIFY != 0:
		return "modify"
	case mask&unix.IN_CLOSE_WRITE != 0:
		return "close_write"
	case mask&unix.IN_DELETE_SELF != 0:
		return "delete"
	case mask&unix.IN_MOVE_SELF != 0:
		return "move"
	case mask&unix.IN_ATTRIB != 0:
		return "attr"
	}
	return ""
}

// guessTriggerProcess 通过 /proc 扫描 fd 持有者近似还原触发进程。
//
// 不精确 (写完 close 后 fd 已释放),仅作 fallback;准确 PID 需后续走 fanotify。
func guessTriggerProcess(path string, ev *decoyEvent) {
	procs, err := os.ReadDir("/proc")
	if err != nil {
		return
	}
	for _, p := range procs {
		if !p.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(p.Name())
		if err != nil {
			continue
		}
		fdDir := filepath.Join("/proc", p.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			target, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil {
				continue
			}
			if target == path {
				ev.PID = int32(pid)
				if exe, err := os.Readlink(filepath.Join("/proc", p.Name(), "exe")); err == nil {
					ev.Exe = exe
				}
				return
			}
		}
	}
}
