//go:build linux

// Package antidebug 自保 + 双进程互保 (P2-1 完整实现)。
//
// Watchdog 设计:
//
//	父进程 (Agent 主进程):
//	  - 启动时 fork 子进程 (watchdog)
//	  - 与 child 走 socketpair 心跳
//	  - 周期 (HeartbeatInterval) send "PING" → 等 "PONG"
//	  - child 心跳超时 (MaxHeartbeatMiss * Interval) → 怀疑 child 被杀, 重启 child
//
//	子进程 (watchdog):
//	  - prctl(PR_SET_PDEATHSIG, SIGKILL) — 父进程死, child 自动死
//	  - 接收 parent "PING" → 立即回 "PONG"
//	  - 心跳超时 → 怀疑 parent 被杀:
//	    a) 检查父进程 (getppid()) 是否仍然存在
//	    b) 父进程已死 → exec /usr/bin/systemctl restart mxsec-agent
//	       (依赖 systemd 重启保护)
//
// 攻击者杀单进程 → 另一进程立即检测 + 重启 + 上报告警。
// 真正杀死 Agent 需精确同时 kill 两进程 + 阻断 systemd, 大幅提高门槛。
package antidebug

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

const (
	defaultHeartbeatInterval = 3 * time.Second
	defaultMaxHeartbeatMiss  = 3 // 9s 没收到 → 怀疑死亡
	envIsWatchdog            = "MXSEC_WATCHDOG_CHILD"
	envSocketFD              = "MXSEC_WATCHDOG_SOCKFD"
)

// WatchdogConfig 配置。
type WatchdogConfig struct {
	HeartbeatInterval time.Duration
	MaxHeartbeatMiss  int
	// RestartCommand 父死后 child 拉起 Agent 用命令 (默认 systemctl restart mxsec-agent)
	RestartCommand []string
	Logger         *zap.Logger
}

// Watchdog 双进程互保管理器。
type Watchdog struct {
	cfg    WatchdogConfig
	logger *zap.Logger

	mu      sync.Mutex
	child   *os.Process // parent 视角的 child handle
	sock    *os.File    // parent <-> child 心跳 socket
	stopped atomic.Bool

	OnSuspectKill func(suspect string) // 命中 callback (上报告警用)
}

// NewWatchdog 构造。
func NewWatchdog(cfg WatchdogConfig) *Watchdog {
	if cfg.HeartbeatInterval <= 0 {
		cfg.HeartbeatInterval = defaultHeartbeatInterval
	}
	if cfg.MaxHeartbeatMiss <= 0 {
		cfg.MaxHeartbeatMiss = defaultMaxHeartbeatMiss
	}
	if cfg.Logger == nil {
		cfg.Logger = zap.NewNop()
	}
	if len(cfg.RestartCommand) == 0 {
		cfg.RestartCommand = []string{"/bin/systemctl", "restart", "mxsec-agent"}
	}
	return &Watchdog{cfg: cfg, logger: cfg.Logger}
}

// IsChild 当前进程是否为 watchdog child。
//
// child 进程的 main.go 应在最早期调用 IsChild → ServeAsChild 路径。
func IsChild() bool { return os.Getenv(envIsWatchdog) == "1" }

// StartAsParent fork 子进程 + 心跳循环 (父进程入口)。
//
// 失败 (非 root / 系统 unavailable) → 仅 warn, 返回 nil → Agent 主流程继续。
func (w *Watchdog) StartAsParent() error {
	if w.cfg.HeartbeatInterval <= 0 {
		return errors.New("invalid heartbeat interval")
	}
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("self exec: %w", err)
	}
	// 创建 socketpair
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		return fmt.Errorf("socketpair: %w", err)
	}
	parentSock := os.NewFile(uintptr(fds[0]), "watchdog-parent")
	childSock := os.NewFile(uintptr(fds[1]), "watchdog-child")
	w.sock = parentSock

	// fork child
	procAttr := &os.ProcAttr{
		Env: append(os.Environ(),
			envIsWatchdog+"=1",
			fmt.Sprintf("%s=3", envSocketFD), // child 把 socket dup 到 fd 3
		),
		Files: []*os.File{
			os.Stdin,
			os.Stdout,
			os.Stderr,
			childSock,
		},
		Sys: &syscall.SysProcAttr{
			Setsid: false,
		},
	}
	proc, err := os.StartProcess(exe, []string{exe, "--watchdog-child"}, procAttr)
	if err != nil {
		_ = parentSock.Close()
		_ = childSock.Close()
		return fmt.Errorf("fork watchdog: %w", err)
	}
	_ = childSock.Close() // parent 不持有 child 侧 socket
	w.mu.Lock()
	w.child = proc
	w.mu.Unlock()

	w.logger.Info("watchdog child forked", zap.Int("pid", proc.Pid))

	go w.parentLoop()
	go w.reapChildLoop()
	return nil
}

// ServeAsChild 子进程入口 (子进程 main 调用)。
//
// 永不返回 (除非 parent 死亡 + 重启失败)。
func ServeAsChild(cfg WatchdogConfig) error {
	if !IsChild() {
		return errors.New("not a watchdog child")
	}
	logger := cfg.Logger
	if logger == nil {
		logger = zap.NewNop()
	}
	// PR_SET_PDEATHSIG: 父进程死, child 收 SIGKILL
	if err := unix.Prctl(unix.PR_SET_PDEATHSIG, uintptr(unix.SIGKILL), 0, 0, 0); err != nil {
		logger.Warn("PR_SET_PDEATHSIG 失败", zap.Error(err))
	}
	// 检查 parent 是否还在 (race: 在 prctl 之前 parent 可能已经死)
	if os.Getppid() == 1 {
		logger.Warn("parent already died at child startup; restarting agent")
		return restartAgent(cfg)
	}
	// 接管 fd 3 socket
	sock := os.NewFile(3, "watchdog-child-sock")
	defer sock.Close()

	parentDead := false
	miss := 0
	interval := cfg.HeartbeatInterval
	if interval <= 0 {
		interval = defaultHeartbeatInterval
	}
	maxMiss := cfg.MaxHeartbeatMiss
	if maxMiss <= 0 {
		maxMiss = defaultMaxHeartbeatMiss
	}
	buf := make([]byte, 64)
	_ = sock.SetReadDeadline(time.Now().Add(interval * 2))

	for {
		n, err := sock.Read(buf)
		if err != nil || n == 0 {
			miss++
			if miss >= maxMiss {
				if os.Getppid() == 1 {
					parentDead = true
					break
				}
				miss = 0 // 父进程还在, 重置
			}
			_ = sock.SetReadDeadline(time.Now().Add(interval * 2))
			continue
		}
		miss = 0
		// 收到 PING → 回 PONG
		_, _ = sock.Write([]byte("PONG"))
		_ = sock.SetReadDeadline(time.Now().Add(interval * 2))
	}

	if parentDead {
		logger.Error("watchdog: parent process died, restarting via systemd",
			zap.Strings("cmd", cfg.RestartCommand))
		return restartAgent(cfg)
	}
	return nil
}

// parentLoop 父进程心跳发送 + 接收。
func (w *Watchdog) parentLoop() {
	t := time.NewTicker(w.cfg.HeartbeatInterval)
	defer t.Stop()
	buf := make([]byte, 64)
	miss := 0
	for {
		if w.stopped.Load() {
			return
		}
		<-t.C
		_, err := w.sock.Write([]byte("PING"))
		if err != nil {
			w.logger.Warn("watchdog: write PING failed", zap.Error(err))
			miss++
		} else {
			_ = w.sock.SetReadDeadline(time.Now().Add(w.cfg.HeartbeatInterval))
			n, err := w.sock.Read(buf)
			if err != nil || n == 0 {
				miss++
			} else {
				miss = 0
			}
		}
		if miss >= w.cfg.MaxHeartbeatMiss {
			w.logger.Error("watchdog: child no PONG, restarting child",
				zap.Int("missed", miss))
			if w.OnSuspectKill != nil {
				w.OnSuspectKill("child_no_pong")
			}
			w.restartChild()
			miss = 0
		}
	}
}

// reapChildLoop wait4 child 退出 → 立刻重启。
func (w *Watchdog) reapChildLoop() {
	for {
		if w.stopped.Load() {
			return
		}
		w.mu.Lock()
		ch := w.child
		w.mu.Unlock()
		if ch == nil {
			time.Sleep(1 * time.Second)
			continue
		}
		state, err := ch.Wait()
		if err != nil {
			w.logger.Warn("watchdog: wait child error", zap.Error(err))
			time.Sleep(2 * time.Second)
			continue
		}
		w.logger.Error("watchdog: child exited, restarting",
			zap.Int("pid", ch.Pid),
			zap.String("state", state.String()))
		if w.OnSuspectKill != nil {
			w.OnSuspectKill("child_exited")
		}
		w.restartChild()
	}
}

// restartChild 杀掉旧 child + 重新 StartAsParent。
//
// 简化: 关闭 sock + 重新 socketpair + fork。
func (w *Watchdog) restartChild() {
	w.mu.Lock()
	ch := w.child
	oldSock := w.sock
	w.child = nil
	w.sock = nil
	w.mu.Unlock()
	if ch != nil {
		_ = ch.Kill()
	}
	if oldSock != nil {
		_ = oldSock.Close()
	}
	time.Sleep(500 * time.Millisecond)
	if err := w.StartAsParent(); err != nil {
		w.logger.Error("watchdog: restart failed", zap.Error(err))
	}
}

// Stop 停止 (Agent 优雅退出时).
func (w *Watchdog) Stop() error {
	w.stopped.Store(true)
	w.mu.Lock()
	ch := w.child
	sock := w.sock
	w.mu.Unlock()
	if sock != nil {
		_ = sock.Close()
	}
	if ch != nil {
		_ = ch.Signal(syscall.SIGTERM)
	}
	return nil
}

// restartAgent (child 内) systemctl restart mxsec-agent。
func restartAgent(cfg WatchdogConfig) error {
	cmd := exec.Command(cfg.RestartCommand[0], cfg.RestartCommand[1:]...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("restart command failed: %w (%s)", err, out)
	}
	// 重启 systemd 起的新 Agent 进程会再 fork 新 child;
	// 本 child 已完成使命, 主动退出。
	os.Exit(0)
	return nil
}
