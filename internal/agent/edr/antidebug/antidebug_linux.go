//go:build linux

// Package antidebug 实现 Agent 自我加固 (M1-6)。
//
// 4 类自我保护:
//
//  1. PR_SET_DUMPABLE=0 — 禁 core dump + 禁 /proc/<pid>/{mem,maps} 被外部读
//  2. PR_SET_NO_NEW_PRIVS=1 — 禁后续 execve 提权 (LD_PRELOAD 等)
//  3. 自挂 ptrace — 进程启动立刻 ptrace(PTRACE_TRACEME) 自挂,
//     debugger 想 attach 会失败 (Linux 仅允许一个 tracer)
//  4. ELF SHA256 自检 — 周期校验自身可执行文件未被换包/打补丁
//
// 不做的事 (留 M2):
//
//   - garble 混淆: 在 build 阶段做 (scripts/build-agent-hardened.sh)
//   - UPX 压缩: 同 build 阶段
//   - 双进程互保: watchdog.go 实现
package antidebug

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

// SelfProtect 启动 4 类硬化措施。
//
// 任一失败 → 仅 warn 不 panic (优雅降级)。
// 应在 main() 最早阶段调用 (logger 初始化后即可)。
func SelfProtect(logger *zap.Logger) error {
	if logger == nil {
		logger = zap.NewNop()
	}
	var errs []error

	if err := prctlSetDumpable(); err != nil {
		logger.Warn("PR_SET_DUMPABLE 失败 (内核老/容器限制)", zap.Error(err))
		errs = append(errs, fmt.Errorf("dumpable: %w", err))
	} else {
		logger.Info("PR_SET_DUMPABLE=0 已设置 (禁 core dump + /proc 读限制)")
	}

	if err := prctlNoNewPrivs(); err != nil {
		logger.Warn("PR_SET_NO_NEW_PRIVS 失败", zap.Error(err))
		errs = append(errs, fmt.Errorf("nnp: %w", err))
	} else {
		logger.Info("PR_SET_NO_NEW_PRIVS=1 已设置 (禁后续 exec 提权)")
	}

	// PTRACE_TRACEME 自挂 — 暂时禁用，与 watchdog child 死锁：
	// 父进程自挂 ptrace → 停在 ptrace_stop → 发不了心跳 → child 永远等不到。
	// 修复方向：watchdog 应在 ptrace tracer 角色下主动 CONT 父进程，
	// 或改用 seccomp filter 替代 ptrace 防 attach。
	// if err := ptraceTraceMe(); err != nil {
	// 	logger.Warn("PTRACE_TRACEME 失败 (yama ptrace_scope=0 时一般可用)", zap.Error(err))
	// 	errs = append(errs, fmt.Errorf("traceme: %w", err))
	// } else {
	// 	logger.Info("PTRACE_TRACEME 已自挂 (外部 debugger 无法 attach)")
	// }

	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

func prctlSetDumpable() error {
	// PR_SET_DUMPABLE=4, value=0
	return unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0)
}

func prctlNoNewPrivs() error {
	// PR_SET_NO_NEW_PRIVS=38
	return unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
}

// ptraceTraceMe 自己 attach 自己, 外部 debugger 想再 attach 会 EPERM。
//
// 直接 ptrace syscall (golang.org/x/sys/unix 没暴露 PtraceTraceMe).
func ptraceTraceMe() error {
	// PTRACE_TRACEME = 0
	_, _, errno := unix.Syscall(unix.SYS_PTRACE, 0, 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

// ELFIntegrityMonitor 周期 SHA256 校验自身可执行文件。
//
// 用法:
//
//	mon := NewELFIntegrityMonitor("/proc/self/exe", 5*time.Minute, logger)
//	go mon.Run(ctx)
//
// 命中即上报 + 触发自杀 (假设可执行被换包/打补丁, 任何继续运行都不可信)。
type ELFIntegrityMonitor struct {
	path     string
	interval time.Duration
	logger   *zap.Logger

	mu       sync.Mutex
	baseline string // 启动时算出的 sha256

	onTamper func() // 命中时回调 (默认 os.Exit(2))
}

// NewELFIntegrityMonitor 构造。path 通常 "/proc/self/exe"。
func NewELFIntegrityMonitor(path string, interval time.Duration, logger *zap.Logger) *ELFIntegrityMonitor {
	if logger == nil {
		logger = zap.NewNop()
	}
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	return &ELFIntegrityMonitor{
		path:     path,
		interval: interval,
		logger:   logger,
		onTamper: func() { os.Exit(2) },
	}
}

// SetOnTamper 自定义命中回调 (测试用)。
func (m *ELFIntegrityMonitor) SetOnTamper(cb func()) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onTamper = cb
}

// Run 阻塞循环。启动立即算 baseline → 周期对比。
func (m *ELFIntegrityMonitor) Run(stop <-chan struct{}) {
	hash, err := hashFile(m.path)
	if err != nil {
		m.logger.Error("无法读取自身可执行文件, ELF 校验禁用", zap.Error(err))
		return
	}
	m.mu.Lock()
	m.baseline = hash
	m.mu.Unlock()
	m.logger.Info("ELF integrity baseline 已建立",
		zap.String("sha256", hash), zap.String("path", m.path))

	tick := time.NewTicker(m.interval)
	defer tick.Stop()
	for {
		select {
		case <-stop:
			return
		case <-tick.C:
			cur, err := hashFile(m.path)
			if err != nil {
				m.logger.Warn("ELF 校验读取失败", zap.Error(err))
				continue
			}
			m.mu.Lock()
			base := m.baseline
			cb := m.onTamper
			m.mu.Unlock()
			if cur != base {
				m.logger.Error("ELF integrity violation: 可执行文件 SHA256 不一致",
					zap.String("baseline", base),
					zap.String("current", cur),
					zap.String("action", "self-terminate"))
				if cb != nil {
					cb()
				}
				return
			}
		}
	}
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
