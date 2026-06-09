// Package worker — 后台周期任务统一 RunLoop (A10 审计修复).
//
// 项目里 `for { select { case <-ctx.Done(): return; case <-t.C: ... } }`
// 模板出现 27+ 次. 本包封装统一接口, 调用方仅给 interval + handler.
//
// 用法:
//
//	worker.RunLoop(ctx, 30*time.Second, "config_change_worker", logger, func(ctx context.Context) {
//	    w.runOnce(ctx)
//	})
//
// 失败 panic 自动 recover + 写日志, 不让单次 panic 杀整个 worker.
package worker

import (
	"context"
	"fmt"
	"runtime/debug"
	"time"

	"go.uber.org/zap"
)

// HandleFunc 每个 tick 执行的回调.
type HandleFunc func(ctx context.Context)

// RunLoop 阻塞跑周期 worker, 接 ctx.Done() 退出.
//
// 参数:
//   - ctx     上游 ctx, cancel 即退
//   - interval tick 间隔 (<=0 → 默认 30s)
//   - name    日志标识
//   - logger  nil 自动 fallback zap.NewNop()
//   - fn      每 tick 执行
//
// 行为:
//   - 启动立即执行一次 fn (避免冷启动 interval 后才开始)
//   - 后续每 interval 执行
//   - fn 内 panic 被 recover, 写错误日志, 下一 tick 继续
func RunLoop(ctx context.Context, interval time.Duration, name string, logger *zap.Logger, fn HandleFunc) {
	if logger == nil {
		logger = zap.NewNop()
	}
	if interval <= 0 {
		interval = 30 * time.Second
	}
	if fn == nil {
		return
	}
	safeFn := func(c context.Context) {
		defer func() {
			if r := recover(); r != nil {
				logger.Error("worker panic recovered",
					zap.String("worker", name),
					zap.Any("panic", r),
					zap.String("stack", string(debug.Stack())))
			}
		}()
		fn(c)
	}

	logger.Info("worker started", zap.String("name", name), zap.Duration("interval", interval))
	defer logger.Info("worker stopped", zap.String("name", name))

	safeFn(ctx)

	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			safeFn(ctx)
		}
	}
}

// RunLoopWithRecover 类似 RunLoop, 但 fn 返 error 时写 warn 日志 (不 recover panic).
func RunLoopWithRecover(ctx context.Context, interval time.Duration, name string, logger *zap.Logger, fn func(ctx context.Context) error) {
	wrap := func(c context.Context) {
		if err := fn(c); err != nil {
			if logger != nil {
				logger.Warn("worker iteration failed",
					zap.String("worker", name),
					zap.Error(err))
			}
		}
	}
	RunLoop(ctx, interval, name, logger, wrap)
}

// Multi 同时跑多个 worker (each 独立 goroutine), 任一 ctx 取消则全停.
type Multi struct {
	logger *zap.Logger
	jobs   []job
}

type job struct {
	name     string
	interval time.Duration
	fn       HandleFunc
}

// NewMulti 构造.
func NewMulti(logger *zap.Logger) *Multi {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &Multi{logger: logger}
}

// Add 注册一个 worker.
func (m *Multi) Add(name string, interval time.Duration, fn HandleFunc) *Multi {
	m.jobs = append(m.jobs, job{name: name, interval: interval, fn: fn})
	return m
}

// Run 阻塞跑所有 worker.
func (m *Multi) Run(ctx context.Context) {
	if len(m.jobs) == 0 {
		return
	}
	done := make(chan struct{}, len(m.jobs))
	for i := range m.jobs {
		j := m.jobs[i]
		go func() {
			defer func() { done <- struct{}{} }()
			RunLoop(ctx, j.interval, j.name, m.logger, j.fn)
		}()
	}
	// 等所有 worker 退出
	for i := 0; i < len(m.jobs); i++ {
		<-done
	}
	m.logger.Info(fmt.Sprintf("multi worker shutdown (%d jobs)", len(m.jobs)))
}
