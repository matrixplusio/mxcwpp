//go:build !linux

package engine

import "go.uber.org/zap"

// decoyWatcher 非 Linux 平台 stub (开发期 macOS 编译过).
//
// macOS 投诱饵 + 监控不在 mxsec 支持范围 (产品定位 Linux/K8s)。
type decoyWatcher struct {
	logger *zap.Logger
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
	logger.Warn("decoy watcher: non-linux platform, no-op stub")
	return &decoyWatcher{logger: logger, events: make(chan decoyEvent)}
}

func (w *decoyWatcher) Watch(_ string) error      { return nil }
func (w *decoyWatcher) Events() <-chan decoyEvent { return w.events }
func (w *decoyWatcher) Close() error              { close(w.events); return nil }
