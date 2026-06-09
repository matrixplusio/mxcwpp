//go:build !linux

package fanotify

import (
	"errors"
	"go.uber.org/zap"
)

// Event 非 Linux stub.
type Event struct {
	Path      string
	Operation string
	PID       int32
	Exe       string
	UID       int32
	GID       int32
}

// Capabilities stub.
type Capabilities struct {
	HasFanotify   bool
	HasFID        bool
	HasDFIDName   bool
	HasPIDFD      bool
	KernelVersion string
}

// Probe 非 Linux always false.
func Probe() Capabilities { return Capabilities{} }

// Watcher 非 Linux no-op.
type Watcher struct{}

// NewWatcher 非 Linux 直接返 error.
func NewWatcher(_ *zap.Logger) (*Watcher, error) {
	return nil, errors.New("fanotify: linux only")
}

func (w *Watcher) Watch(_ string) error           { return errors.New("linux only") }
func (w *Watcher) WatchFilesystem(_ string) error { return errors.New("linux only") }
func (w *Watcher) Unwatch(_ string) error         { return errors.New("linux only") }
func (w *Watcher) Events() <-chan Event           { return nil }
func (w *Watcher) Close() error                   { return nil }
