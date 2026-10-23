//go:build !linux

package antidebug

import (
	"errors"
	"time"

	"go.uber.org/zap"
)

type WatchdogConfig struct {
	HeartbeatInterval time.Duration
	MaxHeartbeatMiss  int
	RestartCommand    []string
	Logger            *zap.Logger
}

type Watchdog struct {
	OnSuspectKill func(suspect string)
}

func NewWatchdog(_ WatchdogConfig) *Watchdog { return &Watchdog{} }
func IsChild() bool                          { return false }
func (w *Watchdog) StartAsParent() error     { return errors.New("watchdog: linux only") }
func (w *Watchdog) Stop() error              { return nil }
func ServeAsChild(_ WatchdogConfig) error    { return errors.New("watchdog: linux only") }
