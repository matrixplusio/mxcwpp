//go:build !linux

package antidebug

import (
	"time"

	"go.uber.org/zap"
)

// SelfProtect non-linux no-op.
func SelfProtect(_ *zap.Logger) error { return nil }

type ELFIntegrityMonitor struct{}

func NewELFIntegrityMonitor(_ string, _ time.Duration, _ *zap.Logger) *ELFIntegrityMonitor {
	return &ELFIntegrityMonitor{}
}

func (m *ELFIntegrityMonitor) SetOnTamper(_ func())  {}
func (m *ELFIntegrityMonitor) Run(_ <-chan struct{}) {}
