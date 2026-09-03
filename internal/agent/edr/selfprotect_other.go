//go:build !linux

package edr

import (
	"context"
	"sync"

	"go.uber.org/zap"
)

// SelfProtect is a no-op stub on non-Linux platforms.
type SelfProtect struct{}

// NewSelfProtect returns a stub on non-Linux platforms.
func NewSelfProtect(_ *zap.Logger) *SelfProtect { return &SelfProtect{} }

// Start is a no-op on non-Linux platforms.
func (sp *SelfProtect) Start(_ context.Context, _ *sync.WaitGroup) {}

// Stop is a no-op on non-Linux platforms.
func (sp *SelfProtect) Stop() {}

// TemporaryUnlock is a no-op on non-Linux platforms.
func (sp *SelfProtect) TemporaryUnlock(_ string) func() { return func() {} }
