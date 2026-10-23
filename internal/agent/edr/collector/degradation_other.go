//go:build !linux

package collector

import (
	"context"
	"sync"

	"go.uber.org/zap"
)

// DegradationManager stub for non-Linux platforms.
type DegradationManager struct{}

func NewDegradationManager(_ *zap.Logger, _ []interface{}, _ func()) *DegradationManager {
	return &DegradationManager{}
}

func (d *DegradationManager) Level() int32                                  { return 0 }
func (d *DegradationManager) Monitor(_ context.Context, wg *sync.WaitGroup) { defer wg.Done() }
