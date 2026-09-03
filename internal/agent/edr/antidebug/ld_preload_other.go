//go:build !linux

package antidebug

import "go.uber.org/zap"

type LDPreloadIndicator struct {
	Category, Severity, Detail string
	Evidence                   map[string]string
}

type LDPreloadScanner struct{}

func NewLDPreloadScanner(_ *zap.Logger) *LDPreloadScanner      { return &LDPreloadScanner{} }
func (s *LDPreloadScanner) ScanSelf() []LDPreloadIndicator     { return nil }
func (s *LDPreloadScanner) ScanPID(_ int) []LDPreloadIndicator { return nil }
