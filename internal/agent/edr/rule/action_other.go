//go:build !linux

package rule

import "go.uber.org/zap"

// ActionExecutor is a no-op stub on non-Linux platforms.
type ActionExecutor struct{} //nolint:unused

// NewActionExecutor returns a stub executor on non-Linux platforms.
func NewActionExecutor(_ *zap.Logger, _ *AuditLogger, _ string) *ActionExecutor { //nolint:unused
	return &ActionExecutor{}
}

// Execute is a no-op on non-Linux platforms.
func (a *ActionExecutor) Execute(_ *Rule, _ map[string]string) {} //nolint:unused
