package engine

import "go.uber.org/zap"

// testLogger 返回静默日志器用于单元测试
func testLogger() *zap.Logger {
	return zap.NewNop()
}
