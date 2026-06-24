// Package plugins 提供插件 SDK 公共工具
package plugins

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// NewPluginLogger 创建插件专用的 logger（所有插件统一使用）
// 输出到 stderr，由 Agent 重定向到 /var/log/mxcwpp-agent/plugins/{plugin}.log
func NewPluginLogger() (*zap.Logger, error) {
	config := zap.NewProductionConfig()
	config.OutputPaths = []string{"stderr"}
	config.ErrorOutputPaths = []string{"stderr"}
	config.Encoding = "json"
	config.Level = zap.NewAtomicLevelAt(zap.InfoLevel)
	config.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder

	return config.Build()
}
