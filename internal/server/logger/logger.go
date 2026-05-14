// Package logger 提供 Server 结构化日志功能（基于 Zap）
package logger

import (
	"os"
	"path/filepath"
	"time"

	rotatelogs "github.com/lestrrat-go/file-rotatelogs"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/imkerbos/mxsec-platform/internal/server/config"
)

// Init 初始化日志器
// 支持双文件输出：主日志 (level+) 和错误日志 (error+)
func Init(cfg config.LogConfig) (*zap.Logger, error) {
	// 配置日志级别
	var level zapcore.Level
	if err := level.UnmarshalText([]byte(cfg.Level)); err != nil {
		level = zapcore.InfoLevel
	}

	// 配置编码器
	encoderConfig := zap.NewProductionEncoderConfig()
	// 自定义时间格式：2026-01-26 22:13:48.123+0800 (空格分隔，带毫秒和时区)
	encoderConfig.EncodeTime = func(t time.Time, enc zapcore.PrimitiveArrayEncoder) {
		enc.AppendString(t.Format("2006-01-02 15:04:05.000-0700"))
	}
	encoderConfig.EncodeLevel = zapcore.LowercaseLevelEncoder

	var encoder zapcore.Encoder
	if cfg.Format == "json" {
		encoder = zapcore.NewJSONEncoder(encoderConfig)
	} else {
		encoder = zapcore.NewConsoleEncoder(encoderConfig)
	}

	maxAge := time.Duration(cfg.MaxAge) * 24 * time.Hour
	if maxAge == 0 {
		maxAge = 30 * 24 * time.Hour // 默认30天
	}

	var cores []zapcore.Core

	// 主日志 core（level+ → server.log + stdout）
	if cfg.File != "" {
		mainWriter, err := newRotateWriter(cfg.File, maxAge)
		if err != nil {
			return nil, err
		}
		mainSyncer := zapcore.NewMultiWriteSyncer(
			zapcore.AddSync(mainWriter),
			zapcore.AddSync(os.Stdout),
		)
		cores = append(cores, zapcore.NewCore(encoder, mainSyncer, level))
	} else {
		cores = append(cores, zapcore.NewCore(encoder, zapcore.AddSync(os.Stdout), level))
	}

	// 错误日志 core（error+ → error.log，独立文件便于排查）
	if cfg.ErrorFile != "" {
		errorWriter, err := newRotateWriter(cfg.ErrorFile, maxAge)
		if err != nil {
			return nil, err
		}
		errorSyncer := zapcore.AddSync(errorWriter)
		cores = append(cores, zapcore.NewCore(encoder, errorSyncer, zapcore.ErrorLevel))
	}

	// 合并 core
	core := zapcore.NewTee(cores...)

	// 创建 logger
	logger := zap.New(core, zap.AddCaller(), zap.AddStacktrace(zapcore.ErrorLevel))

	return logger, nil
}

// newRotateWriter 创建按天轮转的日志写入器
func newRotateWriter(filePath string, maxAge time.Duration) (*rotatelogs.RotateLogs, error) {
	logDir := filepath.Dir(filePath)
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return nil, err
	}

	return rotatelogs.New(
		filePath+".%Y-%m-%d",
		rotatelogs.WithLinkName(filePath),
		rotatelogs.WithMaxAge(maxAge),
		rotatelogs.WithRotationTime(24*time.Hour),
		rotatelogs.WithRotationCount(0),
	)
}
