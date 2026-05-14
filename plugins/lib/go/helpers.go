// Package plugins 提供插件 SDK 公共工具
package plugins

import (
	"context"
	"fmt"
	"runtime/debug"
	"time"

	"go.uber.org/zap"

	"github.com/imkerbos/mxsec-platform/api/proto/bridge"
)

// ReceiveTaskLoop 接收任务循环（所有插件统一使用）
// 自动处理 EOF/pipe 关闭、panic 恢复、错误重试
// pipe 关闭时会 close(taskCh) 通知调用方
func ReceiveTaskLoop(ctx context.Context, client *Client, taskCh chan<- *bridge.Task, logger *zap.Logger) {
	defer func() {
		if r := recover(); r != nil {
			logger.Error("PANIC in ReceiveTaskLoop",
				zap.Any("panic", r),
				zap.String("stack", string(debug.Stack())))
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return
		default:
			task, err := client.ReceiveTask()
			if err != nil {
				errMsg := err.Error()
				if errMsg == "EOF" || errMsg == "io: read/write on closed pipe" {
					logger.Warn("pipe closed, plugin will exit", zap.Error(err))
					return
				}
				logger.Error("failed to receive task, will retry",
					zap.Error(err),
					zap.String("error_type", fmt.Sprintf("%T", err)))
				time.Sleep(time.Second)
				continue
			}

			select {
			case taskCh <- task:
			case <-ctx.Done():
				return
			}
		}
	}
}

// RecoverAndLog 通用 panic 恢复函数，用于 goroutine 的 defer
// 用法: defer plugins.RecoverAndLog(logger, "handleTask")()
func RecoverAndLog(logger *zap.Logger, funcName string) func() {
	return func() {
		if r := recover(); r != nil {
			logger.Error(fmt.Sprintf("PANIC in %s", funcName),
				zap.Any("panic", r),
				zap.String("stack", string(debug.Stack())))
		}
	}
}
