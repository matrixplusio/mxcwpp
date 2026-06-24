// Package plugins 提供插件 SDK 公共工具
package plugins

import (
	"context"
	"fmt"
	"runtime/debug"
	"sync/atomic"
	"time"

	"go.uber.org/zap"

	"github.com/matrixplusio/mxcwpp/api/proto/bridge"
)

// maxDeferredTasks 限制延迟投递的 goroutine 数量，防止业务卡住时 goroutine 暴涨
// 取值参考：plugin 业务通道一般 cap 10~100，业务 + 延迟合计不超过 1024 足够吸收尖峰
const maxDeferredTasks int64 = 1024

// ReceiveTaskLoop 接收任务循环（所有插件统一使用）
//
// 关键约束：
//  1. 自动处理 EOF/pipe 关闭、panic 恢复、错误重试。
//  2. ping/pong 在 client.ReceiveTask 内拦截自动回复，主循环必须持续调
//     ReceiveTask 才能让 ping 被消费；否则 agent watchdog（默认 3min）
//     会强杀 plugin，导致 in-memory 任务队列丢失。
//  3. 业务方的 taskCh 满时不能阻塞主循环，否则触发上述死锁。已知历史
//     事故：remediation plugin handlePreCheck 同步跑 60s × 4 阶段，
//     taskCh cap=10 被填满后 ReceiveTask 停摆 → ping 不回 → 强杀 →
//     in-memory 队列丢失 90 条 precheck 任务。
func ReceiveTaskLoop(ctx context.Context, client *Client, taskCh chan<- *bridge.Task, logger *zap.Logger) {
	defer func() {
		if r := recover(); r != nil {
			logger.Error("PANIC in ReceiveTaskLoop",
				zap.Any("panic", r),
				zap.String("stack", string(debug.Stack())))
		}
	}()

	var deferred atomic.Int64

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
			default:
				// 业务 taskCh 满。绝对不能在此阻塞，否则 ping/pong 停摆。
				// 启延迟投递 goroutine 兜底，主循环立即回到 ReceiveTask 接 ping。
				cur := deferred.Add(1)
				if cur > maxDeferredTasks {
					deferred.Add(-1)
					logger.Warn("taskCh saturated and deferred queue full, dropping task",
						zap.Int32("data_type", task.DataType),
						zap.String("token", task.Token),
						zap.Int64("deferred", cur-1))
					continue
				}
				logger.Warn("taskCh full, deferring task delivery",
					zap.Int32("data_type", task.DataType),
					zap.String("token", task.Token),
					zap.Int64("deferred", cur))
				go func(t *bridge.Task) {
					defer deferred.Add(-1)
					select {
					case taskCh <- t:
					case <-ctx.Done():
					}
				}(task)
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
