// Package main 是 FIM Plugin 的主程序入口
// FIM Plugin 作为 Agent 的子进程运行，通过 Pipe 与 Agent 通信
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go.uber.org/zap"

	"github.com/imkerbos/mxsec-platform/api/proto/bridge"
	"github.com/imkerbos/mxsec-platform/plugins/fim/engine"
	plugins "github.com/imkerbos/mxsec-platform/plugins/lib/go"
)

// 版本信息（编译时注入）
var (
	buildVersion = "dev"
	buildTime    = ""
)

func main() {
	// 1. 初始化插件客户端
	client, err := plugins.NewClient()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create plugin client: %v\n", err)
		os.Exit(1)
	}
	defer client.Close()

	// 2. 初始化日志
	logger, err := plugins.NewPluginLogger()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to initialize logger: %v\n", err)
		os.Exit(1)
	}
	defer logger.Sync()

	logger.Info("fim plugin starting",
		zap.Int("pid", os.Getpid()),
		zap.String("version", buildVersion),
		zap.String("build_time", buildTime))

	// 3. 创建 FIM 引擎
	fimEngine := engine.NewEngine(logger)

	// 4. 创建上下文
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 5. 信号处理
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	// 6. 启动任务接收循环
	taskCh := make(chan *bridge.Task, 10)
	go plugins.ReceiveTaskLoop(ctx, client, taskCh, logger)

	logger.Info("fim plugin initialized, entering main loop")

	// 7. 主循环
	for {
		select {
		case <-ctx.Done():
			logger.Info("fim plugin shutting down")
			return
		case sig := <-sigCh:
			logger.Info("received signal", zap.String("signal", sig.String()))
			cancel()
			return
		case task := <-taskCh:
			if err := handleTask(ctx, task, fimEngine, client, logger); err != nil {
				logger.Error("failed to handle task", zap.Error(err))
			}
		}
	}
}

// handleTask 处理任务路由
func handleTask(ctx context.Context, task *bridge.Task, fimEngine *engine.Engine, client *plugins.Client, logger *zap.Logger) (err error) {
	defer plugins.RecoverAndLog(logger, "handleTask")()

	logger.Info("received task",
		zap.Int32("data_type", task.DataType),
		zap.String("object_name", task.ObjectName))

	switch task.DataType {
	case 6000: // FIM 检查任务
		return handleFIMCheckTask(ctx, task, fimEngine, client, logger)
	case 6003: // 基线下发（服务端审批后推送）
		return handleBaselineDelivery(task, fimEngine, logger)
	default:
		logger.Warn("unknown task type", zap.Int32("data_type", task.DataType))
		return nil
	}
}

// handleFIMCheckTask 处理 FIM 检查任务
func handleFIMCheckTask(ctx context.Context, task *bridge.Task, fimEngine *engine.Engine, client *plugins.Client, logger *zap.Logger) error {
	startTime := time.Now()

	// 提取 task_id（通过 Token 传递）
	taskID := task.Token

	logger.Info("executing FIM check", zap.String("task_id", taskID))

	// 执行检查
	result, err := fimEngine.Execute(ctx, json.RawMessage(task.Data))

	if err != nil {
		// 发送失败完成信号
		completeRecord := &bridge.Record{
			DataType:  6002,
			Timestamp: time.Now().UnixNano(),
			Data: &bridge.Payload{
				Fields: map[string]string{
					"task_id":       taskID,
					"status":        "failed",
					"error_message": err.Error(),
					"completed_at":  time.Now().Format(time.RFC3339),
				},
			},
		}
		_ = client.SendRecord(completeRecord)
		return fmt.Errorf("FIM 检查失败: %w", err)
	}

	// 首次扫描：上报基线快照供服务端审批
	if result.IsInitialBaseline {
		snapshotJSON, _ := json.Marshal(result.Snapshot)
		snapshotRecord := &bridge.Record{
			DataType:  6004, // FIM 基线快照
			Timestamp: time.Now().UnixNano(),
			Data: &bridge.Payload{
				Fields: map[string]string{
					"task_id":     taskID,
					"policy_id":   result.PolicyID,
					"snapshot":    string(snapshotJSON),
					"entry_count": fmt.Sprintf("%d", len(result.Snapshot)),
				},
			},
		}
		if err := client.SendRecord(snapshotRecord); err != nil {
			logger.Error("failed to send baseline snapshot", zap.Error(err))
		}
		logger.Info("baseline snapshot sent for approval",
			zap.String("policy_id", result.PolicyID),
			zap.Int("entry_count", len(result.Snapshot)))
	}

	// 逐条发送 FIM 事件
	for _, event := range result.Events {
		detailJSON, _ := json.Marshal(event.ChangeDetail)
		record := &bridge.Record{
			DataType:  6001, // FIM 事件
			Timestamp: time.Now().UnixNano(),
			Data: &bridge.Payload{
				Fields: map[string]string{
					"event_id":      event.EventID,
					"task_id":       taskID,
					"file_path":     event.FilePath,
					"change_type":   event.ChangeType,
					"severity":      event.Severity,
					"category":      event.Category,
					"change_detail": string(detailJSON),
					"detected_at":   time.Now().Format(time.RFC3339),
				},
			},
		}
		if err := client.SendRecord(record); err != nil {
			logger.Error("failed to send FIM event", zap.Error(err))
		}
	}

	// 发送完成信号
	runTimeSec := time.Since(startTime).Seconds()
	completeRecord := &bridge.Record{
		DataType:  6002, // FIM 任务完成
		Timestamp: time.Now().UnixNano(),
		Data: &bridge.Payload{
			Fields: map[string]string{
				"task_id":       taskID,
				"status":        "completed",
				"total_entries": fmt.Sprintf("%d", result.Summary.TotalEntries),
				"added_count":   fmt.Sprintf("%d", result.Summary.AddedEntries),
				"removed_count": fmt.Sprintf("%d", result.Summary.RemovedEntries),
				"changed_count": fmt.Sprintf("%d", result.Summary.ChangedEntries),
				"run_time_sec":  fmt.Sprintf("%.1f", runTimeSec),
				"completed_at":  time.Now().Format(time.RFC3339),
			},
		},
	}
	if err := client.SendRecord(completeRecord); err != nil {
		logger.Error("failed to send completion signal", zap.Error(err))
	}

	logger.Info("FIM check completed",
		zap.String("task_id", taskID),
		zap.Int("event_count", len(result.Events)),
		zap.Float64("run_time_sec", runTimeSec))
	return nil
}

// handleBaselineDelivery 处理服务端下发的审批基线
func handleBaselineDelivery(task *bridge.Task, fimEngine *engine.Engine, logger *zap.Logger) error {
	logger.Info("接收服务端下发的审批基线")
	if err := fimEngine.SaveBaseline(json.RawMessage(task.Data)); err != nil {
		return fmt.Errorf("保存基线失败: %w", err)
	}
	logger.Info("审批基线已保存")
	return nil
}
