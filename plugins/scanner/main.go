// Package main 是 Scanner Plugin 的主程序入口
// Scanner Plugin 作为 Agent 的子进程运行，通过 Pipe 与 Agent 通信
// 提供 ClamAV + YARA-X 双引擎恶意文件扫描和文件隔离功能
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
	"github.com/imkerbos/mxsec-platform/plugins/scanner/engine"

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

	logger.Info("scanner plugin starting",
		zap.Int("pid", os.Getpid()),
		zap.String("version", buildVersion),
		zap.String("build_time", buildTime))

	// 3. 创建扫描引擎
	scanEngine := engine.NewEngine(logger)

	// 打印依赖可用性状态
	logDependencyStatus(logger)

	// 4. 创建上下文
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 5. 信号处理
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	// 6. 启动任务接收循环
	taskCh := make(chan *bridge.Task, 10)
	go plugins.ReceiveTaskLoop(ctx, client, taskCh, logger)

	logger.Info("scanner plugin initialization completed, entering main loop")

	// 7. 主循环
	for {
		select {
		case <-ctx.Done():
			logger.Info("scanner plugin shutting down")
			return
		case sig := <-sigCh:
			logger.Info("received signal", zap.String("signal", sig.String()))
			cancel()
			return
		case task := <-taskCh:
			if err := handleTask(ctx, task, scanEngine, client, logger); err != nil {
				logger.Error("failed to handle task", zap.Error(err))
			}
		}
	}
}

// handleTask 处理任务
func handleTask(ctx context.Context, task *bridge.Task, scanEngine *engine.Engine, client *plugins.Client, logger *zap.Logger) (err error) {
	defer plugins.RecoverAndLog(logger, "handleTask")()

	logger.Info("received task",
		zap.Int32("data_type", task.DataType),
		zap.String("object_name", task.ObjectName))

	switch task.DataType {
	case engine.DataTypeScanTask: // 7000: 扫描任务
		return handleScanTask(ctx, task, scanEngine, client, logger)
	case engine.DataTypeQuarantineCmd: // 7003: 隔离/删除命令
		return handleQuarantineTask(ctx, task, scanEngine, client, logger)
	default:
		logger.Warn("unknown task type", zap.Int32("data_type", task.DataType))
		return nil
	}
}

// handleScanTask 处理扫描任务
func handleScanTask(ctx context.Context, task *bridge.Task, scanEngine *engine.Engine, client *plugins.Client, logger *zap.Logger) error {
	var req engine.ScanRequest
	if err := json.Unmarshal([]byte(task.Data), &req); err != nil {
		return fmt.Errorf("解析扫描任务失败: %w", err)
	}

	logger.Info("executing scan task",
		zap.String("task_id", req.TaskID),
		zap.String("scan_type", req.ScanType),
		zap.Int("path_count", len(req.Paths)))

	// 执行扫描
	results, err := scanEngine.Scan(ctx, &req)
	if err != nil {
		logger.Error("scan failed", zap.Error(err))
	}

	// 逐条上报结果（DataType 7001）
	for _, result := range results {
		record := &bridge.Record{
			DataType:  engine.DataTypeScanResult,
			Timestamp: time.Now().UnixNano(),
			Data: &bridge.Payload{
				Fields: map[string]string{
					"task_id":     req.TaskID,
					"file_path":   result.FilePath,
					"threat_name": result.ThreatName,
					"threat_type": result.ThreatType,
					"severity":    result.Severity,
					"file_hash":   result.FileHash,
					"file_size":   fmt.Sprintf("%d", result.FileSize),
					"engine":      result.Engine,
					"rule_name":   result.RuleName,
					"detected_at": result.DetectedAt.Format(time.RFC3339),
				},
			},
		}
		if err := client.SendRecord(record); err != nil {
			logger.Error("failed to send scan result", zap.Error(err))
		}
	}

	// 发送任务完成信号（DataType 7002）
	completeRecord := &bridge.Record{
		DataType:  engine.DataTypeScanComplete,
		Timestamp: time.Now().UnixNano(),
		Data: &bridge.Payload{
			Fields: map[string]string{
				"task_id":      req.TaskID,
				"status":       "completed",
				"threat_count": fmt.Sprintf("%d", len(results)),
				"completed_at": time.Now().Format(time.RFC3339),
			},
		},
	}
	if err := client.SendRecord(completeRecord); err != nil {
		logger.Error("failed to send task completion signal", zap.Error(err))
	}

	logger.Info("scan task completed",
		zap.String("task_id", req.TaskID),
		zap.Int("threat_count", len(results)))

	return nil
}

// handleQuarantineTask 处理隔离/删除任务
func handleQuarantineTask(ctx context.Context, task *bridge.Task, scanEngine *engine.Engine, client *plugins.Client, logger *zap.Logger) error {
	var req engine.QuarantineRequest
	if err := json.Unmarshal([]byte(task.Data), &req); err != nil {
		return fmt.Errorf("解析隔离任务失败: %w", err)
	}

	logger.Info("executing quarantine task",
		zap.String("task_id", req.TaskID),
		zap.String("file_path", req.FilePath),
		zap.String("action", req.Action))

	result, err := scanEngine.HandleQuarantine(&req)
	if err != nil {
		logger.Error("quarantine failed", zap.Error(err))
		return err
	}

	// 上报结果（DataType 7004）
	record := &bridge.Record{
		DataType:  engine.DataTypeQuarantineAck,
		Timestamp: time.Now().UnixNano(),
		Data: &bridge.Payload{
			Fields: map[string]string{
				"task_id":         req.TaskID,
				"file_path":       result.FilePath,
				"action":          result.Action,
				"status":          result.Status,
				"quarantine_path": result.QuarantinePath,
				"file_permission": result.FilePermission,
				"file_owner":      result.FileOwner,
				"error_msg":       result.ErrorMsg,
			},
		},
	}
	if err := client.SendRecord(record); err != nil {
		logger.Error("failed to send quarantine result", zap.Error(err))
	}

	return nil
}

// logDependencyStatus 打印扫描引擎依赖的可用性状态
func logDependencyStatus(logger *zap.Logger) {
	pluginDir := os.Getenv("PLUGIN_DIR")
	logger.Info("scanner dependency status",
		zap.String("plugin_dir", pluginDir))

	// 检查 clamscan
	clamav := engine.NewClamAVScanner(logger)
	logger.Info("clamscan availability",
		zap.Bool("available", clamav.Available()))

	// 检查 yr
	yara := engine.NewYARAScanner(logger)
	logger.Info("yr (YARA-X) availability",
		zap.Bool("available", yara.Available()))
}
