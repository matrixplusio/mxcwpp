// av-scanner 插件: 反勒索 honeypot + 文件扫描 (Sprint 4 脚手架)
//
// 严格定位 read-only:
//
//	插件本身不会主动 kill 进程或隔离主机。
//	任何反勒索动作 (kill_pid_and_isolate) 都通过上报事件由 Server 决策,
//	并经 6 闸门 (G1-G6) admission 才落地。
//
// 上报 DataType:
//
//	7020  honeypot decoy 命中 (反勒索触发)
//	7030  av scan finding (单条命中)
//	7031  av scan summary (任务汇总)
//	7032  av scan task complete
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
	"github.com/imkerbos/mxsec-platform/plugins/avscanner/engine"
	plugins "github.com/imkerbos/mxsec-platform/plugins/lib/go"
)

var (
	buildVersion = "dev"
	buildTime    = ""
)

func main() {
	client, err := plugins.NewClient()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create plugin client: %v\n", err)
		os.Exit(1)
	}
	defer client.Close()

	logger, err := plugins.NewPluginLogger()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to init logger: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = logger.Sync() }()

	logger.Info("av-scanner plugin starting",
		zap.Int("pid", os.Getpid()),
		zap.String("version", buildVersion),
		zap.String("build_time", buildTime))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	scanner := engine.NewScanner(logger)
	honeypot := engine.NewHoneypotManager(engine.DefaultHoneypotConfig(), logger)
	if err := honeypot.Deploy(); err != nil {
		logger.Warn("honeypot deploy partial", zap.Error(err))
	}

	stopHoneypot := make(chan struct{})
	go honeypot.Run(stopHoneypot)
	go forwardHoneypotTriggers(ctx, honeypot, client, logger)

	taskCh := make(chan *bridge.Task, 10)
	go plugins.ReceiveTaskLoop(ctx, client, taskCh, logger)

	logger.Info("av-scanner plugin initialized, entering main loop",
		zap.Int("decoys_deployed", len(honeypot.Decoys())))

	for {
		select {
		case <-ctx.Done():
			close(stopHoneypot)
			logger.Info("av-scanner plugin shutting down")
			return
		case sig := <-sigCh:
			logger.Info("received signal", zap.String("signal", sig.String()))
			close(stopHoneypot)
			cancel()
			return
		case task := <-taskCh:
			if err := handleTask(ctx, task, scanner, client, logger); err != nil {
				logger.Error("failed to handle task", zap.Error(err))
			}
		}
	}
}

// handleTask 任务路由。
func handleTask(ctx context.Context, task *bridge.Task, scanner *engine.Scanner, client *plugins.Client, logger *zap.Logger) (err error) {
	defer plugins.RecoverAndLog(logger, "handleTask")()

	logger.Info("received task",
		zap.Int32("data_type", task.DataType),
		zap.String("object_name", task.ObjectName))

	switch task.DataType {
	case 7030: // av 扫描请求
		return handleScanTask(ctx, task, scanner, client, logger)
	case 7040: // selfcheck
		return scanner.Selfcheck(ctx, "")
	default:
		logger.Warn("unknown task type", zap.Int32("data_type", task.DataType))
		return nil
	}
}

func handleScanTask(ctx context.Context, task *bridge.Task, scanner *engine.Scanner, client *plugins.Client, logger *zap.Logger) error {
	var req engine.ScanRequest
	if err := json.Unmarshal([]byte(task.Data), &req); err != nil {
		return fmt.Errorf("decode scan request: %w", err)
	}
	if req.TaskID == "" {
		req.TaskID = task.Token
	}

	findings, summary, err := scanner.Scan(ctx, req)
	if err != nil {
		failed := &bridge.Record{
			DataType:  7032,
			Timestamp: time.Now().UnixNano(),
			Data: &bridge.Payload{
				Fields: map[string]string{
					"task_id":       req.TaskID,
					"status":        "failed",
					"error_message": err.Error(),
				},
			},
		}
		_ = client.SendRecord(failed)
		return err
	}

	for _, f := range findings {
		rec := &bridge.Record{
			DataType:  7030,
			Timestamp: time.Now().UnixNano(),
			Data: &bridge.Payload{
				Fields: map[string]string{
					"task_id":  req.TaskID,
					"path":     f.Path,
					"sha256":   f.SHA256,
					"size":     fmt.Sprintf("%d", f.Size),
					"rule":     f.Rule,
					"severity": f.Severity,
					"detail":   f.Detail,
				},
			},
		}
		if err := client.SendRecord(rec); err != nil {
			logger.Error("send finding failed", zap.Error(err))
		}
	}

	summaryRec := &bridge.Record{
		DataType:  7031,
		Timestamp: time.Now().UnixNano(),
		Data: &bridge.Payload{
			Fields: map[string]string{
				"task_id":      req.TaskID,
				"total_files":  fmt.Sprintf("%d", summary.TotalFiles),
				"hit_findings": fmt.Sprintf("%d", summary.HitFindings),
				"errors":       fmt.Sprintf("%d", summary.Errors),
				"started_at":   summary.StartedAt.Format(time.RFC3339),
				"finished_at":  summary.FinishedAt.Format(time.RFC3339),
			},
		},
	}
	if err := client.SendRecord(summaryRec); err != nil {
		logger.Error("send summary failed", zap.Error(err))
	}

	complete := &bridge.Record{
		DataType:  7032,
		Timestamp: time.Now().UnixNano(),
		Data: &bridge.Payload{
			Fields: map[string]string{
				"task_id":      req.TaskID,
				"status":       "completed",
				"completed_at": time.Now().Format(time.RFC3339),
			},
		},
	}
	_ = client.SendRecord(complete)
	logger.Info("av scan task done",
		zap.String("task_id", req.TaskID),
		zap.Int("findings", len(findings)),
		zap.Int("files", summary.TotalFiles))
	return nil
}

// forwardHoneypotTriggers 把诱饵命中事件转成 DataType 7020 上报。
//
// 注意: 插件不阻断 (read-only); 是否 kill PID 由 Server 决策。
func forwardHoneypotTriggers(ctx context.Context, h *engine.HoneypotManager, client *plugins.Client, logger *zap.Logger) {
	for {
		select {
		case <-ctx.Done():
			return
		case trig := <-h.Triggers():
			rec := &bridge.Record{
				DataType:  7020,
				Timestamp: time.Now().UnixNano(),
				Data: &bridge.Payload{
					Fields: map[string]string{
						"decoy_path":  trig.DecoyPath,
						"decoy_type":  string(trig.DecoyKind),
						"operation":   trig.Operation,
						"pid":         fmt.Sprintf("%d", trig.TriggeringPID),
						"exe":         trig.TriggeringExe,
						"uid":         fmt.Sprintf("%d", trig.TriggeringUID),
						"detected_at": trig.Timestamp.Format(time.RFC3339),
					},
				},
			}
			if err := client.SendRecord(rec); err != nil {
				logger.Error("forward honeypot trigger failed", zap.Error(err))
			} else {
				logger.Warn("honeypot trigger reported (read-only, no kill)",
					zap.String("path", trig.DecoyPath),
					zap.Int32("pid", trig.TriggeringPID))
			}
		}
	}
}
