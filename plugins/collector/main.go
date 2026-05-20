// Package main 是 Collector Plugin 的主程序入口
// Collector Plugin 作为 Agent 的子进程运行，通过 Pipe 与 Agent 通信
// 负责周期性采集主机资产信息（进程、端口、账户等）并上报到 Server
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
	"github.com/imkerbos/mxsec-platform/plugins/collector/engine"
	"github.com/imkerbos/mxsec-platform/plugins/collector/engine/handlers"
	plugins "github.com/imkerbos/mxsec-platform/plugins/lib/go"
)

// 版本信息（编译时注入）
var (
	buildVersion = "dev" // 通过 -ldflags "-X main.buildVersion=x.x.x" 注入
	buildTime    = ""    // 通过 -ldflags "-X main.buildTime=xxx" 注入
)

func main() {
	// 1. 初始化插件客户端（通过 Pipe 与 Agent 通信）
	client, err := plugins.NewClient()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create plugin client: %v\n", err)
		os.Exit(1)
	}
	defer client.Close()

	// 2. 初始化日志（输出到 stderr，由 Agent 重定向到日志文件）
	logger, err := plugins.NewPluginLogger()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to initialize logger: %v\n", err)
		os.Exit(1)
	}
	defer logger.Sync()

	logger.Info("collector plugin starting",
		zap.Int("pid", os.Getpid()),
		zap.String("version", buildVersion),
		zap.String("build_time", buildTime))

	// 3. 创建采集引擎
	collectEngine := engine.NewEngine(client, logger)

	// 4. 注册所有采集器
	// 基础采集器
	collectEngine.RegisterHandler("process", time.Hour, &handlers.ProcessHandler{Logger: logger})
	collectEngine.RegisterHandler("port", time.Hour, &handlers.PortHandler{Logger: logger})
	collectEngine.RegisterHandler("user", 6*time.Hour, &handlers.UserHandler{Logger: logger})

	// 完整采集器
	collectEngine.RegisterHandler("software", 12*time.Hour, &handlers.SoftwareHandler{Logger: logger})
	collectEngine.RegisterHandler("container", 1*time.Hour, &handlers.ContainerHandler{Logger: logger})
	collectEngine.RegisterHandler("app", 6*time.Hour, &handlers.AppHandler{Logger: logger})
	collectEngine.RegisterHandler("network", 6*time.Hour, &handlers.NetInterfaceHandler{Logger: logger})
	collectEngine.RegisterHandler("volume", 6*time.Hour, &handlers.VolumeHandler{Logger: logger})
	collectEngine.RegisterHandler("kmod", 12*time.Hour, &handlers.KmodHandler{Logger: logger})
	collectEngine.RegisterHandler("service", 6*time.Hour, &handlers.ServiceHandler{Logger: logger})
	collectEngine.RegisterHandler("cron", 12*time.Hour, &handlers.CronHandler{Logger: logger})
	collectEngine.RegisterHandler("dep_scan", 12*time.Hour, &handlers.DepScannerHandler{Logger: logger})

	// 5. 创建上下文
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 6. 信号处理
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	// 7. 启动任务接收循环
	taskCh := make(chan *bridge.Task, 10)
	go plugins.ReceiveTaskLoop(ctx, client, taskCh, logger)

	// 8. 启动采集引擎（定时采集）
	go collectEngine.Run(ctx)

	// 9. 主循环：处理任务
	for {
		select {
		case <-ctx.Done():
			logger.Info("collector plugin shutting down")
			return
		case sig := <-sigCh:
			logger.Info("received signal", zap.String("signal", sig.String()))
			cancel()
			return
		case task := <-taskCh:
			if err := handleTask(ctx, task, collectEngine, logger); err != nil {
				logger.Error("failed to handle task", zap.Error(err))
			}
		}
	}
}

// handleTask 处理任务
func handleTask(ctx context.Context, task *bridge.Task, collectEngine *engine.Engine, logger *zap.Logger) error {
	logger.Info("received task",
		zap.Int32("data_type", task.DataType),
		zap.String("object_name", task.ObjectName))

	// 解析任务数据（JSON）
	var taskData map[string]interface{}
	if err := json.Unmarshal([]byte(task.Data), &taskData); err != nil {
		return fmt.Errorf("failed to unmarshal task data: %w", err)
	}

	// 根据任务类型处理
	switch task.DataType {
	case 5050, 5051, 5052, 5053, 5054, 5055, 5056, 5057, 5058, 5059, 5060: // 资产采集任务
		return handleCollectTask(ctx, task, taskData, collectEngine, logger)
	default:
		logger.Warn("unknown task type", zap.Int32("data_type", task.DataType))
		return nil
	}
}

// handleCollectTask 处理资产采集任务
func handleCollectTask(ctx context.Context, task *bridge.Task, taskData map[string]interface{}, collectEngine *engine.Engine, logger *zap.Logger) error {
	// 提取采集类型
	collectType, ok := taskData["type"].(string)
	if !ok {
		return fmt.Errorf("missing type in task data")
	}

	logger.Info("executing collect task", zap.String("type", collectType))

	// 触发对应采集器执行
	if err := collectEngine.CollectOnce(ctx, collectType); err != nil {
		return fmt.Errorf("failed to collect %s: %w", collectType, err)
	}

	logger.Info("collect task completed", zap.String("type", collectType))
	return nil
}
