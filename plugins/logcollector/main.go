// Package main 是日志采集插件（logcollector）的入口。目前采集系统认证日志，后续的日志来源也加在这个插件里。
// 插件作为 Agent 的子进程运行，通过 Pipe 与 Agent 通信；它只上报数据，不接受任务。
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"

	"go.uber.org/zap"

	"github.com/matrixplusio/mxcwpp/api/proto/bridge"
	plugins "github.com/matrixplusio/mxcwpp/plugins/lib/go"
	"github.com/matrixplusio/mxcwpp/plugins/logcollector/auth"
)

// 版本信息（编译时注入）
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
		fmt.Fprintf(os.Stderr, "failed to initialize logger: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = logger.Sync() }()

	logger.Info("logcollector plugin starting",
		zap.Int("pid", os.Getpid()),
		zap.String("version", buildVersion),
		zap.String("build_time", buildTime))

	// 与 EDR 采集共用 agent 的 CPU 配额，紧张时让它先用。降不下来也照常采集。
	if err := auth.LowerSelfPriority(); err != nil {
		logger.Warn("降低插件优先级失败", zap.Error(err))
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	// 插件不处理任务，但必须一直读任务管道：agent 的心跳 ping 从这里来，
	// 不读就不会回 pong，三分钟后被 agent 当成卡死强杀。
	taskCh := make(chan *bridge.Task, 10)
	go plugins.ReceiveTaskLoop(ctx, client, taskCh, logger)

	var sendFailures atomic.Int64
	send := func(ev *auth.Event) {
		rec := &bridge.Record{
			DataType:  auth.DataTypeAuthEvent,
			Timestamp: ev.Time.UnixNano(),
			Data:      &bridge.Payload{Fields: ev.Fields()},
		}
		if err := client.SendRecord(rec); err != nil {
			// 管道出问题时每条都会失败，逐条打日志只会把磁盘写满。
			if sendFailures.Add(1)%100 == 1 {
				logger.Error("failed to send auth event", zap.Error(err), zap.Int64("failures", sendFailures.Load()))
			}
		}
	}

	collector := auth.NewCollector(logger, os.Getenv("MXCWPP_LOGCOLLECTOR_STATE_DIR"), send)
	go collector.Run(ctx)

	logger.Info("logcollector plugin initialized")
	for {
		select {
		case sig := <-sigCh:
			logger.Info("received signal", zap.String("signal", sig.String()))
			cancel()
			return
		case task := <-taskCh:
			logger.Debug("ignoring task", zap.Int32("data_type", task.DataType))
		}
	}
}
