// Package main 是 EDR Plugin 的主程序入口
// EDR Plugin 作为 Agent 的子进程运行，通过 Pipe 与 Agent 通信
// 基于 Tetragon eBPF 采集内核级安全事件（进程、文件、网络）
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go.uber.org/zap"

	"github.com/imkerbos/mxsec-platform/api/proto/bridge"
	"github.com/imkerbos/mxsec-platform/plugins/edr/engine"

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

	logger.Info("edr plugin starting",
		zap.Int("pid", os.Getpid()),
		zap.String("version", buildVersion),
		zap.String("build_time", buildTime))

	// 3. 创建 Tetragon 客户端
	tetragonClient := engine.NewTetragonClient("", logger)

	// 3.5 快速检测 Tetragon 是否可用
	if !tetragonClient.Available() {
		logger.Error("Tetragon not available (tetra CLI and socket not found)",
			zap.String("socket", engine.DefaultTetragonSock))
		os.Exit(10) // ExitCodeDepUnavailable
	}

	// 4. 创建上下文
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 5. 信号处理
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	// 6. 启动 Tetragon 事件流
	eventCh, err := tetragonClient.EventStream(ctx)
	if err != nil {
		logger.Error("启动 Tetragon 事件流失败", zap.Error(err))
		os.Exit(1)
	}

	logger.Info("edr plugin initialization completed, entering event loop")

	// 6.5 后台 goroutine 读取 Agent Pipe（处理心跳 ping/pong + 任务下发）
	go func() {
		for {
			task, err := client.ReceiveTask()
			if err != nil {
				logger.Warn("pipe read error, edr plugin will exit", zap.Error(err))
				cancel()
				return
			}
			// EDR 暂不处理下发任务，仅靠 ReceiveTask 自动回复心跳
			logger.Debug("received task from agent",
				zap.Int32("data_type", task.DataType),
				zap.String("object", task.ObjectName))
		}
	}()

	// 7. 主循环：消费事件并上报
	for {
		select {
		case <-ctx.Done():
			logger.Info("edr plugin shutting down")
			return
		case sig := <-sigCh:
			logger.Info("received signal", zap.String("signal", sig.String()))
			cancel()
			return
		case event, ok := <-eventCh:
			if !ok {
				logger.Warn("event stream closed")
				if !tetragonClient.Available() {
					os.Exit(10) // 依赖消失
				}
				os.Exit(1) // 临时故障
			}
			if err := handleEvent(event, client, logger); err != nil {
				logger.Error("failed to handle event", zap.Error(err))
			}
		}
	}
}

// handleEvent 处理单个 Tetragon 事件，转换为 Record 并上报
func handleEvent(event *engine.TetragonEvent, client *plugins.Client, logger *zap.Logger) (err error) {
	defer plugins.RecoverAndLog(logger, "handleEvent")()

	// 选择 DataType
	dataType := engine.EventTypeToDataType(event.EventType)

	// 构建 Payload fields
	fields := make(map[string]string)
	fields["event_type"] = event.EventType
	fields["timestamp"] = event.Timestamp.Format(time.RFC3339Nano)

	// 进程信息（所有事件都包含）
	if event.Process != nil {
		fields["pid"] = engine.FormatUint32(event.Process.PID)
		fields["ppid"] = engine.FormatUint32(event.Process.PPID)
		fields["exe"] = event.Process.Exe
		fields["cmdline"] = event.Process.Cmdline
		fields["parent_exe"] = event.Process.ParentExe
		fields["uid"] = engine.FormatUint32(event.Process.UID)
		fields["gid"] = engine.FormatUint32(event.Process.GID)
	}

	// 文件信息（仅文件事件）
	if event.File != nil {
		fields["file_path"] = event.File.Path
		fields["file_flags"] = event.File.Flags
	}

	// 网络信息（仅网络事件）
	if event.Network != nil {
		fields["remote_addr"] = event.Network.RemoteAddr
		fields["remote_port"] = engine.FormatPort(event.Network.RemotePort)
		fields["local_addr"] = event.Network.LocalAddr
		fields["local_port"] = engine.FormatPort(event.Network.LocalPort)
		fields["protocol"] = event.Network.Protocol
	}

	// 构建 Record 并上报
	record := &bridge.Record{
		DataType:  dataType,
		Timestamp: event.Timestamp.UnixNano(),
		Data: &bridge.Payload{
			Fields: fields,
		},
	}

	if err := client.SendRecord(record); err != nil {
		return fmt.Errorf("上报事件失败: %w", err)
	}

	logger.Debug("event reported",
		zap.String("event_type", event.EventType),
		zap.Int32("data_type", dataType))

	return nil
}
