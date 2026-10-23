// Package main 是 AgentCenter 主程序入口
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go.uber.org/zap"

	"github.com/matrixplusio/mxcwpp/internal/server/agentcenter/setup"
	"github.com/matrixplusio/mxcwpp/internal/server/common/gctune"
)

var (
	configPath = flag.String("config", "", "配置文件路径（默认：./configs/server.yaml）")
	version    = flag.Bool("version", false, "显示版本信息")
)

func main() {
	flag.Parse()

	if *version {
		printVersion()
		return
	}

	// 初始化所有服务组件
	services, err := setup.Initialize(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "初始化失败: %v\n", err)
		os.Exit(1)
	}
	defer services.Cleanup()

	// P3-B: GC + 内存上限调优
	gctune.Apply("agentcenter", gctune.ProfileServer, services.Logger)

	// 启动后台服务（任务调度器和状态更新器）
	services.StartBackgroundServices()

	services.Logger.Info("AgentCenter 启动成功", zap.String("address", services.Config.Server.GRPC.Address()))

	// 启动 gRPC Server（goroutine）
	go func() {
		if err := services.GRPCServer.Serve(services.Listener); err != nil {
			services.Logger.Fatal("gRPC Server 启动失败", zap.Error(err))
		}
	}()

	// 信号处理
	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, syscall.SIGTERM, syscall.SIGINT)

	services.Logger.Info("AgentCenter 运行中，等待关闭信号...")

	// 等待信号
	sig := <-signalCh
	services.Logger.Info("收到关闭信号", zap.String("signal", sig.String()))

	// 优雅关闭：先分批排空（多实例时 agent 转去别的实例；单实例时等同逐批断开、重启后自动重连），
	// 再标记关闭并停止 gRPC。GracefulStop 会一直等长连接结束，而 agent 的流不会自己结束，
	// 所以给它限时，超时就硬停——此前的表现是被 docker 停止超时强杀。
	services.Logger.Info("正在关闭 AgentCenter...")
	drainCtx, drainCancel := context.WithTimeout(context.Background(), shutdownDrainBudget)
	services.TransferService.Drain(drainCtx, shutdownDrainBatch, shutdownDrainInterval)
	drainCancel()
	services.TransferService.GracefulShutdown()
	stopped := make(chan struct{})
	go func() {
		services.GRPCServer.GracefulStop()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(10 * time.Second):
		services.GRPCServer.Stop()
	}

	services.Logger.Info("AgentCenter 已关闭")
}

// 停机排空参数。容器的停止宽限期（compose stop_grace_period）必须大于
// shutdownDrainBudget + 10s，否则排空没走完就被强杀。
const (
	shutdownDrainBatch    = 50
	shutdownDrainInterval = time.Second
	shutdownDrainBudget   = 45 * time.Second
)

func printVersion() {
	fmt.Println("mxcwpp-agentcenter version dev")
	fmt.Println("Build time: unknown")
}
