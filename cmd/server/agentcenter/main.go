// Package main 是 AgentCenter 主程序入口
package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"go.uber.org/zap"

	"github.com/imkerbos/mxsec-platform/internal/server/agentcenter/setup"
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

	// 优雅关闭：先标记关闭状态（跳过离线通知），再停止 gRPC
	services.Logger.Info("正在关闭 AgentCenter...")
	services.TransferService.GracefulShutdown()
	services.GRPCServer.GracefulStop()

	services.Logger.Info("AgentCenter 已关闭")
}

func printVersion() {
	fmt.Println("mxsec-agentcenter version dev")
	fmt.Println("Build time: unknown")
}
