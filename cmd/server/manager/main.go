// Package main 是 Manager HTTP API Server 主程序入口
package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go.uber.org/zap"

	"github.com/imkerbos/mxsec-platform/internal/server/consumer/gcppubsub"
	"github.com/imkerbos/mxsec-platform/internal/server/manager/biz"
	"github.com/imkerbos/mxsec-platform/internal/server/manager/router"
	"github.com/imkerbos/mxsec-platform/internal/server/manager/setup"
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

	// 根 context，用于控制后台 goroutine 生命周期
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 启动 AC 服务发现主动探测
	services.ACRegistry.Start(ctx)

	// 启动 Manager 侧任务调度器（持 Redis 锁，多实例安全）
	go services.TaskScheduler.Start(ctx)

	// 启动病毒库自动更新器
	go services.VirusDBUpdater.Start(ctx)

	// 启动 pre-check 周期巡检（每 6h 对 unpatched + 未检/过期的 host_vuln 自动 pre-check）
	go services.PreCheckCron.Run(ctx)

	// 启动漏洞扫描定时调度器
	vulnScanner := biz.NewVulnScanner(services.DB, services.Logger)
	scanScheduler := biz.NewScanScheduler(services.DB, services.Logger, vulnScanner)
	go func() {
		if err := scanScheduler.Start(); err != nil {
			services.Logger.Error("漏洞扫描调度器启动失败", zap.Error(err))
		}
	}()
	defer scanScheduler.Stop()

	// 启动 GCP Pub/Sub 消费者管理器（GKE 审计日志接入，per-cluster 配置）
	alarmService := biz.NewKubeAlarmService(services.DB, services.Logger)
	consumerManager := gcppubsub.NewConsumerManager(services.DB, services.Logger, alarmService)
	consumerManager.Start(ctx)

	// 设置路由
	httpRouter := router.Setup(services.DB, services.Logger, services.Config, services.ScoreCache, services.MetricsService, services.ACRegistry, services.ACDispatcher, services.CHConn, services.Redis, services.PrometheusClient, services.VirusDBUpdater, consumerManager)

	// 创建 HTTP Server
	server := &http.Server{
		Addr:         services.Config.Server.HTTP.Address(),
		Handler:      httpRouter,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	services.Logger.Info("Manager HTTP API Server 启动成功", zap.String("address", services.Config.Server.HTTP.Address()))

	// 启动服务器（goroutine）
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			services.Logger.Fatal("HTTP Server 启动失败", zap.Error(err))
		}
	}()

	// 信号处理
	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, syscall.SIGTERM, syscall.SIGINT)

	services.Logger.Info("Manager HTTP API Server 运行中，等待关闭信号...")
	sig := <-signalCh
	services.Logger.Info("收到关闭信号", zap.String("signal", sig.String()))

	// 优雅关闭 HTTP Server
	cancel()
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		services.Logger.Error("HTTP Server 关闭异常", zap.Error(err))
	}
	services.Logger.Info("Manager HTTP API Server 已关闭")
}

func printVersion() {
	fmt.Println("mxsec-manager version dev")
	fmt.Println("Build time: unknown")
}
