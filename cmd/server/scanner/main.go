// Package main 是独立镜像扫描服务入口。
//
// Scanner 从 scan_jobs 队列认领任务，调用 trivy 扫描镜像，结果写回
// image_scans / image_vulnerabilities。与 manager 解耦（manager 只入队，
// 不跑 trivy），可多副本水平扩展。容器镜像需自带 trivy 二进制。
//
// 设计文档: docs/image-scan-extension-design.md
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

	"github.com/matrixplusio/mxcwpp/internal/server/common/gctune"
	"github.com/matrixplusio/mxcwpp/internal/server/config"
	"github.com/matrixplusio/mxcwpp/internal/server/database"
	"github.com/matrixplusio/mxcwpp/internal/server/scanner"
)

func main() {
	configPath := flag.String("config", "", "配置文件路径（默认：./configs/server.yaml）")
	trivyPath := flag.String("trivy-path", "trivy", "trivy 二进制路径")
	workerID := flag.String("id", "", "worker 实例 ID（默认 hostname-pid）")
	httpAddr := flag.String("http", ":8085", "HTTP /health 监听地址")
	flag.Parse()

	logger, err := zap.NewProduction()
	if err != nil {
		fmt.Fprintf(os.Stderr, "init logger: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = logger.Sync() }()

	gctune.Apply("scanner", gctune.ProfileServer, logger)

	cfg, err := config.Load(*configPath)
	if err != nil {
		logger.Fatal("加载配置失败", zap.Error(err))
	}
	db, err := database.Init(cfg.Database, logger, cfg.Log)
	if err != nil {
		logger.Fatal("连接数据库失败", zap.Error(err))
	}
	defer database.Close()

	id := *workerID
	if id == "" {
		host, _ := os.Hostname()
		id = fmt.Sprintf("%s-%d", host, os.Getpid())
	}

	// health 端点
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	healthSrv := &http.Server{Addr: *httpAddr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		if e := healthSrv.ListenAndServe(); e != nil && e != http.ErrServerClosed {
			logger.Warn("health server 退出", zap.Error(e))
		}
	}()

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	logger.Info("Scanner 服务启动", zap.String("id", id), zap.String("trivy", *trivyPath))
	w := scanner.NewWorker(db, logger, *trivyPath, id)
	w.Run(ctx)

	_ = healthSrv.Close()
	logger.Info("Scanner 服务已退出")
}
