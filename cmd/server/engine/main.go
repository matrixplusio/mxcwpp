// Package main 是 Engine 主程序入口。
//
// Engine 是 v2.0 六微服务架构中的检测分析引擎,职责:
//   - 订阅 Kafka mxcwpp.agent.* (ConsumerGroup B "mxcwpp-engine")
//   - 多层引擎: CEL 规则 + 序列检测 + ONNX ML + Storyline + K8s Audit
//   - 产出 mxcwpp.engine.alert / storyline / feedback
//
// PR67 起: 配置走 viper 统一加载, 仅保留 --config flag。
// 兼容: 老部署 env 直接覆盖, 无 yaml 文件也能起 (走 default + env)。
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

	"gorm.io/driver/mysql"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/common/config"
	"github.com/matrixplusio/mxcwpp/internal/server/common/gctune"
	"github.com/matrixplusio/mxcwpp/internal/server/common/mode"
	"github.com/matrixplusio/mxcwpp/internal/server/common/observability"
	"github.com/matrixplusio/mxcwpp/internal/server/engine"
	"github.com/matrixplusio/mxcwpp/internal/server/engine/celengine"
	"github.com/matrixplusio/mxcwpp/internal/server/engine/storyline"
)

func main() {
	configPath := flag.String("config", "configs/engine.yaml", "path to engine config (viper yaml)")
	flag.Parse()

	cfg, err := config.LoadEngine(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load config: %v\n", err)
		os.Exit(1)
	}

	logger, err := zap.NewProduction()
	if err != nil {
		fmt.Fprintf(os.Stderr, "init logger: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = logger.Sync() }()

	// P3-B: GC + memory limit 调优
	gctune.Apply("engine", gctune.ProfileServer, logger)

	logger.Info("Engine starting",
		zap.String("config", *configPath),
		zap.String("http_addr", cfg.HTTPAddr),
		zap.String("default_mode", cfg.DefaultMode),
		zap.String("version", engine.Version),
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tracerProvider, err := observability.InitTracing(ctx, observability.Config{
		Enabled:        cfg.OTel.Enabled,
		ServiceName:    "engine",
		ServiceVersion: engine.Version,
		Endpoint:       cfg.OTel.Endpoint,
		Insecure:       cfg.OTel.Insecure,
		SampleRate:     cfg.OTel.SampleRate,
	})
	if err != nil {
		logger.Error("OTel 初始化失败, 走 noop", zap.Error(err))
	}
	defer func() { _ = tracerProvider.Shutdown(context.Background()) }()

	server := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           engine.NewHTTPHandler(logger),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		logger.Info("Engine HTTP server listening", zap.String("addr", cfg.HTTPAddr))
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("HTTP server error", zap.Error(err))
		}
	}()

	if len(cfg.Kafka.Brokers) > 0 {
		producer, err := engine.NewAlertProducer(cfg.Kafka.Brokers, cfg.AlertTopic, logger)
		if err != nil {
			logger.Fatal("AlertProducer 初始化失败", zap.Error(err))
		}
		defer func() { _ = producer.Close() }()

		resolver := mode.NewMemoryResolver(mode.Mode(cfg.DefaultMode))

		var stages []engine.Stage
		if cfg.Database.DSN != "" {
			db, err := gorm.Open(mysql.Open(cfg.Database.DSN), &gorm.Config{})
			if err != nil {
				logger.Warn("Engine DB 初始化失败, 跳过 stages", zap.Error(err))
			} else {
				if sqlDB, e := db.DB(); e == nil {
					sqlDB.SetMaxOpenConns(cfg.Database.MaxOpenConns)
					sqlDB.SetMaxIdleConns(cfg.Database.MaxIdleConns)
					if d, perr := time.ParseDuration(cfg.Database.ConnMaxLifetime); perr == nil {
						sqlDB.SetConnMaxLifetime(d)
					}
				}
				celEng, err := celengine.New(db, logger.Named("cel"))
				if err != nil {
					logger.Warn("celengine 初始化失败, 跳过 CelRuleStage", zap.Error(err))
				} else {
					// v2 拆分: AlertGenerator 注入 stage, 命中规则直接 upsert alerts 表.
					alertGen := celengine.NewAlertGenerator(db, logger.Named("alert"))
					stages = append(stages, engine.NewCelRuleStage(celEng, logger).WithAlertGenerator(alertGen))
					stages = append(stages, engine.NewSequenceStage(
						celengine.NewSequenceDetector(celEng, db, nil, logger.Named("seq")),
						logger))
				}
				storyEng := storyline.NewEngine(db, logger.Named("story"))
				stages = append(stages, engine.NewStorylineStage(storyEng, logger))
				// P1-3: DataType 3005 privilege escalation
				stages = append(stages, engine.NewPrivilegeStage(logger))
				// P1-4: DataType 3006 anti-rootkit
				stages = append(stages, engine.NewAntiRootkitStage(logger))
				// PR63 RASP read-only (DataType 4000-4099)
				stages = append(stages, engine.NewRASPStage(logger))
				logger.Info("Engine stages 已注入", zap.Int("stages_count", len(stages)))
			}
		} else {
			logger.Warn("Engine DB DSN 未配置, stages 为空, 仅 noop 跑通管线")
		}

		pipeline := engine.NewPipeline(producer, resolver, stages, logger)

		kc, err := engine.NewKafkaConsumer(cfg.Kafka.Brokers, cfg.Kafka.TopicPrefix, pipeline.Handler(), logger)
		if err != nil {
			logger.Fatal("Kafka consumer 初始化失败", zap.Error(err))
		}
		kc.Start(ctx)
		defer func() { _ = kc.Close() }()

		logger.Info("Engine 检测链路启动",
			zap.String("alert_topic", cfg.AlertTopic),
			zap.String("default_mode", cfg.DefaultMode),
			zap.Strings("brokers", cfg.Kafka.Brokers),
		)
	} else {
		logger.Warn("Kafka brokers 未配置, 跳过检测链路启动")
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	logger.Info("Engine shutting down...")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	_ = server.Shutdown(shutdownCtx)
	logger.Info("Engine stopped")
}
