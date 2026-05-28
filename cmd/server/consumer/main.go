// Package main 是 Consumer 主程序入口
// Consumer 订阅 Kafka Topic，将消息路由写入 MySQL / ClickHouse
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

	goredis "github.com/redis/go-redis/v9"

	"github.com/imkerbos/mxsec-platform/internal/server/common/kafka"
	"github.com/imkerbos/mxsec-platform/internal/server/config"
	"github.com/imkerbos/mxsec-platform/internal/server/consumer"
	"github.com/imkerbos/mxsec-platform/internal/server/consumer/anomaly"
	"github.com/imkerbos/mxsec-platform/internal/server/consumer/baseline"
	"github.com/imkerbos/mxsec-platform/internal/server/consumer/celengine"
	consumermetrics "github.com/imkerbos/mxsec-platform/internal/server/consumer/metrics"
	"github.com/imkerbos/mxsec-platform/internal/server/consumer/rulesync"
	"github.com/imkerbos/mxsec-platform/internal/server/consumer/siem"
	"github.com/imkerbos/mxsec-platform/internal/server/consumer/storyline"
	"github.com/imkerbos/mxsec-platform/internal/server/consumer/writer"
	"github.com/imkerbos/mxsec-platform/internal/server/database"
	serverLogger "github.com/imkerbos/mxsec-platform/internal/server/logger"
)

var (
	configPath = flag.String("config", "", "配置文件路径（默认：./configs/server.yaml）")
	version    = flag.Bool("version", false, "显示版本信息")
)

// buildVersion 由编译时 ldflags 注入
var buildVersion = "dev"

func main() {
	flag.Parse()

	if *version {
		fmt.Printf("mxsec-consumer %s\n", buildVersion)
		return
	}

	// 1. 加载配置
	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "加载配置失败: %v\n", err)
		os.Exit(1)
	}
	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "配置校验失败: %v\n", err)
		os.Exit(1)
	}

	// 2. 初始化日志
	logger, err := serverLogger.Init(cfg.Log)
	if err != nil {
		fmt.Fprintf(os.Stderr, "初始化日志失败: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = logger.Sync() }()

	// 3. 检查 Kafka 是否启用
	if !cfg.Kafka.Enabled {
		logger.Fatal("Consumer 需要 Kafka 支持，但 kafka.enabled=false")
	}

	// 4. 初始化数据库
	db, err := database.Init(cfg.Database, logger, cfg.Log)
	if err != nil {
		logger.Fatal("初始化数据库失败", zap.Error(err))
	}
	defer database.Close()

	// 5. 初始化写入器
	mysqlWriter := writer.NewMySQLWriter(db, logger)

	// 5.1 初始化 ClickHouse（可选，未启用时 chWriter 仍可用但为空操作）
	chConn, err := database.InitClickHouse(cfg.ClickHouse, logger)
	if err != nil {
		logger.Warn("Consumer ClickHouse 初始化失败，跳过指标写入", zap.Error(err))
	} else if chConn != nil {
		defer func() { _ = database.CloseClickHouse() }()
	}
	batchSize := cfg.ClickHouse.BatchSize
	if batchSize <= 0 {
		batchSize = 5000
	}
	flushTimeout := cfg.ClickHouse.FlushTimeout
	if flushTimeout <= 0 {
		flushTimeout = 10 * 1e9 // 10s
	}
	chWriter := writer.NewClickHouseWriter(chConn, batchSize, flushTimeout, logger)
	defer chWriter.Close()

	// 5.1 初始化 Redis（可选，用于 agent:ac: 映射写入）
	var redisClient *goredis.Client
	if rc, err := database.InitRedis(cfg.Redis); err != nil {
		logger.Warn("Consumer Redis 初始化失败，跳过 agent:ac: 映射写入", zap.Error(err))
	} else {
		redisClient = rc
		defer func() { _ = database.CloseRedis() }()
		logger.Info("Consumer Redis 已连接", zap.String("addr", cfg.Redis.Addr))
	}

	// 6. 初始化 DLQ 生产者（复用 Kafka 生产者，带重试）
	var dlqProducer *kafka.AsyncProducer
	for i := 0; i < 10; i++ {
		dlqProducer, err = kafka.NewAsyncProducer(cfg.Kafka, logger)
		if err == nil {
			break
		}
		logger.Warn("初始化 DLQ 生产者失败，稍后重试",
			zap.Int("attempt", i+1),
			zap.Error(err),
		)
		time.Sleep(5 * time.Second)
	}
	if dlqProducer == nil {
		logger.Fatal("初始化 DLQ 生产者失败，已重试 10 次", zap.Error(err))
	}
	defer dlqProducer.Close()

	dlqHandler := consumer.NewDLQHandler(dlqProducer, logger)

	// 6.1 初始化 CEL 规则引擎（可选，失败不阻塞启动）
	var celEng *celengine.Engine
	var alertGen *celengine.AlertGenerator
	if eng, err := celengine.New(db, logger); err != nil {
		logger.Warn("CEL 引擎初始化失败，跳过实时检测", zap.Error(err))
	} else {
		celEng = eng
		alertGen = celengine.NewAlertGenerator(db, logger)
		logger.Info("CEL 引擎已启动", zap.Int("rules", celEng.RuleCount()))
	}

	// 6.2 初始化自动响应执行器（依赖 CEL + Redis，可选）
	var autoResponder *celengine.AutoResponder
	if celEng != nil && redisClient != nil {
		autoResponder = celengine.NewAutoResponder(db, logger)
		forwarder := celengine.NewCommandForwarder(redisClient, logger)
		autoResponder.SetDispatcher(forwarder)
		logger.Info("自动响应执行器已启动")
	}

	// 6.3 初始化端口扫描检测器（依赖 Redis，可选）
	scanDetector := celengine.NewScanDetector(redisClient, db, logger)
	if scanDetector != nil {
		logger.Info("端口扫描检测器已启动")
	}

	// 6.4 初始化序列检测器（依赖 CEL 引擎 + Redis，可选）
	var seqDetector *celengine.SequenceDetector
	if celEng != nil {
		seqDetector = celengine.NewSequenceDetector(celEng, db, redisClient, logger)
		if err := seqDetector.ReloadRules(); err != nil {
			logger.Warn("序列规则加载失败", zap.Error(err))
		} else {
			logger.Info("序列检测器已启动", zap.Int("rules", seqDetector.RuleCount()))
		}
	}

	// 6.5 初始化 SIEM 转发器（可选，未配置时 forwarder 为 nil）
	siemForwarder := siem.NewForwarder(logger, siem.Config{
		Enabled:  cfg.SIEM.Enabled,
		Protocol: cfg.SIEM.Protocol,
		Address:  cfg.SIEM.Address,
		Facility: cfg.SIEM.Facility,
	})
	if siemForwarder != nil {
		defer siemForwarder.Close()
		logger.Info("SIEM 转发器已启动",
			zap.String("address", cfg.SIEM.Address),
			zap.String("protocol", cfg.SIEM.Protocol))
		// 将 SIEM 转发器注入 AlertGenerator
		if alertGen != nil {
			alertGen.SetSIEMForwarder(siemForwarder)
		}
	}

	// 6.6 上下文（后续多个组件需要 ctx 控制生命周期）
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 6.7 初始化 BDE 基线引擎（行为检测，支持持久化和冷启动）
	bdeEngine := baseline.NewEngine(db, logger.Named("bde"))
	bdeEngine.StartCheckpoint(ctx.Done())
	logger.Info("BDE 基线引擎已启动")

	// 6.8 初始化攻击故事线引擎（聚合 story_id 标记的事件为攻击叙事）
	storyEngine := storyline.NewEngine(db, logger.Named("storyline"))
	storyEngine.StartFlush(ctx.Done())
	logger.Info("攻击故事线引擎已启动")

	// 6.9 初始化 Git 规则同步（可选，定期从 Git 仓库同步检测规则）
	if cfg.RuleSync.Enabled {
		syncer := rulesync.New(cfg.RuleSync, db, logger)
		syncer.Start(ctx)
		logger.Info("Git 规则同步已启动",
			zap.String("git_url", cfg.RuleSync.GitURL),
			zap.Duration("interval", cfg.RuleSync.Interval),
		)
	}

	// 7. 创建消费路由器
	router, err := consumer.NewRouter(
		cfg.Kafka.Brokers,
		"mxsec-consumer",
		cfg.Kafka.TopicPrefix,
		mysqlWriter,
		chWriter,
		dlqHandler,
		redisClient,
		celEng,
		alertGen,
		autoResponder,
		scanDetector,
		seqDetector,
		logger,
	)
	if err != nil {
		logger.Fatal("创建 Consumer 路由器失败", zap.Error(err))
	}
	defer router.Close()
	router.SetBDEEngine(bdeEngine)
	router.SetStorylineEngine(storyEngine)

	// 初始化 ML 异常检测引擎（IForest + 关联检测）
	anomalyDet := anomaly.NewDetector(db, logger.Named("anomaly"))
	anomalyDet.StartRetrain(ctx.Done())
	router.SetAnomalyDetector(anomalyDet)
	logger.Info("ML 异常检测引擎已启动")

	// 7.5 启动 Prometheus /metrics HTTP server（与消费循环并行）
	//
	// Consumer 进程独立，需要单独 HTTP 端口暴露指标供 Prometheus 抓取。
	// 默认 :9100；可通过 metrics.consumer_addr 配置项覆盖。
	metricsAddr := ":9100"
	if cfg.Metrics.ConsumerAddr != "" {
		metricsAddr = cfg.Metrics.ConsumerAddr
	}
	// 自暴露 build 元信息（version + PID），monitor.go 通过 PromQL 拉取
	consumermetrics.SetBuildInfo(buildVersion, "")
	go func() {
		if err := consumermetrics.StartHTTPServer(ctx, metricsAddr, logger); err != nil {
			logger.Error("Consumer metrics server 异常退出", zap.Error(err))
		}
	}()

	// 8. 启动消费
	// 启动进程树清理协程
	if celEng != nil {
		celEng.StartCleanup(ctx)
	}

	errCh := make(chan error, 1)
	go func() {
		logger.Info("Consumer 启动",
			zap.Strings("brokers", cfg.Kafka.Brokers),
			zap.String("topic_prefix", cfg.Kafka.TopicPrefix),
		)
		errCh <- router.Run(ctx)
	}()

	// 9. 等待信号或退出
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-quit:
		logger.Info("收到退出信号", zap.String("signal", sig.String()))
		cancel()

		// 等待 ConsumerGroup 完全关闭（带超时）
		shutdownTimer := time.NewTimer(15 * time.Second)
		defer shutdownTimer.Stop()
		select {
		case err := <-errCh:
			if err != nil {
				logger.Warn("Consumer 关闭时出错", zap.Error(err))
			}
		case <-shutdownTimer.C:
			logger.Warn("Consumer 优雅关闭超时，强制退出")
		}
	case err := <-errCh:
		if err != nil {
			logger.Error("Consumer 异常退出", zap.Error(err))
			os.Exit(1)
		}
	}

	logger.Info("Consumer 已停止")
}
