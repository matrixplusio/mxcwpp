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

	"github.com/matrixplusio/mxcwpp/internal/server/alertbus"
	"github.com/matrixplusio/mxcwpp/internal/server/common/gctune"
	"github.com/matrixplusio/mxcwpp/internal/server/common/kafka"
	"github.com/matrixplusio/mxcwpp/internal/server/config"
	"github.com/matrixplusio/mxcwpp/internal/server/consumer"
	consumermetrics "github.com/matrixplusio/mxcwpp/internal/server/consumer/metrics"
	"github.com/matrixplusio/mxcwpp/internal/server/consumer/writer"
	"github.com/matrixplusio/mxcwpp/internal/server/database"
	"github.com/matrixplusio/mxcwpp/internal/server/engine/anomaly"
	"github.com/matrixplusio/mxcwpp/internal/server/engine/baseline"
	"github.com/matrixplusio/mxcwpp/internal/server/engine/rulesync"
	"github.com/matrixplusio/mxcwpp/internal/server/engine/storyline"
	serverLogger "github.com/matrixplusio/mxcwpp/internal/server/logger"
	"github.com/matrixplusio/mxcwpp/internal/server/model"
	"gorm.io/gorm"
)

// readDataSourceFlag 读取 feature_flag.{key} 的 value（mysql/ch）。
// DB 查不到时回落 "mysql" 默认。
func readDataSourceFlag(db *gorm.DB, logger *zap.Logger, key string) string {
	var f model.FeatureFlag
	if err := db.Where("flag_key = ?", key).First(&f).Error; err != nil {
		logger.Warn("feature flag 查询失败，使用 mysql 默认", zap.String("key", key), zap.Error(err))
		return "mysql"
	}
	v := f.Value
	if v != "mysql" && v != "ch" {
		v = "mysql"
	}
	logger.Info("feature flag 已加载", zap.String("key", key), zap.String("value", v))
	return v
}

var (
	configPath = flag.String("config", "", "配置文件路径（默认：./configs/server.yaml）")
	version    = flag.Bool("version", false, "显示版本信息")
)

// buildVersion 由编译时 ldflags 注入
var buildVersion = "dev"

func main() {
	flag.Parse()

	if *version {
		fmt.Printf("mxcwpp-consumer %s\n", buildVersion)
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

	// P3-B: GC 调优
	gctune.Apply("consumer", gctune.ProfileServer, logger)

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

	// 6.1 SIEM 外发出口（可选）
	//
	// 原实现构造了 Forwarder、打印"已启动"，然后从未调用过它——日志说它在跑，
	// 实际一条告警都发不出去。现在统一挂到 alertbus 的外发出口上。
	siemEgress, closeSIEM := alertbus.NewSIEMEgress(logger.Named("siem"),
		cfg.SIEM.Enabled, cfg.SIEM.Protocol, cfg.SIEM.Address, cfg.SIEM.Facility, 0)
	defer closeSIEM()

	// 4.1 告警发布点：Consumer 产出的行为基线偏离经此走通知出口。
	// 未在 alerting.notify_categories 列出的类别不通知，告警仍照常入库。
	alertbus.SetDefault(alertbus.New(db, logger.Named("alertbus"),
		alertbus.FromConfig(cfg.Alerting.NotifyCategories,
			cfg.Alerting.MinSeverity, cfg.Alerting.SuppressWindowMinutes)).
		WithEgress(siemEgress))

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

	// Sprint 2 PR48: 分析模块可选启用 (默认 true 兼容 v1; v2 部署应设 false 由 Engine 服务承担)。
	// 详见 docs/architecture.md §2.3 Consumer 职责: 只做 Kafka -> 存储幂等写入。
	logger.Info("Consumer 仅 writer 路径 (v2 拆分: 检测由 Engine 服务承担)")

	// 6.2 上下文 (后续多个组件需要 ctx 控制生命周期)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 6.3 初始化 BDE 基线引擎（行为检测，支持持久化和冷启动）
	bdeEngine := baseline.NewEngine(db, logger.Named("bde"))
	bdeEngine.StartCheckpoint(ctx.Done())
	// 反馈闭环：周期按 behavior_alerts 的 ignored 率自调各指标阈值倍率。
	bdeEngine.StartTuningReload(ctx)
	logger.Info("BDE 基线引擎已启动")

	// 6.8 初始化攻击故事线引擎（聚合 story_id 标记的事件为攻击叙事）
	storyEngine := storyline.NewEngine(db, logger.Named("storyline"))
	storyEngine.SetClickHouse(chConn)
	// 按 feature_flag.data_source.storyline_events 决定 events 写入目标
	storyEngine.SetEventsTarget(readDataSourceFlag(db, logger, model.FlagDataSourceStorylineEvents))
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
		"mxcwpp-consumer",
		cfg.Kafka.TopicPrefix,
		mysqlWriter,
		chWriter,
		dlqHandler,
		redisClient,
		cfg.Kafka.Consumer.InitialOffset,
		logger,
	)
	if err != nil {
		logger.Fatal("创建 Consumer 路由器失败", zap.Error(err))
	}
	defer router.Close()
	router.SetBDEEngine(bdeEngine)
	router.SetStorylineEngine(storyEngine)

	// 初始化 ML 异常检测引擎（IForest + 关联检测）
	anomalyDet := anomaly.NewDetector(db, chConn, logger.Named("anomaly"))
	// M0 安全模式：从 feature_flag 读取安全模式（缺配置/非法回落 shadow，绝不默认写正式告警），
	// 并校验 anomaly_alerts schema（hit_count/last_seen_at/去重唯一索引）。schema 未就绪时检测器
	// fail-closed（落库模式降级 shadow，只观测不落库），进程仍存活；就绪状态经 /readyz 暴露。
	anomalyDet.SetMode(anomaly.LoadMode(db, logger.Named("anomaly")))
	anomalyDet.VerifySchema()
	// 恢复上次的参照基线。参照必须来自一段未被污染的历史，丢了就再也长不回来；
	// 不恢复的话每次重启都以"无参照"运行，投毒防护静默失效。
	anomalyDet.LoadState()
	// 恢复上次训练出的模型。不恢复的话每次重启都要重新攒样本 + 等一个完整重训周期
	// 才恢复评分能力，这段时间检测器照常运行却什么都发现不了。
	anomalyDet.LoadActiveModel()
	anomalyDet.LoadScoreThreshold(db)
	consumermetrics.RegisterReadiness("anomaly_schema", func() bool {
		return anomalyDet.Status().SchemaReady
	})
	anomalyDet.StartRetrain(ctx.Done())
	router.SetAnomalyDetector(anomalyDet)
	st := anomalyDet.Status()
	logger.Info("ML 异常检测引擎已启动",
		zap.String("mode", string(st.Mode)),
		zap.String("effective_mode", string(st.EffectiveMode)),
		zap.Bool("schema_ready", st.SchemaReady),
		zap.Bool("dns_field_ready", st.DNSFieldReady),
		zap.Bool("reference_baseline_ready", anomalyDet.HasReference()),
	)

	// ML 异常检测器状态指标：启动即初始化一次，随后周期刷新（trained/sample/host 会随消费变化）。
	refreshAnomalyMetrics := func() {
		s := anomalyDet.Status()
		consumermetrics.SetAnomalyStatus(
			string(s.Mode), string(s.EffectiveMode),
			s.SchemaReady, s.DNSFieldReady, s.Trained, s.SampleCount, s.HostCount)
	}
	refreshAnomalyMetrics()
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				// 周期重载安全模式，使 off/shadow 能作为无需重启的线上止血开关。
				// DB 瞬时失败时 LoadMode fail-closed 到 shadow，恢复后下一周期自动重载。
				anomalyDet.SetMode(anomaly.LoadMode(db, logger.Named("anomaly")))
				refreshAnomalyMetrics()
			}
		}
	}()

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

	// 8. 启动消费 (v2 拆分: cel 进程树清理由 Engine 服务管理)
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
