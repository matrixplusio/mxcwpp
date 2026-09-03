// Package main 是 Engine 主程序入口。
//
// Engine 是 v2.0 六微服务架构中的检测分析引擎,职责:
//   - 订阅 Kafka mxcwpp.agent.* (ConsumerGroup B "mxcwpp-engine")
//   - 多层引擎: CEL 规则 + 序列检测 + ONNX ML + K8s Audit
//   - 产出 mxcwpp.engine.alert / feedback
//
// 攻击故事线(storyline)不在本进程: 聚合与落库由 consumer 进程独占,
// 见 internal/server/engine/capability.go 中 storyline 条目的说明。
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

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/alertbus"
	"github.com/matrixplusio/mxcwpp/internal/server/common/config"
	"github.com/matrixplusio/mxcwpp/internal/server/common/gctune"
	"github.com/matrixplusio/mxcwpp/internal/server/common/mode"
	"github.com/matrixplusio/mxcwpp/internal/server/common/observability"
	"github.com/matrixplusio/mxcwpp/internal/server/engine"
	"github.com/matrixplusio/mxcwpp/internal/server/engine/celengine"
	"github.com/matrixplusio/mxcwpp/internal/server/engine/intrusion"
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
		var stageAlertWriter *engine.StageAlertWriter
		dbDSN := cfg.Database.ResolveDSN()
		if dbDSN != "" {
			db, err := gorm.Open(mysql.Open(dbDSN), &gorm.Config{})
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
				stageAlertWriter = engine.NewStageAlertWriter(db, logger.Named("stage_alert"))

				// SIEM 外发出口：Engine 是检测告警的主要来源，缺了它客户 SIEM 会漏掉大头。
				siemEgress, closeSIEM := alertbus.NewSIEMEgress(logger.Named("siem"),
					cfg.SIEM.Enabled, cfg.SIEM.Protocol, cfg.SIEM.Address, cfg.SIEM.Facility, 0)
				defer closeSIEM()

				// 告警发布点：Engine 产出的 ML 异常经此走通知出口。
				// 未在 alerting.notify_categories 列出的类别不通知，告警仍照常入库。
				alertbus.SetDefault(alertbus.New(db, logger.Named("alertbus"),
					alertbus.FromConfig(cfg.Alerting.NotifyCategories,
						cfg.Alerting.MinSeverity, cfg.Alerting.SuppressWindowMinutes)).
					WithEgress(siemEgress))

				celEng, err := celengine.New(db, logger.Named("cel"))
				if err != nil {
					logger.Warn("celengine 初始化失败, 跳过 CelRuleStage", zap.Error(err))
				} else {
					// 进程树 / 事件追踪器的定期清理。不启动则两者只增不减：
					// EventTracker.Observe 仅淘汰当前正在写的那个 key，其余 key 的
					// 时间戳永久驻留；ProcessTree 同理。堆对象随运行时长单调增长，
					// 每轮 GC 都要 mark 全部存活对象，最终表现为 CPU 高而日志安静。
					celEng.StartCleanup(ctx)

					// v2 拆分: AlertGenerator 注入 stage, 命中规则直接 upsert alerts 表.
					alertGen := celengine.NewAlertGenerator(db, logger.Named("alert"))
					// P2-B: 周期 reload DB 告警白名单(自动调优采纳的 exception),原子快照零锁读热路径
					alertGen.StartWhitelistReload(ctx)
					// 周期 reload 主机 created_at 快照,消除 hostInGrace 每事件 DB 查(engine CPU 高根因)
					alertGen.StartHostGraceReload(ctx)
					// 周期 reload 资产权重 / 关联度快照,消除 computeRiskScore 每事件两次 DB 查(engine CPU 高根因)
					alertGen.StartRiskCacheReload(ctx)
					stages = append(stages, engine.NewCelRuleStage(celEng, logger).WithAlertGenerator(alertGen))
					seqDetector := celengine.NewSequenceDetector(celEng, db, nil, logger.Named("seq"))
					if err := seqDetector.ReloadRules(); err != nil {
						logger.Warn("序列规则加载失败", zap.Error(err))
					}
					seqDetector.StartReload(ctx)
					stages = append(stages, engine.NewSequenceStage(seqDetector, logger).WithAlertGenerator(alertGen))

					// 服务端 IOC 匹配(网络事件外联 IP / hash / URL 对情报集匹配),不依赖给 agent 下发 IOC
					iocMatcher := celengine.NewIOCMatcher(db, logger.Named("ioc"))
					if err := iocMatcher.Reload(); err != nil {
						logger.Warn("IOC 匹配集加载失败", zap.Error(err))
					}
					iocMatcher.StartReload(ctx)
					stages = append(stages, engine.NewIOCStage(iocMatcher, alertGen, logger))

					// 入站端口扫描聚合检测(ScanDetector,需 Redis 做源IP×窗口滑动计数)。
					// 激活此前未接线的 ScanDetector：按聚合判扫描替代"单入站连接即告警"的旧规则。
					// 未配 Redis(addr 空)则跳过(NewScanDetector 对 nil 返回 nil，ScanStage 安全 no-op)。
					if cfg.Redis.Addr != "" {
						rdb := redis.NewClient(&redis.Options{
							Addr:     cfg.Redis.Addr,
							Password: cfg.Redis.Password,
							DB:       cfg.Redis.DB,
						})
						if scanDet := celengine.NewScanDetector(rdb, db, logger.Named("scan")); scanDet != nil {
							scanDet.StartWhitelistReload(ctx)
							stages = append(stages, engine.NewScanStage(scanDet, logger))
						}
					}
				}
				// storyline 聚合由 consumer 进程独占（cmd/server/consumer/main.go）。
				// engine 曾在此再建一个 storyline.Engine，但从不调 StartFlush：
				// 事件只进内存 map（上限 10000 story × 500 pendingEvts），永不落库、
				// 不产 Alert、不推 Kafka —— 纯内存占用。已移除。
				// P1-3: DataType 3005 privilege escalation
				stages = append(stages, engine.NewPrivilegeStage(logger))
				// P1-4: DataType 3006 anti-rootkit
				stages = append(stages, engine.NewAntiRootkitStage(logger))
				// PR63 RASP read-only (DataType 4000-4099)
				stages = append(stages, engine.NewRASPStage(logger))

				// 入侵检测：逐个接线，按误报风险从低到高。
				// 每个都先用标注语料的正常样本验证过零误命中
				// （见 internal/server/engine/intrusion/corpus_fp_test.go）。
				//
				// rootkit：LKM / LD_PRELOAD / cron / systemd / root 授权密钥。
				// 已排除包管理器写 systemd 与 cron 的常规行为。
				stages = append(stages, engine.NewRootkitStage(nil, logger))
				// reverse_shell：bash /dev/tcp、nc -e、解释器反连等已知形态。
				stages = append(stages, engine.NewReverseShellStage(nil, logger))
				// priv_escalation：已验证不把日常 sudo 当信号。
				stages = append(stages, engine.NewPrivEscalationStage(nil, logger))
				// brute_force：5 分钟窗口内 5 次失败才告警，成功登录清零计数，
				// 用户输错一次密码不会触发。
				stages = append(stages, engine.NewBruteForceStage(nil, logger))
				// webshell：文件内容特征匹配，正常语料零误命中。
				stages = append(stages, engine.NewWebshellStage(nil, logger))
				// abnormal_login：每主机学习期（7 天且 ≥10 次登录）内静默喂画像，
				// 画像落 host_login_profile_states，重启后接着用，学习期不重来。
				// 学习期是静默的，指标必须一起接，否则「正常」和「没生效」看起来一样。
				loginDet := intrusion.NewAbnormalLoginDetectorWithStore(db, logger.Named("abnormal_login"))
				loginDet.LoadFromDB()
				loginDet.StartCheckpoint(ctx, 0)
				if err := loginDet.RegisterMetrics(nil); err != nil {
					logger.Warn("异常登录学习期指标注册失败", zap.Error(err))
				}
				stages = append(stages, engine.NewAbnormalLoginStage(loginDet, logger))

				logger.Info("Engine stages 已注入", zap.Int("stages_count", len(stages)))
			}
		} else {
			logger.Warn("Engine DB DSN 未配置, stages 为空, 仅 noop 跑通管线")
		}

		// 注入 Stage 告警落库器：Privilege / RASP / AntiRootkit 等不自带落库的 Stage
		// 此前只把告警推到 mxcwpp.engine.alert，而该 topic 无消费者——检测在跑但界面
		// 永远看不到。alertWriter 为 nil（未配 DB）时保持原行为。
		pipeline := engine.NewPipeline(producer, resolver, stages, logger).
			WithStageAlertWriter(stageAlertWriter)

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
