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

	"github.com/matrixplusio/mxcwpp/internal/server/alertbus"
	"github.com/matrixplusio/mxcwpp/internal/server/common/gctune"
	"github.com/matrixplusio/mxcwpp/internal/server/consumer/gcppubsub"
	"github.com/matrixplusio/mxcwpp/internal/server/engine/kube"
	"github.com/matrixplusio/mxcwpp/internal/server/manager/biz"
	"github.com/matrixplusio/mxcwpp/internal/server/manager/router"
	managerscheduler "github.com/matrixplusio/mxcwpp/internal/server/manager/scheduler"
	"github.com/matrixplusio/mxcwpp/internal/server/manager/setup"
	"github.com/matrixplusio/mxcwpp/internal/server/vulnsync/advisory"
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
	gctune.Apply("manager", gctune.ProfileServer, services.Logger)

	// 根 context，用于控制后台 goroutine 生命周期
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 启动 AC 服务发现主动探测
	services.ACRegistry.Start(ctx)

	// 启动 Manager 侧任务调度器（持 Redis 锁，多实例安全）
	go services.TaskScheduler.Start(ctx)

	// 启动病毒库自动更新器
	go services.VirusDBUpdater.Start(ctx)

	// P1-1: 启动配置变更审批 Worker (30s 周期扫 approved → apply)
	configChangeWorker := biz.NewConfigChangeWorker(services.DB, services.Logger, 0)
	go configChangeWorker.Start(ctx)

	// 后台定时任务：排期与上次执行时间都在 scheduled_jobs 表里，控制台可改；
	// 进程重启不重新计时，也不再有「启动即跑」。任务分散在几处登记，全部登记完才 Start（见下方）。
	jobs := managerscheduler.InitJobs(services.DB, services.Logger.Named("jobs"))
	managerscheduler.RegisterBuiltinJobs(jobs, services.DB, services.Logger)
	jobs.Register(managerscheduler.PeriodicJob{
		Key: managerscheduler.JobVulnPrecheck, Name: "漏洞预检巡检",
		Description:          "让有待检漏洞的在线主机用包管理器核对漏洞是否真实存在。逐台串行下发，主机上会执行包查询。",
		TouchesHosts:         true,
		DefaultIntervalHours: 24, DefaultStartHour: 1,
		Timeout: managerscheduler.JobTimeoutPrecheck,
		Run:     func(c context.Context) error { services.PreCheckCron.TickOnce(c); return nil },
	})
	jobs.Register(managerscheduler.PeriodicJob{
		Key: managerscheduler.JobVirusDBCheck, Name: "病毒库检查",
		Description:          "向上游检查病毒特征库有没有新版本，有变化才打包发布。检查本身不触达主机。",
		DefaultIntervalHours: 4, DefaultStartHour: 0,
		Run: func(c context.Context) error { services.VirusDBUpdater.RunOnce(c); return nil },
	})

	// 告警通知统一出口：各服务发布的事件在此匹配渠道、去重、发送、重试并记录投递。
	// 类别灰度、最低等级、抑制窗口只在这里生效（alerting.* 配置以 manager 为准）。
	go alertbus.NewDispatcher(services.DB, services.Logger.Named("notify-dispatcher"),
		alertbus.FromConfig(services.Config.Alerting.NotifyCategories,
			services.Config.Alerting.MinSeverity, services.Config.Alerting.SuppressWindowMinutes)).Run(ctx)

	// 漏洞通报升级调度器 (SLA 检查/升级通知/自动关闭),业务调度归 Manager
	go managerscheduler.StartBulletinEscalationScheduler(services.DB, services.Logger)
	// P2: Incident 关联调度器 (同主机多源信号 → 攻击链事件)
	go managerscheduler.StartIncidentCorrelationScheduler(services.DB, services.Logger)
	// 低频跨资产探测：单主机扫描阈值以下、分散到多台主机或多个地址上的探测。
	go managerscheduler.StartCrossAssetProbeScheduler(services.DB, services.CHConn, services.Logger)
	// 事件响应超时检查：没人读的截止时间只是一列数据。
	go managerscheduler.StartIncidentSLAScheduler(services.DB, services.Logger)
	// 采集中断检测：心跳在、插件数据停了，此前没有任何告警。
	go managerscheduler.StartTelemetryGapScheduler(services.DB, services.Logger)
	// 认证日志采集断流：主机在线、logcollector 心跳停了（插件被停、被杀、卡死）。
	go managerscheduler.StartAuthlogSilenceScheduler(services.DB, services.CHConn, services.Logger)

	// 启动 advisory Kafka consumer：消费 VulnSync 推送的富 advisory，匹配主机写 host_vuln。
	// 取代 manager 进程内 syncCoreAdvisories 自拉路径（拉源已剥离至 VulnSync 服务）。
	if len(services.Config.Kafka.Brokers) > 0 {
		advConsumer, err := biz.NewAdvisoryConsumer(services.Config.Kafka.Brokers, services.DB, services.Logger.Named("advisory-consumer"))
		if err != nil {
			services.Logger.Error("advisory consumer 初始化失败", zap.Error(err))
		} else {
			advConsumer.Start(ctx)
			defer func() { _ = advConsumer.Close() }()
		}
	} else {
		services.Logger.Warn("Kafka brokers 未配置，advisory consumer 未启动")
	}

	// 启动 NVD enrich cron:对 cvss_score=0 / severity=none 的 vulnerability(主要 RHSA/OSV
	// 不提供 NVD CVSS),按 cve_id 单查 NVD JSON 2.0 API 补 score/severity/description。
	// API key 取自 server.yaml 的 vuln.nvd_api_key(可空,空时走 6s 间隔限速)。
	nvdEnricher := advisory.NewNVDEnricher(services.DB, services.Config.Vuln.NVDAPIKey, services.Logger.Named("nvd-enrich"))
	jobs.Register(managerscheduler.PeriodicJob{
		Key: managerscheduler.JobNVDEnrich, Name: "漏洞库补充信息",
		Description:          "为缺少评分和描述的漏洞向 NVD 查询补全。",
		DefaultIntervalHours: 24, DefaultStartHour: 4,
		Timeout: managerscheduler.JobTimeoutNVD,
		Run:     nvdEnricher.RunScheduled,
	})

	// 启动 GCP Pub/Sub 消费者管理器（GKE 审计日志接入，per-cluster 配置）
	alarmService := kube.NewKubeAlarmService(services.DB, services.Logger)
	// 注入 notification 派发器,解耦 engine/kube 反向依赖 manager/biz
	alarmService.SetNotifier(biz.NewKubeAlarmNotifier(services.DB, services.Logger))
	consumerManager := gcppubsub.NewConsumerManager(services.DB, services.Logger, alarmService)
	consumerManager.Start(ctx)

	// 设置路由
	httpRouter := router.Setup(services.DB, services.Logger, services.Config, services.ScoreCache, services.MetricsService, services.ACRegistry, services.ACDispatcher, services.CHConn, services.Redis, services.PrometheusClient, services.VirusDBUpdater, consumerManager)

	// 路由初始化时还会登记依赖其对象的任务（K8s 基线重扫），所以到这里才启动调度。
	go jobs.Start(ctx)

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
	fmt.Println("mxcwpp-manager version dev")
	fmt.Println("Build time: unknown")
}
