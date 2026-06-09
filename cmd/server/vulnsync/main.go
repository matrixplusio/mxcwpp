// Package main 是 VulnSync 主程序入口。
//
// VulnSync 是 v2.0 六微服务架构中的漏洞情报融合服务,职责:
//   - 定时同步 11+ 外部源(NVD/OSV/RHSA/USN/Debian/Alpine/SUSE/CISA KEV/ExploitDB/CNNVD/EPSS/信创 4 源)
//   - PURL+NEVRA 双索引模型 + 3 级 confidence 仲裁
//   - 推送 advisory 到 Kafka mxsec.vuln.advisory
//   - Leader Election (避免重复抓取)
//
// 设计文档: docs/vulnsync-design.md
package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"go.uber.org/zap"

	"github.com/redis/go-redis/v9"

	"github.com/imkerbos/mxsec-platform/internal/server/common/gctune"
	"github.com/imkerbos/mxsec-platform/internal/server/vulnsync"
	"github.com/imkerbos/mxsec-platform/internal/server/vulnsync/leader"
	"github.com/imkerbos/mxsec-platform/internal/server/vulnsync/publisher"
	"github.com/imkerbos/mxsec-platform/internal/server/vulnsync/sources"
)

func main() {
	configPath := flag.String("config", "configs/vulnsync.yaml", "path to vulnsync config")
	httpAddr := flag.String("http", ":8083", "HTTP listen address for /health and /metrics")
	redisAddr := flag.String("redis-addr", "", "Redis 地址 (启用 Leader Election);空时跳过")
	instanceID := flag.String("instance-id", "", "实例唯一 ID (默认 hostname+pid)")
	kafkaBrokers := flag.String("kafka-brokers", "", "Kafka 地址 (启用 Publisher);空时跳过 advisory 推送")
	advisoryTopic := flag.String("advisory-topic", "mxsec.vuln.advisory", "advisory 推送 topic")
	nvdAPIKey := flag.String("nvd-api-key", "", "NVD API key (留空走 6s 无 key 限速)")
	enabledSources := flag.String("sources", "nvd,osv,cisa_kev,exploitdb,epss,redhat,ubuntu,debian,alpine,suse", "启用的 source 列表(逗号分隔);留空启用所有")
	cnnvdEndpoint := flag.String("cnnvd-endpoint", "", "CNNVD 商业 API 端点 (留空走占位)")
	cnnvdAPIKey := flag.String("cnnvd-api-key", "", "CNNVD 商业 API key")
	flag.Parse()

	logger, err := zap.NewProduction()
	if err != nil {
		fmt.Fprintf(os.Stderr, "init logger: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = logger.Sync() }()

	// P3-B: GC 调优
	gctune.Apply("vulnsync", gctune.ProfileServer, logger)

	logger.Info("VulnSync starting",
		zap.String("config", *configPath),
		zap.String("http_addr", *httpAddr),
		zap.String("version", vulnsync.Version),
	)

	server := &http.Server{
		Addr:              *httpAddr,
		Handler:           vulnsync.NewHTTPHandler(logger),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		logger.Info("VulnSync HTTP server listening", zap.String("addr", *httpAddr))
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("HTTP server error", zap.Error(err))
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Leader Election
	var election *leader.Election
	if *redisAddr != "" {
		id := *instanceID
		if id == "" {
			if h, err := os.Hostname(); err == nil {
				id = fmt.Sprintf("%s-%d", h, os.Getpid())
			} else {
				id = fmt.Sprintf("vulnsync-%d", os.Getpid())
			}
		}
		rdb := redis.NewClient(&redis.Options{Addr: *redisAddr})
		defer func() { _ = rdb.Close() }()
		election = leader.NewElection(rdb, id, leader.Config{}, logger)
		go election.Run(ctx)
		logger.Info("VulnSync Leader Election started",
			zap.String("redis_addr", *redisAddr),
			zap.String("instance_id", id),
		)
	} else {
		logger.Warn("Redis 未配置,单实例模式,跳过 Leader Election")
	}

	// Publisher (Kafka mxsec.vuln.advisory)
	var pub *publisher.Publisher
	if *kafkaBrokers != "" {
		brokers := strings.Split(*kafkaBrokers, ",")
		pub, err = publisher.New(brokers, *advisoryTopic, logger)
		if err != nil {
			logger.Fatal("VulnSync Publisher 初始化失败", zap.Error(err))
		}
		defer func() { _ = pub.Close() }()
		logger.Info("VulnSync Publisher started",
			zap.String("topic", *advisoryTopic),
		)
	} else {
		logger.Warn("Kafka brokers 未配置,advisory 仅写入日志,不推 Topic")
	}

	// Sources Registry
	reg := sources.NewRegistry()
	enabled := map[string]bool{}
	for _, s := range strings.Split(*enabledSources, ",") {
		enabled[strings.TrimSpace(s)] = true
	}

	registerAll(reg, *nvdAPIKey, *cnnvdEndpoint, *cnnvdAPIKey, enabled, logger)

	// Schedules
	schedules := []vulnsync.SourceSchedule{
		{Name: "nvd", Interval: 1 * time.Hour},
		{Name: "osv", Interval: 1 * time.Hour},
		{Name: "cisa_kev", Interval: 6 * time.Hour},
		{Name: "exploitdb", Interval: 6 * time.Hour},
		{Name: "epss", Interval: 24 * time.Hour},
		{Name: "openeuler", Interval: 6 * time.Hour},
		{Name: "anolis", Interval: 6 * time.Hour},
		{Name: "kylin", Interval: 6 * time.Hour},
		{Name: "uos", Interval: 6 * time.Hour},
		{Name: "redhat", Interval: 4 * time.Hour},
		{Name: "ubuntu", Interval: 4 * time.Hour},
		{Name: "debian", Interval: 4 * time.Hour},
		{Name: "alpine", Interval: 4 * time.Hour},
		{Name: "suse", Interval: 4 * time.Hour},
		{Name: "cnnvd", Interval: 24 * time.Hour},
	}

	sch := vulnsync.NewScheduler(reg, pub, election, schedules, logger)
	go sch.Run(ctx)
	logger.Info("VulnSync Scheduler started",
		zap.Int("schedules", len(schedules)),
		zap.Strings("registered_sources", reg.Names()),
	)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	logger.Info("VulnSync shutting down...")

	cancel()
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	_ = server.Shutdown(shutdownCtx)
	logger.Info("VulnSync stopped")
}

func registerAll(reg *sources.Registry, nvdAPIKey, cnnvdEndpoint, cnnvdAPIKey string, enabled map[string]bool, logger *zap.Logger) {
	allEnabled := len(enabled) == 0
	if allEnabled || enabled["nvd"] {
		_ = reg.Register(sources.NewNVDDriver("", nvdAPIKey, 0))
	}
	if allEnabled || enabled["osv"] {
		_ = reg.Register(sources.NewOSVDriver("", 0))
	}
	if allEnabled || enabled["cisa_kev"] {
		_ = reg.Register(sources.NewCISAKEVDriver(0))
	}
	if allEnabled || enabled["exploitdb"] {
		_ = reg.Register(sources.NewExploitDBDriver(0))
	}
	if allEnabled || enabled["epss"] {
		_ = reg.Register(sources.NewEPSSDriver(0))
	}
	if allEnabled || enabled["openeuler"] {
		_ = reg.Register(sources.NewOpenEulerDriver(0))
	}
	if allEnabled || enabled["anolis"] {
		_ = reg.Register(sources.NewAnolisDriver(0))
	}
	if allEnabled || enabled["kylin"] {
		_ = reg.Register(sources.NewKylinDriver(0))
	}
	if allEnabled || enabled["uos"] {
		_ = reg.Register(sources.NewUOSDriver(0))
	}
	if allEnabled || enabled["redhat"] {
		_ = reg.Register(sources.NewRedHatDriver(0))
	}
	if allEnabled || enabled["ubuntu"] {
		_ = reg.Register(sources.NewUbuntuDriver(0))
	}
	if allEnabled || enabled["debian"] {
		_ = reg.Register(sources.NewDebianDriver(0))
	}
	if allEnabled || enabled["alpine"] {
		_ = reg.Register(sources.NewAlpineDriver("", 0))
	}
	if allEnabled || enabled["suse"] {
		_ = reg.Register(sources.NewSUSEDriver(0))
	}
	if allEnabled || enabled["cnnvd"] {
		_ = reg.Register(sources.NewCNNVDDriver(cnnvdEndpoint, cnnvdAPIKey, 0))
	}
	logger.Info("VulnSync sources 注册完成",
		zap.Strings("names", reg.Names()),
	)
}
