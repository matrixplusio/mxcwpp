// Package main 是 VulnSync 主程序入口。
//
// VulnSync 是 v2.0 六微服务架构中的漏洞情报融合服务,职责:
//   - 定时同步 OS 厂商权威 advisory(RHSA/Rocky/USN/Debian/Alpine/CentOS + 信创 4 源)
//   - 每条 advisory 带 NEVRA + fixed_version + OS gate,推送富 advisory 到 Kafka mxcwpp.vuln.advisory
//   - Manager consumer 消费后用 Matcher 比对主机软件清单写 host_vulnerabilities
//   - Leader Election (避免多副本重复抓取)
//
// 注: OSV/语言包(PURL 驱动)与 NVD/KEV/EPSS 元数据 enrich 仍在 Manager 侧,
// 非时间增量拉取,不归 VulnSync 调度。
//
// 设计文档: docs/architecture.md (VulnSync 节) + docs/vulnsync-migration.md
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
	"gorm.io/driver/mysql"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/common/gctune"
	"github.com/matrixplusio/mxcwpp/internal/server/config"
	"github.com/matrixplusio/mxcwpp/internal/server/vulnsync"
	"github.com/matrixplusio/mxcwpp/internal/server/vulnsync/advisory"
	"github.com/matrixplusio/mxcwpp/internal/server/vulnsync/leader"
	"github.com/matrixplusio/mxcwpp/internal/server/vulnsync/publisher"
)

func main() {
	configPath := flag.String("config", "configs/vulnsync.yaml", "path to vulnsync config")
	httpAddr := flag.String("http", ":8083", "HTTP listen address for /health and /metrics")
	redisAddr := flag.String("redis-addr", "", "Redis 地址 (启用 Leader Election);空时跳过")
	instanceID := flag.String("instance-id", "", "实例唯一 ID (默认 hostname+pid)")
	kafkaBrokers := flag.String("kafka-brokers", "", "Kafka 地址 (启用 Publisher);空时跳过 advisory 推送")
	advisoryTopic := flag.String("advisory-topic", "mxcwpp.vuln.advisory", "advisory 推送 topic")
	enabledSources := flag.String("sources", "", "启用的 source 列表(逗号分隔, 用 advisory Name: rhsa,rocky-apollo,usn,debian-tracker,alpine,centos);留空启用所有")
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

	// 解析 Kafka brokers：优先 --kafka-brokers flag；为空则回退 -config 指向的
	// server.yaml 的 kafka.brokers（与 manager/consumer/engine 同一配置源，单一真源）。
	var brokers []string
	if *kafkaBrokers != "" {
		brokers = strings.Split(*kafkaBrokers, ",")
	} else if cfg, cErr := config.Load(*configPath); cErr != nil {
		logger.Warn("加载 config 失败,无法从 server.yaml 取 kafka.brokers",
			zap.String("config", *configPath), zap.Error(cErr))
	} else if cfg.Kafka.Enabled && len(cfg.Kafka.Brokers) > 0 {
		brokers = cfg.Kafka.Brokers
		logger.Info("从 server.yaml 取得 kafka.brokers", zap.Strings("brokers", brokers))
	}

	// Publisher (Kafka mxcwpp.vuln.advisory)
	var pub *publisher.Publisher
	if len(brokers) > 0 {
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

	// advisory.Source 池（OS 厂商权威源，产 NEVRA 匹配数据）
	enabled := map[string]bool{}
	for _, s := range strings.Split(*enabledSources, ",") {
		if t := strings.TrimSpace(s); t != "" {
			enabled[t] = true
		}
	}
	// fleet-aware 源门控：只同步 fleet 实际存在的 OS 家族对应的源，避免拉/发无意义 advisory
	// （全 RHEL fleet 不拉 debian/ubuntu/alpine）。DB 查失败或 fleet 空时不门控（安全兜底，宁可多拉不漏检）。
	fleetFamilies := loadFleetOSFamilies(*configPath, logger)
	srcs := buildAdvisorySources(enabled, fleetFamilies, logger)

	schedules := []vulnsync.SourceSchedule{
		{Name: "rhsa", Interval: 4 * time.Hour},
		{Name: "rocky-apollo", Interval: 4 * time.Hour},
		{Name: "usn", Interval: 4 * time.Hour},
		{Name: "debian-tracker", Interval: 4 * time.Hour},
		{Name: "alpine", Interval: 4 * time.Hour},
		{Name: "centos", Interval: 6 * time.Hour},
		{Name: "openeuler-sa", Interval: 6 * time.Hour},
		{Name: "anolis-ansa", Interval: 6 * time.Hour},
		{Name: "kylin-sa", Interval: 6 * time.Hour},
		{Name: "uos-sa", Interval: 6 * time.Hour},
	}

	names := make([]string, 0, len(srcs))
	for n := range srcs {
		names = append(names, n)
	}

	sch := vulnsync.NewScheduler(srcs, pub, election, schedules, logger)
	go sch.Run(ctx)
	logger.Info("VulnSync Scheduler started",
		zap.Int("schedules", len(schedules)),
		zap.Strings("registered_sources", names),
	)

	// HTTP server：/health /metrics + /sync(手动触发，绑定 scheduler.TriggerNow)
	server := &http.Server{
		Addr:              *httpAddr,
		Handler:           vulnsync.NewHTTPHandler(logger, func() int { return sch.TriggerNow(ctx) }),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		logger.Info("VulnSync HTTP server listening", zap.String("addr", *httpAddr))
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("HTTP server error", zap.Error(err))
		}
	}()

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

// sourceOSFamilies 记录每个 OS-distro advisory 源服务的 host OS 家族（小写）。
// 用于 fleet-aware 门控：fleet 无对应家族的主机则不同步该源。
var sourceOSFamilies = map[string][]string{
	"rhsa":           {"rhel", "centos", "centos-stream", "rocky", "almalinux", "oraclelinux"},
	"rocky-apollo":   {"rocky", "centos", "centos-stream", "rhel", "almalinux"},
	"centos":         {"centos", "centos-stream"},
	"usn":            {"ubuntu"},
	"debian-tracker": {"debian"},
	"alpine":         {"alpine"},
	"openeuler-sa":   {"openeuler", "anolis", "openanolis"},
	"anolis-ansa":    {"anolis", "openanolis"},
	"kylin-sa":       {"kylin"},
	"uos-sa":         {"uos"},
}

// sourceServesFleet 判断某源服务的 OS 家族是否与 fleet 在场家族有交集。
func sourceServesFleet(sourceName string, fleet map[string]bool) bool {
	fams, ok := sourceOSFamilies[sourceName]
	if !ok {
		// 未登记映射的源（如未来新增）→ 保守放行，避免漏检。
		return true
	}
	for _, f := range fams {
		if fleet[f] {
			return true
		}
	}
	return false
}

// loadFleetOSFamilies 只读查询 hosts 表的 distinct os_family（小写集合）。
// 供 fleet-aware 源门控使用。查询失败返回 nil（调用方据此不门控，安全兜底）。
func loadFleetOSFamilies(configPath string, logger *zap.Logger) map[string]bool {
	cfg, err := config.Load(configPath)
	if err != nil {
		logger.Warn("fleet-aware 门控：加载 config 失败，跳过门控（同步全部源）", zap.Error(err))
		return nil
	}
	db, err := gorm.Open(mysql.Open(cfg.Database.MySQL.DSN()), &gorm.Config{})
	if err != nil {
		logger.Warn("fleet-aware 门控：连接 DB 失败，跳过门控（同步全部源）", zap.Error(err))
		return nil
	}
	sqlDB, _ := db.DB()
	defer func() {
		if sqlDB != nil {
			_ = sqlDB.Close()
		}
	}()
	var families []string
	if err := db.Table("hosts").Distinct().Pluck("os_family", &families).Error; err != nil {
		logger.Warn("fleet-aware 门控：查询 host os_family 失败，跳过门控（同步全部源）", zap.Error(err))
		return nil
	}
	set := make(map[string]bool, len(families))
	for _, f := range families {
		if t := strings.ToLower(strings.TrimSpace(f)); t != "" {
			set[t] = true
		}
	}
	return set
}

// buildAdvisorySources 构造 OS 厂商 advisory 源池。
//
// 优先级：显式 -sources(enabled) 命中 → 直接启用（人工覆盖）；否则走 fleet-aware 门控——
// 仅启用 fleet 实际存在的 OS 家族对应的源。fleetFamilies 为空(DB 查失败) → 不门控，启用全部（兜底）。
//
// 与 advisory.NewCoordinator 的源池对齐（去掉 OSV：OSV 走 PURL/host 驱动，
// 不适合 VulnSync 时间增量调度，仍由 Manager 的语言包扫描负责）。
func buildAdvisorySources(enabled map[string]bool, fleetFamilies map[string]bool, logger *zap.Logger) map[string]advisory.Source {
	all := []advisory.Source{
		advisory.NewRedHatSource(),
		advisory.NewRockySource(),
		advisory.NewUbuntuSource(),
		advisory.NewDebianSource(),
		advisory.NewAlpineSource(),
		advisory.NewCentOSSource(),
		// 信创 OS（当前 stub，Fetch 返空，待对接商业源）
		advisory.NewOpenEulerSource(),
		advisory.NewAnolisSource(),
		advisory.NewKylinSource(),
		advisory.NewUOSSource(),
	}
	explicit := len(enabled) > 0
	gate := len(fleetFamilies) > 0
	out := make(map[string]advisory.Source, len(all))
	var skipped []string
	for _, s := range all {
		name := s.Name()
		switch {
		case explicit:
			// 人工 -sources 覆盖优先
			if enabled[name] {
				out[name] = s
			}
		case gate && !sourceServesFleet(name, fleetFamilies):
			skipped = append(skipped, name)
		default:
			out[name] = s
		}
	}
	if len(skipped) > 0 {
		fleet := make([]string, 0, len(fleetFamilies))
		for f := range fleetFamilies {
			fleet = append(fleet, f)
		}
		logger.Info("fleet-aware 源门控：跳过无对应主机 OS 的源",
			zap.Strings("fleet_os_families", fleet),
			zap.Strings("skipped_sources", skipped))
	}
	return out
}
