// Package setup 提供 Manager 服务的初始化逻辑
package setup

import (
	"net/url"
	"os"
	"strings"
	"time"

	chdriver "github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/imkerbos/mxsec-platform/internal/server/config"
	"github.com/imkerbos/mxsec-platform/internal/server/database"
	serverLogger "github.com/imkerbos/mxsec-platform/internal/server/logger"
	"github.com/imkerbos/mxsec-platform/internal/server/manager/biz"
	"github.com/imkerbos/mxsec-platform/internal/server/manager/sd"
	"github.com/imkerbos/mxsec-platform/internal/server/metrics"
	"github.com/imkerbos/mxsec-platform/internal/server/migration"
	"github.com/imkerbos/mxsec-platform/internal/server/prometheus"
)

// ManagerServices 包含 Manager 服务所需的所有组件
type ManagerServices struct {
	Config           *config.Config
	Logger           *zap.Logger
	DB               *gorm.DB
	Redis            *redis.Client
	CHConn           chdriver.Conn // ClickHouse 连接（可为 nil，未启用时跳过）
	ScoreCache       *biz.BaselineScoreCache
	RedisScoreCache  *biz.BaselineScoreCacheRedis
	MetricsService   *biz.MetricsService
	PrometheusClient *prometheus.Client  // Prometheus 查询客户端（可为 nil）
	ACRegistry       *sd.Registry        // AC 服务发现注册表
	ACDispatcher     *sd.ACDispatcher    // AC 命令分发器
	TaskScheduler    *biz.TaskScheduler  // Manager 侧任务调度器（多实例安全）
	VirusDBUpdater   *biz.VirusDBUpdater // 病毒库自动更新器
}

// Initialize 初始化 Manager 服务的所有组件
func Initialize(configPath string) (*ManagerServices, error) {
	// 1. 加载配置
	cfg, err := config.Load(configPath)
	if err != nil {
		return nil, err
	}

	// 2. 验证配置
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	// 3. 初始化日志
	logger, err := serverLogger.Init(cfg.Log)
	if err != nil {
		return nil, err
	}

	cfg.LogInfo(logger)
	logger.Info("Manager HTTP API Server 启动中...")

	// 4. 初始化 Prometheus 指标
	metrics.Init(logger)

	// 5. 初始化数据库
	db, err := database.Init(cfg.Database, logger, cfg.Log)
	if err != nil {
		logger.Fatal("初始化数据库失败", zap.Error(err))
		return nil, err
	}

	// 5.1 初始化默认数据（策略和规则）
	// policyDir 传空字符串，让 InitDefaultData 自动检测生产/开发环境路径
	if err := migration.InitDefaultData(db, logger, "", &cfg.Plugins); err != nil {
		logger.Warn("初始化默认数据失败", zap.Error(err))
		// 不中断启动，允许后续手动初始化
	}

	// 5.2 初始化 Redis
	var redisClient *redis.Client
	var redisScoreCache *biz.BaselineScoreCacheRedis
	rc, err := database.InitRedis(cfg.Redis)
	if err != nil {
		logger.Warn("Redis 初始化失败，降级为内存缓存", zap.Error(err))
	} else {
		redisClient = rc
		redisScoreCache = biz.NewBaselineScoreCacheRedis(db, logger, database.NewRedisClientAdapter(rc), 5*time.Minute)
		logger.Info("Redis 已连接", zap.String("addr", cfg.Redis.Addr))
	}

	// 5.3 初始化基线得分缓存（内存版，兼容 Redis 未启用时）
	scoreCache := biz.NewBaselineScoreCache(db, logger, 5*time.Minute)

	// 5.4 初始化 Prometheus 客户端（主机性能监控唯一数据源）
	var prometheusClient *prometheus.Client
	if cfg.Metrics.Prometheus.Enabled {
		queryURL := extractPrometheusQueryURL(cfg, logger)
		if queryURL != "" {
			prometheusClient = prometheus.NewClient(queryURL, cfg.Metrics.Prometheus.Timeout, logger)
			logger.Info("Prometheus 客户端已初始化", zap.String("query_url", queryURL))
		}
	}

	// 5.5 初始化 ClickHouse（可选，在 MetricsService 之前，后者需要 chConn）
	chConn, err := database.InitClickHouse(cfg.ClickHouse, logger)
	if err != nil {
		logger.Warn("Manager ClickHouse 初始化失败，Dashboard 指标降级为 0", zap.Error(err))
	}

	// 5.6 初始化监控数据查询服务（主机性能监控仅使用 Prometheus）
	metricsService := biz.NewMetricsService(db, prometheusClient, chConn, logger)

	// 5.7 初始化 AC 服务发现注册表
	acRegistry := sd.NewRegistry(logger)
	if redisClient != nil {
		acRegistry.SetRedisClient(redisClient)
		// 从 Redis 恢复上次注册的 AC 实例（Manager 重启后不丢失已注册的 AC）
		acRegistry.LoadFromRedis()
	}

	// 5.8 初始化 Manager 侧任务调度器
	acDispatcher := sd.NewACDispatcher(acRegistry, redisClient, logger)
	taskScheduler := biz.NewTaskScheduler(db, acDispatcher, redisClient, logger)

	// 5.9 初始化病毒库更新器
	virusDBUpdater := biz.NewVirusDBUpdater(db, redisClient, logger, "./data", "./uploads", cfg.Plugins.BaseURL)

	return &ManagerServices{
		Config:           cfg,
		Logger:           logger,
		DB:               db,
		Redis:            redisClient,
		CHConn:           chConn,
		ScoreCache:       scoreCache,
		RedisScoreCache:  redisScoreCache,
		MetricsService:   metricsService,
		PrometheusClient: prometheusClient,
		ACRegistry:       acRegistry,
		ACDispatcher:     acDispatcher,
		TaskScheduler:    taskScheduler,
		VirusDBUpdater:   virusDBUpdater,
	}, nil
}

// extractPrometheusQueryURL 提取 Prometheus 查询 URL
// 优先使用 query_url，如果没有则从 remote_write_url 提取基础 URL
func extractPrometheusQueryURL(cfg *config.Config, logger *zap.Logger) string {
	queryURL := cfg.Metrics.Prometheus.QueryURL
	if queryURL != "" {
		return queryURL
	}

	// 从 remote_write_url 提取基础 URL
	remoteWriteURL := cfg.Metrics.Prometheus.RemoteWriteURL
	if remoteWriteURL == "" {
		logger.Warn("Prometheus 已启用但未配置查询 URL")
		return ""
	}

	// 解析 URL 并提取基础部分
	parsedURL, err := url.Parse(remoteWriteURL)
	if err == nil {
		// 移除路径部分，只保留 scheme://host:port
		parsedURL.Path = ""
		parsedURL.RawQuery = ""
		return parsedURL.String()
	}

	// 如果解析失败，尝试简单字符串处理
	// 移除 /api/v1/write 后缀
	if strings.HasSuffix(remoteWriteURL, "/api/v1/write") {
		return strings.TrimSuffix(remoteWriteURL, "/api/v1/write")
	}

	return remoteWriteURL
}

// Cleanup 清理资源
func (s *ManagerServices) Cleanup() {
	if s.Logger != nil {
		s.Logger.Sync()
	}
	if s.DB != nil {
		if err := database.Close(); err != nil {
			if s.Logger != nil {
				s.Logger.Error("关闭数据库连接失败", zap.Error(err))
			} else {
				// 如果 logger 已经关闭，使用标准输出
				os.Stderr.WriteString("关闭数据库连接失败: " + err.Error() + "\n")
			}
		}
	}
	if s.Redis != nil {
		if err := database.CloseRedis(); err != nil && s.Logger != nil {
			s.Logger.Error("关闭 Redis 连接失败", zap.Error(err))
		}
	}
	if s.CHConn != nil {
		if err := database.CloseClickHouse(); err != nil && s.Logger != nil {
			s.Logger.Error("关闭 ClickHouse 连接失败", zap.Error(err))
		}
	}
}
