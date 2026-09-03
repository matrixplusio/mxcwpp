// Package init 提供 Manager 服务的初始化逻辑
package init

import (
	"net/url"
	"os"
	"strings"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/config"
	"github.com/matrixplusio/mxcwpp/internal/server/database"
	serverLogger "github.com/matrixplusio/mxcwpp/internal/server/logger"
	"github.com/matrixplusio/mxcwpp/internal/server/manager/biz"
	"github.com/matrixplusio/mxcwpp/internal/server/metrics"
	"github.com/matrixplusio/mxcwpp/internal/server/migration"
	"github.com/matrixplusio/mxcwpp/internal/server/prometheus"
)

// ManagerServices 包含 Manager 服务所需的所有组件
type ManagerServices struct {
	Config         *config.Config
	Logger         *zap.Logger
	DB             *gorm.DB
	ScoreCache     *biz.BaselineScoreCache
	MetricsService *biz.MetricsService
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

	// 5.1.0 seed feature flags + retention policies（幂等，已存在不覆盖）
	migration.SeedFeatureFlags(db, logger)
	migration.SeedRetentionPolicies(db, logger)

	// 5.2 初始化基线得分缓存（TTL: 5分钟）
	scoreCache := biz.NewBaselineScoreCache(db, logger, 5*time.Minute)

	// 5.3 初始化 Prometheus 客户端（主机性能监控唯一数据源）
	var prometheusClient *prometheus.Client
	if cfg.Metrics.Prometheus.Enabled {
		queryURL := extractPrometheusQueryURL(cfg, logger)
		if queryURL != "" {
			prometheusClient = prometheus.NewClient(queryURL, cfg.Metrics.Prometheus.Timeout, logger)
			logger.Info("Prometheus 客户端已初始化", zap.String("query_url", queryURL))
		}
	}

	// 5.4 初始化监控数据查询服务（主机性能监控仅使用 Prometheus）
	metricsService := biz.NewMetricsService(db, prometheusClient, nil, logger)

	return &ManagerServices{
		Config:         cfg,
		Logger:         logger,
		DB:             db,
		ScoreCache:     scoreCache,
		MetricsService: metricsService,
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
		_ = s.Logger.Sync()
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
}
