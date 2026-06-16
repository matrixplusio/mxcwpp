// Package router 提供 HTTP 路由配置
package router

import (
	"strings"

	chdriver "github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/imkerbos/mxsec-platform/internal/server/common/mode"
	"github.com/imkerbos/mxsec-platform/internal/server/common/tenant"
	"github.com/imkerbos/mxsec-platform/internal/server/config"
	"github.com/imkerbos/mxsec-platform/internal/server/consumer/gcppubsub"
	"github.com/imkerbos/mxsec-platform/internal/server/engine/kube"
	"github.com/imkerbos/mxsec-platform/internal/server/manager/api"
	"github.com/imkerbos/mxsec-platform/internal/server/manager/biz"
	"github.com/imkerbos/mxsec-platform/internal/server/manager/biz/mssp"
	"github.com/imkerbos/mxsec-platform/internal/server/manager/middleware"
	"github.com/imkerbos/mxsec-platform/internal/server/manager/sd"
	"github.com/imkerbos/mxsec-platform/internal/server/metrics"
	"github.com/imkerbos/mxsec-platform/internal/server/prometheus"
)

// Setup 设置并返回配置好的 Gin 路由引擎
func Setup(db *gorm.DB, logger *zap.Logger, cfg *config.Config, scoreCache *biz.BaselineScoreCache, metricsService *biz.MetricsService, acRegistry *sd.Registry, acDispatcher *sd.ACDispatcher, chConn chdriver.Conn, redisClient *redis.Client, promClient *prometheus.Client, virusDBUpdater *biz.VirusDBUpdater, consumerManager *gcppubsub.ConsumerManager) *gin.Engine {
	// 设置 Gin 模式
	if cfg.Log.Level == "debug" {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.New()

	// 中间件
	router.Use(middleware.Logger(logger))
	router.Use(gin.Recovery())
	router.Use(middleware.Prometheus()) // 记录 HTTP QPS + 延迟到 mxsec_http_requests_total/duration
	router.Use(middleware.CORS(cfg.Server.CORSOrigins))

	// 批4: 安全响应头（默认关，灰度开）。HSTS 需全站 HTTPS，否则会锁死 http 访问。
	if cfg.Server.Security.Headers.Enabled {
		router.Use(middleware.SecurityHeaders(cfg.Server.Security.Headers.HSTS, cfg.Server.Security.Headers.CSP))
		logger.Info("安全响应头已启用", zap.Bool("hsts", cfg.Server.Security.Headers.HSTS))
	}

	// 健康检查（支持 GET 和 HEAD 方法，Docker healthcheck 可能使用 HEAD）
	healthHandler := api.NewHealthHandler(db, logger)
	router.GET("/health", healthHandler.Health)
	router.HEAD("/health", healthHandler.Health)

	// Prometheus metrics 端点（可选 BasicAuth 保护）
	// 跳过未替换的模板占位符（如 __METRICS_BASIC_AUTH_USER__），防 Prom self-scrape 401
	metricsHandler := gin.WrapH(metrics.Handler())
	basicAuthEnabled := cfg.Metrics.BasicAuthUser != "" &&
		cfg.Metrics.BasicAuthPassword != "" &&
		!strings.HasPrefix(cfg.Metrics.BasicAuthUser, "__") &&
		!strings.HasPrefix(cfg.Metrics.BasicAuthPassword, "__")
	if basicAuthEnabled {
		metricsAuth := gin.BasicAuth(gin.Accounts{
			cfg.Metrics.BasicAuthUser: cfg.Metrics.BasicAuthPassword,
		})
		router.GET("/metrics", metricsAuth, metricsHandler)
	} else {
		router.GET("/metrics", metricsHandler)
	}

	// Agent 安装脚本路由（不需要认证）
	agentHandler := api.NewAgentHandler(logger, cfg.Server.GRPC.Address(), cfg.Server.HTTP.Address())
	router.GET("/agent/install.sh", agentHandler.InstallScript)
	router.GET("/agent/uninstall.sh", agentHandler.UninstallScript)

	// 插件下载路由（不需要认证，Agent 直接下载）
	// 注意：现在由 componentsHandler 统一处理
	componentsHandler := api.NewComponentsHandler(db, logger, cfg, "./uploads", "/uploads")
	router.GET("/api/v1/plugins/download/:name", componentsHandler.DownloadPluginPackage)
	router.HEAD("/api/v1/plugins/download/:name", componentsHandler.DownloadPluginPackage)

	// Agent 安装包下载路由（不需要认证，安装脚本直接下载）
	router.GET("/api/v1/agent/download/:pkg_type/:arch", componentsHandler.DownloadAgentPackage)

	// Agent 更新检查路由（不需要认证，Agent CLI 直接调用）
	router.GET("/api/v1/agent/update-check", componentsHandler.CheckAgentUpdate)

	// 第三方依赖包下载路由（不需要认证，Agent 直接下载）
	router.GET("/api/v1/dependency/download/:name", componentsHandler.DownloadDependencyPackage)
	router.HEAD("/api/v1/dependency/download/:name", componentsHandler.DownloadDependencyPackage)

	// 静态文件服务（用于访问上传的 Logo 等文件，禁止目录列出）
	router.StaticFS("/uploads", gin.Dir("./uploads", false))

	// K8s Audit Webhook（不需要认证，apiserver 通过 cluster_token 鉴权）
	alarmService := kube.NewKubeAlarmService(db, logger)
	auditHandler := api.NewKubeAuditHandler(db, logger, alarmService)
	router.POST("/api/v1/kube/audit-webhook/:cluster_token", auditHandler.ReceiveAuditWebhook)

	// AC 内部注册接口（不需要 JWT，AC 到 Manager 的内部调用）
	discoveryHandler := api.NewDiscoveryHandler(acRegistry, logger)
	internalAC := router.Group("/api/v1/internal/ac")
	if secret := cfg.Server.InternalSecret; secret != "" {
		internalAC.Use(middleware.InternalAuth(secret))
	}
	internalAC.POST("/register", discoveryHandler.Register)
	internalAC.POST("/heartbeat", discoveryHandler.Heartbeat)
	internalAC.DELETE("/deregister", discoveryHandler.Deregister)

	// Prometheus 告警 webhook（不走 JWT，仅可选 X-Internal-Secret 鉴权 + Prom IP 白名单）
	// 接收 Prometheus alerting 配置中 webhook 推送的告警，入 mxsec alerts 表
	promAlertsHandler := api.NewPrometheusAlertsHandler(db, logger)
	internalAlerts := router.Group("/api/v1/internal/alerts")
	if secret := cfg.Server.InternalSecret; secret != "" {
		internalAlerts.Use(middleware.InternalAuth(secret))
	}
	internalAlerts.POST("/prometheus", promAlertsHandler.Ingest)

	// API 路由
	apiV1 := router.Group("/api/v1")

	// API 健康检查（用于前端获取版本信息）
	apiV1.GET("/health", healthHandler.Health)
	apiV1.GET("/system/version", healthHandler.Version)

	// 认证相关路由（不需要认证）
	jwtSecret := cfg.Server.JWTSecret
	if len(jwtSecret) < 32 {
		logger.Fatal("JWT 密钥未配置或长度不足: 请在配置文件中设置 server.jwt_secret（至少 32 字符）")
	}
	authHandler := api.NewAuthHandler(db, logger, []byte(jwtSecret))
	// 批4: 登出 JWT 黑名单（默认关，需 Redis）。启用后登出即吊销 token。
	if cfg.Server.Security.JWTBlacklist.Enabled && redisClient != nil {
		authHandler.EnableJWTBlacklist(redisClient)
		logger.Info("JWT 黑名单已启用（登出即吊销）")
	}
	apiV1.GET("/auth/captcha", authHandler.GetCaptcha)

	// 批4: 登录接口 IP 限流（默认关，灰度开），防口令爆破。登录前置无 tenant，按 IP 限流。
	if cfg.Server.Security.LoginRateLimit.Enabled {
		rps := cfg.Server.Security.LoginRateLimit.RPS
		if rps <= 0 {
			rps = 10
		}
		burst := cfg.Server.Security.LoginRateLimit.Burst
		if burst <= 0 {
			burst = 5
		}
		loginLimiter := middleware.PerRouteRateLimit(redisClient, rps, burst, middleware.KeyByIP, logger)
		apiV1.POST("/auth/login", loginLimiter, authHandler.Login)
		apiV1.POST("/auth/login-precheck", loginLimiter, authHandler.LoginPrecheck)
		logger.Info("登录接口 IP 限流已启用", zap.Int("rps", rps), zap.Int("burst", burst))
	} else {
		apiV1.POST("/auth/login", authHandler.Login)
		apiV1.POST("/auth/login-precheck", authHandler.LoginPrecheck)
	}
	apiV1.POST("/auth/logout", authHandler.Logout)
	apiV1.GET("/auth/me", authHandler.GetCurrentUser)
	apiV1.POST("/auth/change-password", authHandler.AuthMiddleware(), authHandler.ChangePassword)

	// 系统配置 - 获取站点配置（不需要认证，登录页面也需要显示站点名称）
	systemConfigHandler := api.NewSystemConfigHandler(db, logger, "./uploads", "/uploads")
	apiV1.GET("/system-config/site", systemConfigHandler.GetSiteConfig)

	// 需要认证的路由
	apiV1Auth := apiV1.Group("")
	apiV1Auth.Use(authHandler.AuthMiddleware())
	apiV1Auth.Use(middleware.AuditLogWithCH(db, chConn, logger))
	// RBAC：让 role_permissions 表参与放行——对写操作按所属模块校验权限（纵向越权防护）。
	// 读操作放行；admin 角色恒通过；user 默认无写权。
	permResolver := api.NewPermissionResolver(db, logger)
	api.SetGlobalResolver(permResolver)
	apiV1Auth.Use(permResolver.EnforceWritePermissions())

	// 服务发现查询（需要认证，运维 / 前端监控页面调用）
	apiV1Auth.GET("/discovery/agentcenter", discoveryHandler.ListACInstances)

	// 需要管理员权限的路由
	apiV1Admin := apiV1Auth.Group("")
	apiV1Admin.Use(api.RoleMiddleware("admin"))

	// 注册 API 路由
	setupAPIRoutes(apiV1Auth, db, logger, cfg, scoreCache, metricsService, alarmService, acRegistry, acDispatcher, chConn, redisClient, promClient, virusDBUpdater, consumerManager)
	setupAdminAPIRoutes(apiV1Admin, db, logger, cfg, chConn)

	// v2.0 平台超管路由 /api/v2/admin/*
	// 鉴权链: Auth (复用 v1) → tenant.AdminMiddleware (强制 IsPlatformAdmin)
	apiV2 := router.Group("/api/v2")
	apiV2.Use(authHandler.AuthMiddleware())
	apiV2Admin := apiV2.Group("/admin")
	apiV2Admin.Use(tenant.AdminMiddleware())
	adminTenantsHandler := api.NewAdminTenantsHandler(db, logger)
	apiV2Admin.GET("/tenants", adminTenantsHandler.ListTenants)
	apiV2Admin.GET("/tenants/:id", adminTenantsHandler.GetTenant)
	apiV2Admin.POST("/tenants", adminTenantsHandler.CreateTenant)
	apiV2Admin.POST("/tenants/:id/suspend", adminTenantsHandler.SuspendTenant)
	apiV2Admin.POST("/tenants/:id/resume", adminTenantsHandler.ResumeTenant)

	// Sprint 2 PR38: /api/v2/system/mode (用户级查询) + /api/v2/admin/tenants/:id/mode (超管切换)
	// MemoryResolver 启动时从 tenants 表加载初始 mode (后续 PR 加 Redis Pub/Sub 同步多副本)
	modeResolver := mode.NewMemoryResolver(mode.Observe)
	loadTenantModes(db, modeResolver, logger)
	systemModeHandler := api.NewSystemModeHandler(db, logger, modeResolver)

	apiV2.GET("/system/mode", systemModeHandler.GetCurrentMode)
	apiV2Admin.POST("/tenants/:id/mode", systemModeHandler.SetTenantMode)
	apiV2Admin.GET("/tenants/modes", systemModeHandler.ListTenantModes)

	// P1-1: 配置中心变更审批 /api/v2/config/change-requests/*
	configChangeHandler := api.NewConfigChangeRequestHandler(db, logger)
	configChangeGroup := apiV2.Group("/config/change-requests")
	configChangeGroup.POST("", configChangeHandler.Create)
	configChangeGroup.GET("", configChangeHandler.List)
	configChangeGroup.GET("/sensitivity", configChangeHandler.GetSensitivity)
	configChangeGroup.GET("/:id", configChangeHandler.Get)
	configChangeGroup.POST("/:id/approve", configChangeHandler.Approve)
	configChangeGroup.POST("/:id/reject", configChangeHandler.Reject)
	configChangeGroup.POST("/:id/cancel", configChangeHandler.Cancel)

	// A3: MSSP 控制台路由 /api/v2/mssp/*
	msspSvc := mssp.NewService(db, logger)
	msspHandler := api.NewMSSPHandler(msspSvc, logger)
	msspGroup := apiV2.Group("/mssp")
	msspGroup.GET("/dashboard", msspHandler.Dashboard)
	msspGroup.GET("/child-tenants", msspHandler.ListChildTenants)
	msspGroup.POST("/child-tenants", msspHandler.CreateChildTenant)
	msspGroup.GET("/child-tenants/:id", msspHandler.GetChildTenant)
	msspGroup.POST("/child-tenants/:id/suspend", msspHandler.SuspendChildTenant)
	msspGroup.POST("/child-tenants/:id/resume", msspHandler.ResumeChildTenant)
	msspGroup.GET("/alerts", msspHandler.CrossTenantAlerts)

	return router
}

// loadTenantModes 启动时把 tenants.default_mode 加载到 MemoryResolver。
func loadTenantModes(db *gorm.DB, resolver *mode.MemoryResolver, logger *zap.Logger) {
	var tenants []struct {
		ID          string
		DefaultMode string
	}
	if err := db.Table("tenants").Where("status = ?", "active").Find(&tenants).Error; err != nil {
		logger.Warn("加载 tenants mode 失败,使用全局默认 observe",
			zap.Error(err))
		return
	}
	loaded := 0
	for _, t := range tenants {
		m := mode.Mode(t.DefaultMode)
		if !m.IsValid() {
			continue
		}
		if err := resolver.SetTenant(t.ID, m); err == nil {
			loaded++
		}
	}
	logger.Info("Mode Resolver 初始化完成",
		zap.Int("tenants_loaded", loaded))
}

// setupAPIRoutes 注册所有需要认证的 API 路由
func setupAPIRoutes(router *gin.RouterGroup, db *gorm.DB, logger *zap.Logger, cfg *config.Config, scoreCache *biz.BaselineScoreCache, metricsService *biz.MetricsService, alarmService *kube.KubeAlarmService, acRegistry *sd.Registry, acDispatcher *sd.ACDispatcher, chConn chdriver.Conn, redisClient *redis.Client, promClient *prometheus.Client, virusDBUpdater *biz.VirusDBUpdater, consumerManager *gcppubsub.ConsumerManager) {
	setupHostsAPI(router, db, logger, scoreCache, metricsService)
	setupPolicyGroupsAPI(router, db, logger)
	setupPoliciesAPI(router, db, logger)
	setupRulesAPI(router, db, logger)
	setupTasksAPI(router, db, logger, acDispatcher)
	setupResultsAPI(router, db, logger)
	setupFixAPI(router, db, logger, acDispatcher)
	setupDashboardAPI(router, db, logger, chConn, redisClient, acRegistry, promClient)
	setupAssetsAPI(router, db, logger)
	setupReportsAPI(router, db, logger, chConn, redisClient, cfg)
	setupBusinessLinesAPI(router, db, logger)
	setupAlertsAPI(router, db, logger)
	setupAlertWhitelistAPI(router, db, logger)
	setupPolicyImportExportAPI(router, db, logger)
	setupInspectionAPI(router, db, logger)
	setupFIMAPI(router, db, logger, chConn)
	setupKubeAPI(router, db, logger, alarmService, cfg, consumerManager)
	setupMonitorAPI(router, db, logger, cfg, acRegistry, chConn, redisClient, promClient)
	setupVulnerabilitiesAPI(router, db, logger, acDispatcher)
	setupVulnBulletinsAPI(router, db, logger)
	setupAntivirusAPI(router, db, logger, virusDBUpdater, acDispatcher)
	setupQuarantineAPI(router, db, logger)
	setupDetectionRulesAPI(router, db, logger)
	setupAlertContextAPI(router, db, logger, chConn)
	setupThreatIntelAPI(router, db, logger, redisClient)
	setupNetworkBlockAPI(router, db, logger, acDispatcher)
	setupDependencyAPI(router, db, logger, acDispatcher)
	setupEDREventsAPI(router, logger, chConn, redisClient)
	setupBDEBaselineAPI(router, db, logger)
	setupStorylineAPI(router, db, logger, chConn)
	setupMemoryThreatAPI(router, db, logger)
	setupVEXAPI(router, db, logger)
	setupHoneypotAPI(router, db, logger)
	setupRootkitAPI(router, db, logger)
	setupADAuditAPI(router, db, logger)
	setupHuntingAPI(router, db, logger, chConn)
	setupHostIsolationAPI(router, db, logger, acDispatcher)
	setupAnomalyAPI(router, db, logger)
}

// setupAdminAPIRoutes 注册需要管理员权限的 API 路由
func setupAdminAPIRoutes(router *gin.RouterGroup, db *gorm.DB, logger *zap.Logger, cfg *config.Config, chConn chdriver.Conn) {
	setupUsersAPI(router, db, logger)
	setupSystemConfigAPI(router, db, logger)
	setupNotificationsAPI(router, db, logger)
	setupComponentsAPI(router, db, logger, cfg)
	setupBackupsAPI(router, db, logger)
	setupMigrationAPI(router, db, logger)
	setupAuditLogAPI(router, db, logger)
	setupRBACAPI(router, db, logger)
	setupDataConfigAPI(router, db, logger, chConn)
}

// setupDataConfigAPI 注册数据存储配置（feature flag + retention policy）。
func setupDataConfigAPI(router *gin.RouterGroup, db *gorm.DB, logger *zap.Logger, chConn chdriver.Conn) {
	handler := api.NewAdminDataConfigHandler(db, chConn, logger)
	router.GET("/feature-flags", handler.ListFeatureFlags)
	router.PUT("/feature-flags/:key", handler.UpdateFeatureFlag)
	router.GET("/retention-policies", handler.ListRetentionPolicies)
	router.PUT("/retention-policies/:ch_table", handler.UpdateRetentionPolicy)
}

// setupRBACAPI 设置 RBAC 权限管理 API 路由
func setupRBACAPI(router *gin.RouterGroup, db *gorm.DB, logger *zap.Logger) {
	handler := api.NewRBACHandler(db, logger)
	router.GET("/rbac/permissions", handler.ListPermissions)
	router.GET("/rbac/roles", handler.ListRoles)
	router.GET("/rbac/roles/:role/permissions", handler.GetRolePermissions)
	router.PUT("/rbac/roles/:role/permissions", handler.UpdateRolePermissions)
}

// setupMigrationAPI 设置 MVP1 → MVP2 迁移助手 API 路由
func setupMigrationAPI(router *gin.RouterGroup, db *gorm.DB, logger *zap.Logger) {
	handler := api.NewMigrationHandler(db, logger)
	router.POST("/system/migration/test-connection", handler.TestConnection)
	router.POST("/system/migration/jobs", handler.StartJob)
	router.GET("/system/migration/jobs", handler.ListJobs)
	router.GET("/system/migration/jobs/:id", handler.GetJob)
	router.POST("/system/migration/jobs/:id/cancel", handler.CancelJob)
}

// setupNetworkBlockAPI 设置网络阻断 API 路由
func setupNetworkBlockAPI(router *gin.RouterGroup, db *gorm.DB, logger *zap.Logger, acDispatcher *sd.ACDispatcher) {
	handler := api.NewNetworkBlockHandler(db, logger, acDispatcher)
	router.GET("/network-block/rules", handler.ListRules)
	router.POST("/network-block/rules", handler.CreateRule)
	router.POST("/network-block/rules/:id/remove", handler.RemoveRule)
	router.DELETE("/network-block/rules/:id", handler.DeleteRule)
}

// setupStorylineAPI 设置攻击故事线 API 路由
func setupStorylineAPI(router *gin.RouterGroup, db *gorm.DB, logger *zap.Logger, chConn chdriver.Conn) {
	handler := api.NewStorylineHandler(db, logger)
	handler.SetClickHouse(chConn)
	router.GET("/storylines", handler.ListStorylines)
	router.GET("/storylines/stats", handler.GetStorylineStats)
	router.GET("/storylines/:story_id", handler.GetStoryline)
	router.POST("/storylines/:story_id/resolve", handler.ResolveStoryline)
}

// setupBDEBaselineAPI 设置 BDE 行为基线 API 路由
func setupBDEBaselineAPI(router *gin.RouterGroup, db *gorm.DB, logger *zap.Logger) {
	handler := api.NewBDEBaselineHandler(db, logger)
	router.GET("/bde/baseline/states", handler.ListBaselineStates)
	router.GET("/bde/baseline/stats", handler.GetBaselineStats)
	router.GET("/bde/alerts", handler.ListBehaviorAlerts)
}

// setupHuntingAPI 设置威胁狩猎 API 路由
func setupHuntingAPI(router *gin.RouterGroup, db *gorm.DB, logger *zap.Logger, chConn chdriver.Conn) {
	handler := api.NewHuntingHandler(db, chConn, logger)
	router.POST("/hunting/query", handler.ExecuteQuery)
	router.GET("/hunting/queries", handler.ListSavedQueries)
	router.POST("/hunting/queries", handler.CreateSavedQuery)
	router.DELETE("/hunting/queries/:id", handler.DeleteSavedQuery)
}

// setupAnomalyAPI 设置 ML 异常检测 API 路由
func setupAnomalyAPI(router *gin.RouterGroup, db *gorm.DB, logger *zap.Logger) {
	handler := api.NewAnomalyHandler(db, logger)
	router.GET("/anomalies", handler.ListAnomalies)
	router.GET("/anomalies/stats", handler.GetAnomalyStats)
	router.PUT("/anomalies/:id/resolve", handler.ResolveAnomaly)
}

// setupHostIsolationAPI 设置主机隔离 API 路由
func setupHostIsolationAPI(router *gin.RouterGroup, db *gorm.DB, logger *zap.Logger, acDispatcher *sd.ACDispatcher) {
	handler := api.NewHostIsolationHandler(db, logger, acDispatcher)
	router.POST("/hosts/isolate", handler.IsolateHost)
	router.POST("/hosts/release", handler.ReleaseHost)
	router.GET("/hosts/:host_id/isolation-status", handler.GetIsolationStatus)
	router.GET("/hosts/isolations", handler.ListIsolations)
}

// setupMemoryThreatAPI 设置内存威胁 API 路由
func setupMemoryThreatAPI(router *gin.RouterGroup, db *gorm.DB, logger *zap.Logger) {
	handler := api.NewMemoryThreatHandler(db, logger)
	router.GET("/memory-threats", handler.ListMemoryThreats)
	router.GET("/memory-threats/stats", handler.GetMemoryThreatStats)
	router.PUT("/memory-threats/:id/resolve", handler.ResolveMemoryThreat)
}

// setupVEXAPI VEX 漏洞利用性声明 API (B7).
func setupVEXAPI(router *gin.RouterGroup, db *gorm.DB, logger *zap.Logger) {
	h := api.NewVEXHandler(db, logger)
	router.GET("/vex/:product_id", h.GetDocument)
	router.GET("/vex/:product_id/statements", h.ListStatements)
	router.GET("/vex/:product_id/cyclonedx", h.ExportCycloneDX)
	router.GET("/vex/:product_id/csaf", h.ExportCSAF)
}

// setupHoneypotAPI 蜜罐传感器 API (C1).
func setupHoneypotAPI(router *gin.RouterGroup, db *gorm.DB, logger *zap.Logger) {
	h := api.NewHoneypotHandler(db, logger)
	router.GET("/v2/honeypot/sensors", h.ListSensors)
	router.POST("/v2/honeypot/sensors", h.CreateSensor)
	router.POST("/v2/honeypot/sensors/:id/stop", h.StopSensor)
	router.GET("/v2/honeypot/events", h.ListEvents)
}

// setupRootkitAPI Rootkit / DKOM 检测 API (C2).
func setupRootkitAPI(router *gin.RouterGroup, db *gorm.DB, logger *zap.Logger) {
	h := api.NewRootkitHandler(db, logger)
	router.GET("/rootkit/findings", h.ListFindings)
	router.POST("/rootkit/scan", h.TriggerScan)
	router.POST("/rootkit/findings/:id/resolve", h.Resolve)
}

// setupADAuditAPI AD / LDAP 域控审计 API (EDR-4).
func setupADAuditAPI(router *gin.RouterGroup, db *gorm.DB, logger *zap.Logger) {
	h := api.NewADAuditHandler(db, logger)
	router.GET("/ad-audit/events", h.ListEvents)
	router.GET("/ad-audit/alerts", h.ListAlerts)
	router.GET("/ad-audit/stats", h.Stats)
}

// setupHostsAPI 设置主机 API 路由
func setupHostsAPI(router *gin.RouterGroup, db *gorm.DB, logger *zap.Logger, scoreCache *biz.BaselineScoreCache, metricsService *biz.MetricsService) {
	handler := api.NewHostsHandler(db, logger, scoreCache, metricsService)
	router.GET("/hosts", handler.ListHosts)
	router.POST("/hosts/restart-agent", handler.RestartAgent)
	router.GET("/hosts/restart-records", handler.GetRestartRecords)
	router.GET("/hosts/:host_id", handler.GetHost)
	router.GET("/hosts/:host_id/metrics", handler.GetHostMetrics)
	router.GET("/hosts/:host_id/risk-statistics", handler.GetHostRiskStatistics)
	router.GET("/hosts/:host_id/plugins", handler.GetHostPlugins)
	router.PUT("/hosts/:host_id/tags", handler.UpdateHostTags)
	router.PUT("/hosts/:host_id/business-line", handler.UpdateHostBusinessLine)
	router.DELETE("/hosts/:host_id", handler.DeleteHost)
	router.POST("/hosts/batch-delete", handler.BatchDeleteHost)
	router.POST("/hosts/batch-update-tags", handler.BatchUpdateTags)
	router.POST("/hosts/batch-update-business-line", handler.BatchUpdateBusinessLine)
	router.GET("/hosts/status-distribution", handler.GetHostStatusDistribution)
	router.GET("/hosts/risk-distribution", handler.GetHostRiskDistribution)
}

// setupPolicyGroupsAPI 设置策略组 API 路由
func setupPolicyGroupsAPI(router *gin.RouterGroup, db *gorm.DB, logger *zap.Logger) {
	handler := api.NewPolicyGroupsHandler(db, logger)
	router.GET("/policy-groups", handler.ListPolicyGroups)
	router.GET("/policy-groups/:id", handler.GetPolicyGroup)
	router.GET("/policy-groups/:id/statistics", handler.GetPolicyGroupStatistics)
	router.POST("/policy-groups", handler.CreatePolicyGroup)
	router.PUT("/policy-groups/:id", handler.UpdatePolicyGroup)
	router.DELETE("/policy-groups/:id", handler.DeletePolicyGroup)
}

// setupPoliciesAPI 设置策略 API 路由
func setupPoliciesAPI(router *gin.RouterGroup, db *gorm.DB, logger *zap.Logger) {
	handler := api.NewPoliciesHandler(db, logger)
	router.GET("/policies", handler.ListPolicies)
	router.GET("/policies/:policy_id", handler.GetPolicy)
	router.GET("/policies/:policy_id/statistics", handler.GetPolicyStatistics)
	router.POST("/policies", handler.CreatePolicy)
	router.PUT("/policies/:policy_id", handler.UpdatePolicy)
	router.DELETE("/policies/:policy_id", handler.DeletePolicy)

	// 批量操作
	router.POST("/policies/batch/enable", handler.BatchEnableDisable)
	router.POST("/policies/batch/delete", handler.BatchDelete)
	router.POST("/policies/batch/export", handler.BatchExport)
}

// setupRulesAPI 设置规则 API 路由
func setupRulesAPI(router *gin.RouterGroup, db *gorm.DB, logger *zap.Logger) {
	handler := api.NewRulesHandler(db, logger)
	router.GET("/policies/:policy_id/rules", handler.ListRules)
	router.POST("/policies/:policy_id/rules", handler.CreateRule)
	router.GET("/rules/:rule_id", handler.GetRule)
	router.PUT("/rules/:rule_id", handler.UpdateRule)
	router.DELETE("/rules/:rule_id", handler.DeleteRule)
}

// setupTasksAPI 设置任务 API 路由
// 读操作对所有认证用户开放，写操作需要 admin 角色
func setupTasksAPI(router *gin.RouterGroup, db *gorm.DB, logger *zap.Logger, acDispatcher *sd.ACDispatcher) {
	handler := api.NewTasksHandler(db, logger, acDispatcher)
	// 读操作（所有认证用户）
	router.GET("/tasks", handler.ListTasks)
	router.GET("/tasks/:task_id", handler.GetTask)
	router.GET("/tasks/:task_id/host-status", handler.GetTaskHostStatus)
	// 写操作（需要 admin 角色）
	admin := router.Group("", api.RoleMiddleware("admin"))
	admin.POST("/tasks", handler.CreateTask)
	admin.POST("/tasks/:task_id/run", handler.RunTask)
	admin.POST("/tasks/:task_id/cancel", handler.CancelTask)
	admin.DELETE("/tasks/:task_id", handler.DeleteTask)
}

// setupResultsAPI 设置结果 API 路由
func setupResultsAPI(router *gin.RouterGroup, db *gorm.DB, logger *zap.Logger) {
	handler := api.NewResultsHandler(db, logger)
	router.GET("/results", handler.ListResults)
	router.GET("/results/detail", handler.GetResult)
	router.GET("/results/host/:host_id/score", handler.GetHostBaselineScore)
	router.GET("/results/host/:host_id/summary", handler.GetHostBaselineSummary)
	router.GET("/results/host/:host_id/export", handler.ExportHostBaselineResults)
}

// setupFixAPI 设置基线修复 API 路由
// 读操作对所有认证用户开放，写操作需要 admin 角色
func setupFixAPI(router *gin.RouterGroup, db *gorm.DB, logger *zap.Logger, acDispatcher *sd.ACDispatcher) {
	handler := api.NewFixHandler(db, logger, acDispatcher)
	// 读操作（所有认证用户）
	router.GET("/fix/fixable-items", handler.GetFixableItems)
	router.GET("/fix-tasks", handler.ListFixTasks)
	router.GET("/fix-tasks/:task_id", handler.GetFixTask)
	router.GET("/fix-tasks/:task_id/results", handler.GetFixResults)
	router.GET("/fix-tasks/:task_id/host-status", handler.GetFixTaskHostStatus)
	// 写操作（需要 admin 角色）
	admin := router.Group("", api.RoleMiddleware("admin"))
	admin.POST("/fix-tasks", handler.CreateFixTask)
	admin.POST("/fix-tasks/:task_id/cancel", handler.CancelFixTask)
	admin.DELETE("/fix-tasks/:task_id", handler.DeleteFixTask)
}

// setupDashboardAPI 设置 Dashboard API 路由
func setupDashboardAPI(router *gin.RouterGroup, db *gorm.DB, logger *zap.Logger, chConn chdriver.Conn, redisClient *redis.Client, acRegistry *sd.Registry, promClient *prometheus.Client) {
	handler := api.NewDashboardHandler(db, logger, chConn, redisClient, acRegistry, promClient)
	router.GET("/dashboard/stats", handler.GetDashboardStats)
}

// setupUsersAPI 设置用户管理 API 路由
func setupUsersAPI(router *gin.RouterGroup, db *gorm.DB, logger *zap.Logger) {
	handler := api.NewUsersHandler(db, logger)
	router.GET("/users", handler.ListUsers)
	router.GET("/users/:id", handler.GetUser)
	router.POST("/users", handler.CreateUser)
	router.PUT("/users/:id", handler.UpdateUser)
	router.DELETE("/users/:id", handler.DeleteUser)
}

// setupAssetsAPI 设置资产 API 路由
func setupAssetsAPI(router *gin.RouterGroup, db *gorm.DB, logger *zap.Logger) {
	handler := api.NewAssetsHandler(db, logger)
	router.GET("/assets/overview", handler.GetOverview)
	router.GET("/assets/history", handler.GetHistory)
	router.GET("/assets/statistics", handler.GetStatistics)
	router.GET("/assets/relations", handler.GetRelations)
	router.GET("/assets/status", handler.GetCollectionStatus)
	router.GET("/assets/top", handler.GetTopN)
	router.GET("/assets/processes", handler.ListProcesses)
	router.GET("/assets/ports", handler.ListPorts)
	router.GET("/assets/users", handler.ListUsers)
	router.GET("/assets/software", handler.ListSoftware)
	router.GET("/assets/containers", handler.ListContainers)
	router.GET("/assets/apps", handler.ListApps)
	router.GET("/assets/network-interfaces", handler.ListNetInterfaces)
	router.GET("/assets/volumes", handler.ListVolumes)
	router.GET("/assets/kmods", handler.ListKmods)
	router.GET("/assets/services", handler.ListServices)
	router.GET("/assets/crons", handler.ListCrons)
	router.GET("/assets/export", handler.ExportAssets)
	router.GET("/assets/sbom", handler.ExportSBOM)
}

// setupReportsAPI 设置报表 API 路由
func setupReportsAPI(router *gin.RouterGroup, db *gorm.DB, logger *zap.Logger, chConn chdriver.Conn, redisClient *redis.Client, cfg *config.Config) {
	handler := api.NewReportsHandler(db, logger)
	handler.SetClickHouse(chConn)
	handler.SetRedis(redisClient)

	// PDF 导出（Gotenberg sidecar，HTML→PDF 模式）
	httpPrefix := ""
	if cfg.PDF.InternalURL != "" {
		httpPrefix = cfg.PDF.InternalURL
	}
	pdfHandler := api.NewReportPDFHandler(
		cfg.PDF.GotenbergURL,
		handler,
		"/uploads",
		"./uploads",
		httpPrefix,
		logger,
	)
	router.GET("/reports/edr/pdf", pdfHandler.ExportEDRReportPDF)
	router.GET("/reports/antivirus/pdf", pdfHandler.ExportAntivirusReportPDF)
	router.GET("/reports/vulnerability/pdf", pdfHandler.ExportVulnReportPDF)
	router.GET("/reports/kube/pdf", pdfHandler.ExportKubeReportPDF)
	router.GET("/reports/task/:task_id/pdf", pdfHandler.ExportTaskReportPDF)
	router.GET("/reports/stats", handler.GetStats)
	router.GET("/reports/baseline-score-trend", handler.GetBaselineScoreTrend)
	router.GET("/reports/check-result-trend", handler.GetCheckResultTrend)
	// 任务报告
	router.GET("/reports/task/:task_id", handler.GetTaskReport)
	router.GET("/reports/task/:task_id/host/:host_id", handler.GetTaskHostDetail)
	router.GET("/reports/task/:task_id/executive", handler.GetExecutiveTaskReport)
	// Top 统计
	router.GET("/reports/top-failed-rules", handler.GetTopFailedRules)
	router.GET("/reports/top-risk-hosts", handler.GetTopRiskHosts)
	// 分类报告
	router.GET("/reports/antivirus", handler.GetAntivirusReport)
	router.GET("/reports/vulnerability", handler.GetVulnerabilityReport)
	router.GET("/reports/kube", handler.GetKubeReport)
	router.GET("/reports/edr", handler.GetEDRReport)
	// Executive 报告（可导出 PDF）
	router.GET("/reports/antivirus/:task_id/executive", handler.GetAntivirusExecutiveReport)
	router.GET("/reports/vulnerability/executive", handler.GetVulnerabilityExecutiveReport)
	router.GET("/reports/remediation/executive", handler.GetRemediationExecutiveReport)
	router.GET("/reports/kube/executive", handler.GetKubeExecutiveReport)
	router.GET("/reports/edr/executive", handler.GetEDRExecutiveReport)
	// 已保存的报告
	router.GET("/reports/generated", handler.ListGeneratedReports)
	router.GET("/reports/generated/:id", handler.GetGeneratedReport)
	router.DELETE("/reports/generated/:id", handler.DeleteGeneratedReport)
}

// setupBusinessLinesAPI 设置业务线 API 路由
func setupBusinessLinesAPI(router *gin.RouterGroup, db *gorm.DB, logger *zap.Logger) {
	handler := api.NewBusinessLinesHandler(db, logger)
	router.GET("/business-lines", handler.ListBusinessLines)
	router.GET("/business-lines/:id", handler.GetBusinessLine)
	router.POST("/business-lines", handler.CreateBusinessLine)
	router.PUT("/business-lines/:id", handler.UpdateBusinessLine)
	router.DELETE("/business-lines/:id", handler.DeleteBusinessLine)
}

// setupSystemConfigAPI 设置系统配置 API 路由（需要认证）
func setupSystemConfigAPI(router *gin.RouterGroup, db *gorm.DB, logger *zap.Logger) {
	handler := api.NewSystemConfigHandler(db, logger, "./uploads", "/uploads")

	// Kubernetes 镜像配置
	router.GET("/system-config/kubernetes-image", handler.GetKubernetesImageConfig)
	router.PUT("/system-config/kubernetes-image", handler.UpdateKubernetesImageConfig)

	// 站点配置（更新和上传需要认证）
	router.PUT("/system-config/site", handler.UpdateSiteConfig)

	// Logo 上传
	router.POST("/system-config/upload-logo", handler.UploadLogo)

	// 告警配置
	router.GET("/system-config/alert", handler.GetAlertConfig)
	router.PUT("/system-config/alert", handler.UpdateAlertConfig)
}

// setupNotificationsAPI 设置通知管理 API 路由
func setupNotificationsAPI(router *gin.RouterGroup, db *gorm.DB, logger *zap.Logger) {
	handler := api.NewNotificationsHandler(db, logger)
	router.GET("/notifications", handler.ListNotifications)
	router.GET("/notifications/:id", handler.GetNotification)
	router.POST("/notifications", handler.CreateNotification)
	router.PUT("/notifications/:id", handler.UpdateNotification)
	router.DELETE("/notifications/:id", handler.DeleteNotification)
	router.POST("/notifications/test", handler.TestNotification)
}

// setupAlertsAPI 设置告警管理 API 路由
func setupAlertsAPI(router *gin.RouterGroup, db *gorm.DB, logger *zap.Logger) {
	handler := api.NewAlertsHandler(db, logger)
	router.GET("/alerts", handler.ListAlerts)
	router.GET("/alerts/statistics", handler.GetAlertStatistics)
	router.GET("/alerts/:id", handler.GetAlert)
	router.POST("/alerts/:id/resolve", handler.ResolveAlert)
	router.POST("/alerts/:id/ignore", handler.IgnoreAlert)
	// 批量操作
	router.POST("/alerts/batch/resolve", handler.BatchResolveAlerts)
	router.POST("/alerts/batch/ignore", handler.BatchIgnoreAlerts)
	router.POST("/alerts/batch/delete", handler.BatchDeleteAlerts)
}

// setupAuditLogAPI 设置操作审计日志 API 路由
func setupAuditLogAPI(router *gin.RouterGroup, db *gorm.DB, logger *zap.Logger) {
	handler := api.NewAuditLogHandler(db, logger)
	router.GET("/audit-logs", handler.ListAuditLogs)
}

// setupAlertWhitelistAPI 设置告警白名单 API 路由
func setupAlertWhitelistAPI(router *gin.RouterGroup, db *gorm.DB, logger *zap.Logger) {
	handler := api.NewAlertWhitelistHandler(db, logger)
	router.GET("/alerts/whitelist", handler.ListWhitelist)
	router.POST("/alerts/whitelist", handler.CreateWhitelist)
	router.PUT("/alerts/whitelist/:id", handler.UpdateWhitelist)
	router.DELETE("/alerts/whitelist/:id", handler.DeleteWhitelist)
}

// setupComponentsAPI 设置组件管理 API 路由
func setupComponentsAPI(router *gin.RouterGroup, db *gorm.DB, logger *zap.Logger, cfg *config.Config) {
	handler := api.NewComponentsHandler(db, logger, cfg, "./uploads", "/uploads")

	// 组件管理
	router.GET("/components", handler.ListComponents)
	router.POST("/components", handler.CreateComponent)
	router.GET("/components/plugin-status", handler.GetPluginSyncStatus)
	router.GET("/components/:id", handler.GetComponent)
	router.DELETE("/components/:id", handler.DeleteComponent)

	// 版本管理
	router.GET("/components/:id/versions", handler.ListVersions)
	router.POST("/components/:id/versions", handler.ReleaseVersion)
	router.GET("/components/:id/versions/:version_id", handler.GetVersion)
	router.PUT("/components/:id/versions/:version_id/set-latest", handler.SetLatestVersion)
	router.DELETE("/components/:id/versions/:version_id", handler.DeleteVersion)

	// 包上传
	router.POST("/components/:id/versions/:version_id/packages", handler.UploadPackage)
	router.DELETE("/packages/:id", handler.DeletePackage)

	// Agent 更新推送
	router.POST("/components/agent/push-update", handler.PushAgentUpdate)

	// 同步所有插件到最新版本
	router.POST("/components/plugins/sync-latest", handler.SyncAllPluginsToLatest)

	// 插件配置手动广播
	router.POST("/components/plugins/broadcast", handler.BroadcastPluginConfigs)

	// 推送记录查询
	router.GET("/components/push-records", handler.ListPushRecords)
	router.GET("/components/push-records/:id", handler.GetPushRecord)
}

// setupPolicyImportExportAPI 设置策略导入导出 API 路由
func setupPolicyImportExportAPI(router *gin.RouterGroup, db *gorm.DB, logger *zap.Logger) {
	api.RegisterPolicyImportExportRoutes(router, db, logger)
}

// setupInspectionAPI 设置运维巡检 API 路由
func setupInspectionAPI(router *gin.RouterGroup, db *gorm.DB, logger *zap.Logger) {
	handler := api.NewInspectionHandler(db, logger)
	router.GET("/inspection/overview", handler.GetOverview)
}

// setupKubeAPI 设置 Kubernetes 容器安全 API 路由
func setupKubeAPI(router *gin.RouterGroup, db *gorm.DB, logger *zap.Logger, alarmService *kube.KubeAlarmService, cfg *config.Config, consumerManager *gcppubsub.ConsumerManager) {
	kubeClient := biz.NewKubeClientManager(db, logger)

	// 集群管理
	clusterHandler := api.NewKubeClusterHandler(db, logger, kubeClient, cfg, consumerManager)
	router.GET("/kube/clusters", clusterHandler.ListClusters)
	router.POST("/kube/clusters", clusterHandler.CreateCluster)
	router.GET("/kube/clusters/:id", clusterHandler.GetCluster)
	router.PUT("/kube/clusters/:id", clusterHandler.UpdateCluster)
	router.DELETE("/kube/clusters/:id", clusterHandler.DeleteCluster)
	router.GET("/kube/clusters/:id/nodes", clusterHandler.GetClusterNodes)
	router.GET("/kube/clusters/:id/pods", clusterHandler.GetClusterPods)
	router.GET("/kube/clusters/:id/workloads", clusterHandler.GetClusterWorkloads)
	router.POST("/kube/clusters/:id/regenerate-token", clusterHandler.RegenerateAuditToken)
	router.PUT("/kube/clusters/:id/gcp-config", clusterHandler.UpdateGCPConfig)
	router.DELETE("/kube/clusters/:id/gcp-config", clusterHandler.DeleteGCPConfig)

	// 容器告警
	alarmHandler := api.NewKubeAlarmHandler(db, logger)
	router.GET("/kube/alarms", alarmHandler.ListAlarms)
	router.POST("/kube/alarms/:id/process", alarmHandler.ProcessAlarm)
	router.POST("/kube/alarms/batch-process", alarmHandler.BatchProcessAlarms)
	router.POST("/kube/alarms/batch-ignore", alarmHandler.BatchIgnoreAlarms)

	// 安全事件
	eventHandler := api.NewKubeEventHandler(db, logger)
	router.GET("/kube/events", eventHandler.ListEvents)
	router.POST("/kube/events/:id/handle", eventHandler.HandleEvent)

	// CEL 规则引擎
	ruleEngine, err := kube.NewKubeRuleEngine(logger)
	if err != nil {
		logger.Error("初始化 K8s CEL 规则引擎失败", zap.Error(err))
	}

	// 基线检查
	baselineChecker := biz.NewKubeBaselineChecker(db, logger, kubeClient, ruleEngine)
	baselineHandler := api.NewKubeBaselineHandler(db, logger, baselineChecker)
	router.GET("/kube/baseline", baselineHandler.ListBaseline)
	router.GET("/kube/baseline/:id", baselineHandler.GetBaselineDetail)
	router.POST("/kube/baseline/detect", baselineHandler.RunBaselineCheck)

	// 基线规则管理
	rulesHandler := api.NewKubeBaselineRulesHandler(db, logger, baselineChecker, ruleEngine)
	router.GET("/kube/baseline-rules", rulesHandler.ListRules)
	router.GET("/kube/baseline-rules/export", rulesHandler.ExportRules)
	router.POST("/kube/baseline-rules/import", rulesHandler.ImportRules)
	router.POST("/kube/baseline-rules/validate-expression", rulesHandler.ValidateExpression)
	router.GET("/kube/baseline-rules/expression-templates", rulesHandler.GetExpressionTemplates)
	router.POST("/kube/baseline-rules/expression-templates", rulesHandler.CreateExpressionTemplate)
	router.PUT("/kube/baseline-rules/expression-templates/:id", rulesHandler.UpdateExpressionTemplate)
	router.DELETE("/kube/baseline-rules/expression-templates/:id", rulesHandler.DeleteExpressionTemplate)
	router.GET("/kube/baseline-rules/:id", rulesHandler.GetRule)
	router.POST("/kube/baseline-rules", rulesHandler.CreateRule)
	router.PUT("/kube/baseline-rules/:id", rulesHandler.UpdateRule)
	router.DELETE("/kube/baseline-rules/:id", rulesHandler.DeleteRule)
	router.PUT("/kube/baseline-rules/:id/toggle", rulesHandler.ToggleRule)

	// 基线告警
	baselineAlertHandler := api.NewKubeBaselineAlertHandler(db, logger)
	router.GET("/kube/baseline-alerts", baselineAlertHandler.ListAlerts)
	router.POST("/kube/baseline-alerts/:id/ignore", baselineAlertHandler.IgnoreAlert)
	router.POST("/kube/baseline-alerts/batch-ignore", baselineAlertHandler.BatchIgnoreAlerts)

	// 白名单
	whitelistHandler := api.NewKubeWhitelistHandler(db, logger)
	router.GET("/kube/whitelist", whitelistHandler.ListWhitelist)
	router.POST("/kube/whitelist", whitelistHandler.CreateWhitelist)
	router.PUT("/kube/whitelist/:id", whitelistHandler.UpdateWhitelist)
	router.DELETE("/kube/whitelist/:id", whitelistHandler.DeleteWhitelist)

	// 统计
	statsHandler := api.NewKubeStatsHandler(db, logger)
	router.GET("/kube/stats/summary", statsHandler.GetSummary)
	router.GET("/kube/stats/alarm-trend", statsHandler.GetAlarmTrend)
}

// setupFIMAPI 设置 FIM（文件完整性监控）API 路由
func setupFIMAPI(router *gin.RouterGroup, db *gorm.DB, logger *zap.Logger, chConn chdriver.Conn) {
	// 策略管理
	policiesHandler := api.NewFIMPoliciesHandler(db, logger)
	router.GET("/fim/policies", policiesHandler.ListFIMPolicies)
	router.POST("/fim/policies", policiesHandler.CreateFIMPolicy)
	router.GET("/fim/policies/:id", policiesHandler.GetFIMPolicy)
	router.PUT("/fim/policies/:id", policiesHandler.UpdateFIMPolicy)
	router.DELETE("/fim/policies/:id", policiesHandler.DeleteFIMPolicy)

	// 任务管理
	tasksHandler := api.NewFIMTasksHandler(db, logger)
	router.GET("/fim/tasks", tasksHandler.ListFIMTasks)
	router.POST("/fim/tasks", tasksHandler.CreateFIMTask)
	router.GET("/fim/tasks/:id", tasksHandler.GetFIMTask)
	router.POST("/fim/tasks/:id/run", tasksHandler.RunFIMTask)

	// 事件查询与确认
	eventsHandler := api.NewFIMEventsHandler(db, logger, chConn)
	router.GET("/fim/events", eventsHandler.ListFIMEvents)
	router.GET("/fim/events/stats", eventsHandler.GetFIMEventStats)
	router.POST("/fim/events/batch-confirm", eventsHandler.BatchConfirmFIMEvents)
	router.GET("/fim/events/:id", eventsHandler.GetFIMEvent)
	router.POST("/fim/events/:id/confirm", eventsHandler.ConfirmFIMEvent)

	// 基线管理
	baselinesHandler := api.NewFIMBaselinesHandler(db, logger)
	router.GET("/fim/baselines", baselinesHandler.ListBaselines)
	router.POST("/fim/baselines/batch-approve", baselinesHandler.BatchApproveBaselines)
	router.GET("/fim/baselines/:id", baselinesHandler.GetBaseline)
	router.POST("/fim/baselines/:id/approve", baselinesHandler.ApproveBaseline)
	router.POST("/fim/baselines/:id/reject", baselinesHandler.RejectBaseline)
}

// setupMonitorAPI 设置系统监控 API 路由
func setupMonitorAPI(router *gin.RouterGroup, db *gorm.DB, logger *zap.Logger, cfg *config.Config, acRegistry *sd.Registry, chConn chdriver.Conn, redisClient *redis.Client, promClient *prometheus.Client) {
	handler := api.NewMonitorHandler(cfg, db, chConn, promClient, acRegistry, logger, redisClient)
	router.GET("/monitor/host", handler.GetHostMonitor)
	router.GET("/monitor/services", handler.GetServicesMonitor)
	router.GET("/monitor/services/:name/history", handler.GetServiceHistory) // Tier 1-2 历史趋势
	router.GET("/monitor/slo", handler.GetSLO)                               // Tier 2-2 SLO 可用性
	router.GET("/monitor/service-alerts", handler.GetServiceAlerts)
	router.POST("/monitor/service-alerts/:id/ack", handler.AckServiceAlert)
}

// setupBackupsAPI 设置配置备份 API 路由
func setupBackupsAPI(router *gin.RouterGroup, db *gorm.DB, logger *zap.Logger) {
	handler := api.NewBackupsHandler(db, logger)
	router.GET("/system/backups", handler.ListBackups)
	router.POST("/system/backups", handler.CreateBackup)
	router.GET("/system/backup-config", handler.GetBackupConfig)
	router.PUT("/system/backup-config", handler.UpdateBackupConfig)
	router.GET("/system/backups/:id/download", handler.DownloadBackup)
	router.POST("/system/backups/:id/restore", handler.RestoreBackup)
	router.DELETE("/system/backups/:id", handler.DeleteBackup)
}

// setupAntivirusAPI 设置病毒查杀 API 路由
func setupAntivirusAPI(router *gin.RouterGroup, db *gorm.DB, logger *zap.Logger, virusDBUpdater *biz.VirusDBUpdater, acDispatcher *sd.ACDispatcher) {
	handler := api.NewAntivirusHandler(db, logger, virusDBUpdater, acDispatcher)

	// 扫描任务 CRUD
	router.GET("/antivirus/tasks", handler.ListTasks)
	router.POST("/antivirus/tasks", handler.CreateTask)
	router.GET("/antivirus/tasks/:id", handler.GetTask)
	router.DELETE("/antivirus/tasks/:id", handler.DeleteTask)
	router.POST("/antivirus/tasks/:id/cancel", handler.CancelTask)

	// 扫描结果查询
	router.GET("/antivirus/results", handler.ListResults)
	router.GET("/antivirus/results/:id", handler.GetResult)
	router.POST("/antivirus/results/:id/quarantine", handler.QuarantineResult)
	router.POST("/antivirus/results/:id/ignore", handler.IgnoreResult)
	router.POST("/antivirus/results/:id/delete-file", handler.DeleteFileResult)

	// 统计概览
	router.GET("/antivirus/statistics", handler.GetStatistics)

	// 病毒库同步状态
	router.GET("/antivirus/virus-db/status", handler.GetVirusDBStatus)
	router.GET("/antivirus/virus-db/history", handler.GetVirusDBHistory)
	router.POST("/antivirus/virus-db/sync", handler.TriggerVirusDBSync)
}

// setupQuarantineAPI 设置文件隔离箱 API 路由
func setupQuarantineAPI(router *gin.RouterGroup, db *gorm.DB, logger *zap.Logger) {
	handler := api.NewQuarantineHandler(db, logger)
	router.GET("/quarantine/files", handler.ListFiles)
	router.GET("/quarantine/files/:id", handler.GetFile)
	router.POST("/quarantine/files/:id/restore", handler.RestoreFile)
	router.DELETE("/quarantine/files/:id", handler.DeleteFile)
	router.POST("/quarantine/files/batch-delete", handler.BatchDelete)
	router.GET("/quarantine/statistics", handler.GetStatistics)
}

// setupVulnerabilitiesAPI 设置漏洞管理 API 路由
func setupVulnerabilitiesAPI(router *gin.RouterGroup, db *gorm.DB, logger *zap.Logger, acDispatcher *sd.ACDispatcher) {
	handler := api.NewVulnerabilitiesHandler(db, logger)
	router.GET("/vulnerabilities", handler.ListVulnerabilities)
	router.POST("/vulnerabilities/:id/ignore", handler.IgnoreVulnerability)
	router.PUT("/vulnerabilities/:id/category", handler.UpdateCategoryOverride) // admin override 分类/重启动作
	router.POST("/vulnerabilities/:id/unignore", handler.UnignoreVulnerability)
	router.POST("/vulnerabilities/sync", handler.TriggerSync)
	router.POST("/vulnerabilities/scan", handler.TriggerScan)
	router.GET("/vulnerabilities/scan-status", handler.GetScanStatus)
	router.GET("/vulnerabilities/scan-history", handler.GetScanHistory)
	router.GET("/vulnerabilities/scan-history/:id", handler.GetScanHistoryDetail)
	router.GET("/vulnerabilities/scan-tasks", handler.ListScanTasks)
	router.GET("/vulnerabilities/scan-tasks/:task_id", handler.GetScanTask)

	router.GET("/vulnerabilities/:id", handler.GetVulnerability)

	// 漏洞修复相关
	remHandler := api.NewRemediationHandler(db, logger)
	router.GET("/vulnerabilities/:id/advice", remHandler.GetAdvice)
	router.POST("/vulnerabilities/:id/patch", remHandler.PatchVulnerability)
	router.POST("/vulnerabilities/:id/verify", remHandler.VerifyRemediation)
	router.GET("/vulnerabilities/stats/remediation", remHandler.GetRemediationStats)
	router.GET("/vulnerabilities/stats/trend", remHandler.GetRemediationTrend)
	router.GET("/vulnerabilities/stats/priority", handler.GetPriorityStats)
	router.GET("/vulnerabilities/stats/asset-type", handler.GetAssetTypeStats)
	router.GET("/vulnerabilities/export-by-owner", handler.ExportByOwner)

	// 修复任务管理
	taskHandler := api.NewRemediationTasksHandler(db, logger)
	router.POST("/remediation-tasks", taskHandler.CreateTask)
	router.GET("/remediation-tasks", taskHandler.ListTasks)
	router.GET("/remediation-tasks/stats", taskHandler.GetTaskStats)
	router.GET("/remediation-tasks/:id", taskHandler.GetTask)
	router.POST("/remediation-tasks/:id/confirm", taskHandler.ConfirmTask)
	// P5.6: 修复任务执行后 user 手动确认 + 触发 pre-check 复测
	verifyHandler := api.NewRemediationTaskVerifyHandler(db, logger, acDispatcher)
	router.POST("/remediation-tasks/:id/confirm-executed", verifyHandler.ConfirmExecuted)
	router.POST("/remediation-tasks/:id/cancel", taskHandler.CancelTask)
	router.POST("/remediation-tasks/:id/retry", taskHandler.RetryTask)
	router.GET("/remediation-tasks/:id/events", taskHandler.ListEvents)          // 全量 events 列表
	router.GET("/remediation-tasks/:id/events/stream", taskHandler.StreamEvents) // SSE 实时流

	// 漏洞 advisory 同步（admin 手动触发）
	vulnSyncHandler := api.NewVulnSyncHandler(db, logger)
	router.POST("/vulnerabilities/advisory-sync", vulnSyncHandler.SyncAdvisories)

	// 漏洞数据源管理（UI「漏洞源管理」页面）
	vdsHandler := api.NewVulnDataSourcesHandler(db, logger)
	router.GET("/vuln-data-sources", vdsHandler.List)
	router.PUT("/vuln-data-sources/:id", vdsHandler.Update)
	router.POST("/vuln-data-sources/:id/test", vdsHandler.TestConnection)
	router.POST("/vuln-data-sources/:id/sync", vdsHandler.TriggerSync)
	router.POST("/remediation-tasks/:id/verify", remHandler.VerifyTask)
	router.POST("/remediation-tasks/batch", taskHandler.BatchCreate)
	router.POST("/remediation-tasks/batch-confirm", taskHandler.BatchConfirm)
	router.POST("/remediation-tasks/batch-retry", taskHandler.BatchRetry)
	router.POST("/remediation-tasks/batch-cancel", taskHandler.BatchCancel)
	router.POST("/remediation-tasks/host-batch", taskHandler.CreateForHost) // 单 host 批量创建（A: vulnIds 子集 / B: allUnpatched 全量）

	// 主机漏洞预检（agent 在本机查仓库 + 已装包，避免 server vuln DB 错命令）
	preCheckHandler := api.NewHostVulnPreCheckHandler(db, logger, acDispatcher)
	router.POST("/host-vulnerabilities/:id/precheck", preCheckHandler.CreateForHostVuln)
	router.POST("/hosts/:host_id/precheck-all", preCheckHandler.CreateForHostAll)
	// 全集群 pre-check 需 admin 权限，避免普通用户一键打爆集群 dnf
	router.POST("/host-vulnerabilities/precheck-all-online",
		api.RoleMiddleware("admin"),
		preCheckHandler.CreateForAllOnline)

	// 扫描计划管理
	vulnScanner := biz.NewVulnScanner(db, logger)
	scanScheduler := biz.NewScanScheduler(db, logger, vulnScanner)
	schedHandler := api.NewScanSchedulesHandler(db, logger, scanScheduler)
	router.GET("/vulnerabilities/schedules", schedHandler.ListSchedules)
	router.POST("/vulnerabilities/schedules", schedHandler.CreateSchedule)
	router.PUT("/vulnerabilities/schedules/:id", schedHandler.UpdateSchedule)
	router.DELETE("/vulnerabilities/schedules/:id", schedHandler.DeleteSchedule)
	router.POST("/vulnerabilities/schedules/:id/toggle", schedHandler.ToggleSchedule)
	router.GET("/vulnerabilities/schedules/:id/executions", schedHandler.ListExecutions)
	router.GET("/vulnerabilities/schedules/executions/:execId", schedHandler.GetExecution)

	// 漏洞库缓存管理
	cacheHandler := api.NewVulnCacheHandler(db, logger)
	router.GET("/vulnerabilities/cache/stats", cacheHandler.GetStats)
	router.POST("/vulnerabilities/cache/import", cacheHandler.ImportDB)
	router.GET("/vulnerabilities/cache/imports", cacheHandler.GetImportHistory)
	router.POST("/vulnerabilities/cache/purge", cacheHandler.PurgeExpired)

	// 镜像扫描
	imageHandler := api.NewImageScansHandler(db, logger)
	router.POST("/images/scan", imageHandler.ScanImage)
	router.GET("/images/scans", imageHandler.ListScans)
	router.GET("/images/scans/:id", imageHandler.GetScan)
	router.GET("/images/scans/:id/vulns", imageHandler.GetScanVulns)
	router.POST("/images/registries", imageHandler.CreateRegistry)
	router.GET("/images/registries", imageHandler.ListRegistries)
	router.PUT("/images/registries/:id", imageHandler.UpdateRegistry)
	router.DELETE("/images/registries/:id", imageHandler.DeleteRegistry)
	router.POST("/images/registries/:id/scan", imageHandler.ScanRegistryImages)

	// SBOM 导入
	sbomHandler := api.NewSBOMImportHandler(db, logger)
	router.POST("/sbom/import", sbomHandler.ImportSBOM)
	router.GET("/sbom/projects", sbomHandler.ListProjects)
	router.GET("/sbom/projects/:name", sbomHandler.GetProject)

	// 修复策略管理
	remExecutor := biz.NewRemediationExecutor(db, logger)
	policyHandler := api.NewRemediationPoliciesHandler(db, logger, remExecutor)
	router.POST("/remediation-policies", policyHandler.CreatePolicy)
	router.GET("/remediation-policies", policyHandler.ListPolicies)
	router.GET("/remediation-policies/:id", policyHandler.GetPolicy)
	router.PUT("/remediation-policies/:id", policyHandler.UpdatePolicy)
	router.DELETE("/remediation-policies/:id", policyHandler.DeletePolicy)
	router.POST("/remediation-policies/:id/execute", policyHandler.ExecutePolicy)
	router.POST("/remediation-policies/:id/preview", policyHandler.PreviewPolicy)
	router.GET("/remediation-policies/:id/executions", policyHandler.ListExecutions)
}

// setupVulnBulletinsAPI 设置漏洞通报 API 路由
func setupVulnBulletinsAPI(router *gin.RouterGroup, db *gorm.DB, logger *zap.Logger) {
	handler := api.NewVulnBulletinsHandler(db, logger)
	router.GET("/vuln-bulletins", handler.ListBulletins)
	router.GET("/vuln-bulletins/statistics", handler.GetBulletinStatistics)
	router.GET("/vuln-bulletins/config", handler.GetBulletinConfig)
	router.PUT("/vuln-bulletins/config", handler.UpdateBulletinConfig)
	router.GET("/vuln-bulletins/:id", handler.GetBulletin)
	router.PUT("/vuln-bulletins/:id/acknowledge", handler.AcknowledgeBulletin)
	router.PUT("/vuln-bulletins/:id/resolve", handler.ResolveBulletin)
	router.PUT("/vuln-bulletins/:id/ignore", handler.IgnoreBulletin)
	router.PUT("/vuln-bulletins/:id/reopen", handler.ReopenBulletin)
	router.POST("/vuln-bulletins/batch", handler.BatchBulletins)
}

// setupAlertContextAPI 设置告警溯源 API 路由
func setupAlertContextAPI(router *gin.RouterGroup, db *gorm.DB, logger *zap.Logger, chConn chdriver.Conn) {
	handler := api.NewAlertContextHandler(db, chConn, logger)
	router.GET("/alerts/:id/context", handler.GetAlertContext)
}

// setupDetectionRulesAPI 设置检测规则管理 API 路由
func setupDetectionRulesAPI(router *gin.RouterGroup, db *gorm.DB, logger *zap.Logger) {
	handler := api.NewDetectionRulesHandler(db, logger)
	router.GET("/detection-rules", handler.ListRules)
	router.GET("/detection-rules/categories", handler.GetCategories)
	router.GET("/detection-rules/mitre-ids", handler.GetMitreIDs)
	router.GET("/detection-rules/statistics", handler.GetStatistics)
	router.GET("/detection-rules/:id", handler.GetRule)
	router.POST("/detection-rules", handler.CreateRule)
	router.PUT("/detection-rules/:id", handler.UpdateRule)
	router.DELETE("/detection-rules/:id", handler.DeleteRule)
	router.POST("/detection-rules/:id/toggle", handler.ToggleRule)
}

// setupThreatIntelAPI 设置威胁情报 API 路由
func setupThreatIntelAPI(router *gin.RouterGroup, db *gorm.DB, logger *zap.Logger, redisClient *redis.Client) {
	service := biz.NewThreatIntel(db, redisClient, logger)
	handler := api.NewThreatIntelHandler(service, redisClient, logger)
	router.GET("/threat-intel/stats", handler.GetIOCStats)
	router.GET("/threat-intel/iocs", handler.ListIOCs)
	router.POST("/threat-intel/check", handler.CheckIOC)
	router.POST("/threat-intel/sync", handler.TriggerSync)
	router.GET("/threat-intel/sync-status", handler.GetSyncStatus)
	router.GET("/threat-intel/sync-history", handler.GetSyncHistory)
}

// setupDependencyAPI 设置依赖管理 API 路由
func setupDependencyAPI(router *gin.RouterGroup, db *gorm.DB, logger *zap.Logger, acDispatcher *sd.ACDispatcher) {
	handler := api.NewDependencyHandler(db, logger, acDispatcher)
	router.POST("/hosts/dependency/install", handler.Install)
	router.POST("/hosts/dependency/status", handler.Status)
}

// setupEDREventsAPI 设置 EDR 事件查询 API 路由
func setupEDREventsAPI(router *gin.RouterGroup, logger *zap.Logger, chConn chdriver.Conn, redisClient *redis.Client) {
	handler := api.NewEDREventsHandler(logger, chConn, redisClient)
	router.GET("/edr/events", handler.ListEDREvents)
	router.GET("/edr/events/detail", handler.GetEDREventDetail)
	router.GET("/edr/events/stats", handler.GetEDREventStats)
}
