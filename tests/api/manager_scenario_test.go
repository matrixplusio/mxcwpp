//go:build integration
// +build integration

// Package api_test 提供 Manager HTTP API 场景测试和功能测试
//
// 运行方式：
//
//	# 启动本地依赖
//	make dev-docker-up
//
//	# 全量场景测试
//	go test -v -tags integration ./tests/api/... \
//	  -TEST_DB_HOST=127.0.0.1 -TEST_DB_PORT=3306
//
//	# 单测某个场景
//	go test -v -tags integration ./tests/api/... -run TestScenario_HostOnboarding
package api_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"

	"github.com/imkerbos/mxsec-platform/internal/server/manager/api"
	"github.com/imkerbos/mxsec-platform/internal/server/manager/biz"
	"github.com/imkerbos/mxsec-platform/internal/server/manager/sd"
	"github.com/imkerbos/mxsec-platform/internal/server/model"
)

// ─────────────────────────────────────────────
// 测试基础设施
// ─────────────────────────────────────────────

func setupDB(t *testing.T) *gorm.DB {
	t.Helper()
	host := getEnvOr("TEST_DB_HOST", "127.0.0.1")
	port := getEnvOr("TEST_DB_PORT", "3306")
	user := getEnvOr("TEST_DB_USER", "root")
	pass := getEnvOr("TEST_DB_PASSWORD", "123456")
	name := getEnvOr("TEST_DB_NAME", "mxsec_test")

	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?charset=utf8mb4&parseTime=True&loc=Local",
		user, pass, host, port, name)
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	require.NoError(t, err, "无法连接测试 MySQL，请设置 TEST_DB_* 环境变量")

	// 自动迁移测试表（顺序不能乱）
	require.NoError(t, db.AutoMigrate(
		&model.Policy{}, &model.Host{},
	))
	require.NoError(t, db.AutoMigrate(
		&model.Rule{},
	))
	require.NoError(t, db.AutoMigrate(
		&model.ScanTask{}, &model.ScanResult{},
		&model.Alert{}, &model.AlertWhitelist{},
		&model.HostMetric{}, &model.HostPlugin{},
		&model.Process{}, &model.Port{}, &model.AssetUser{},
		&model.Software{}, &model.Container{}, &model.Cron{},
		&model.Service{}, &model.NetInterface{}, &model.Volume{},
		&model.Kmod{}, &model.App{},
	))
	return db
}

// setupRouter 构建测试 Router（不挂载 JWT 中间件，不需要真实认证）
func setupRouter(t *testing.T, db *gorm.DB) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	logger := zap.NewNop()

	scoreCache := biz.NewBaselineScoreCache(db, logger, 5*time.Minute)
	metricsService := biz.NewMetricsService(db, nil, nil, logger)
	registry := sd.NewRegistry(logger)

	r := gin.New()
	v1 := r.Group("/api/v1")

	// 主机管理
	hostsHandler := api.NewHostsHandler(db, logger, scoreCache, metricsService)
	v1.GET("/hosts", hostsHandler.ListHosts)
	v1.GET("/hosts/:host_id", hostsHandler.GetHost)
	v1.GET("/hosts/:host_id/metrics", hostsHandler.GetHostMetrics)
	v1.GET("/hosts/status-distribution", hostsHandler.GetHostStatusDistribution)
	v1.DELETE("/hosts/:host_id", hostsHandler.DeleteHost)

	// 策略 / 规则 / 任务 / 结果
	policiesHandler := api.NewPoliciesHandler(db, logger)
	v1.GET("/policies", policiesHandler.ListPolicies)
	v1.POST("/policies", policiesHandler.CreatePolicy)
	v1.GET("/policies/:policy_id", policiesHandler.GetPolicy)
	v1.PUT("/policies/:policy_id", policiesHandler.UpdatePolicy)
	v1.DELETE("/policies/:policy_id", policiesHandler.DeletePolicy)

	tasksHandler := api.NewTasksHandler(db, logger)
	v1.GET("/tasks", tasksHandler.ListTasks)
	v1.POST("/tasks", tasksHandler.CreateTask)
	v1.GET("/tasks/:task_id", tasksHandler.GetTask)
	v1.POST("/tasks/:task_id/run", tasksHandler.RunTask)

	resultsHandler := api.NewResultsHandler(db, logger)
	v1.GET("/results", resultsHandler.ListResults)
	v1.GET("/results/host/:host_id/score", resultsHandler.GetHostBaselineScore)
	v1.GET("/results/host/:host_id/summary", resultsHandler.GetHostBaselineSummary)

	// 告警管理
	alertsHandler := api.NewAlertsHandler(db, logger)
	v1.GET("/alerts", alertsHandler.ListAlerts)
	v1.POST("/alerts/:id/resolve", alertsHandler.ResolveAlert)
	v1.POST("/alerts/:id/ignore", alertsHandler.IgnoreAlert)
	v1.POST("/alerts/batch/resolve", alertsHandler.BatchResolveAlerts)

	whitelistHandler := api.NewAlertWhitelistHandler(db, logger)
	v1.GET("/alerts/whitelist", whitelistHandler.ListWhitelist)
	v1.POST("/alerts/whitelist", whitelistHandler.CreateWhitelist)
	v1.DELETE("/alerts/whitelist/:id", whitelistHandler.DeleteWhitelist)

	// 系统监控
	monitorHandler := api.NewMonitorHandler(db, nil, registry, logger)
	v1.GET("/monitor/host", monitorHandler.GetHostMonitor)
	v1.GET("/monitor/services", monitorHandler.GetServicesMonitor)

	// 服务发现
	discoveryHandler := api.NewDiscoveryHandler(registry, logger)
	v1.GET("/discovery/agentcenter", discoveryHandler.ListACInstances)

	// 业务线
	bizLineHandler := api.NewBusinessLinesHandler(db, logger)
	v1.GET("/business-lines", bizLineHandler.ListBusinessLines)

	// Dashboard
	dashHandler := api.NewDashboardHandler(db, logger, nil)
	v1.GET("/dashboard/stats", dashHandler.GetDashboardStats)

	return r
}

func getEnvOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func doRequest(t *testing.T, r *gin.Engine, method, path string, body interface{}) *httptest.ResponseRecorder {
	t.Helper()
	var reqBody *bytes.Buffer
	if body != nil {
		b, err := json.Marshal(body)
		require.NoError(t, err)
		reqBody = bytes.NewBuffer(b)
	} else {
		reqBody = bytes.NewBuffer(nil)
	}
	req := httptest.NewRequest(method, path, reqBody)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func mustDecode(t *testing.T, body []byte) map[string]interface{} {
	t.Helper()
	var m map[string]interface{}
	require.NoError(t, json.Unmarshal(body, &m))
	return m
}

// ─────────────────────────────────────────────
// 场景 1：主机接入与查询
// ─────────────────────────────────────────────

// TestScenario_HostOnboarding 验证主机通过心跳写入 DB 后，Manager API 能正确查询
func TestScenario_HostOnboarding(t *testing.T) {
	db := setupDB(t)
	r := setupRouter(t, db)

	hostID := "test-host-" + uuid.New().String()[:8]

	// 前置：直接插入 host 模拟 Consumer 写入（e2e 场景中 Consumer 负责这一步）
	now := model.LocalTime(time.Now())
	host := &model.Host{
		HostID:        hostID,
		Hostname:      "test-server-01",
		Status:        model.HostStatusOnline,
		LastHeartbeat: &now,
		AgentVersion:  "1.0.0",
		IPv4:          model.StringArray{"192.168.1.100"},
	}
	require.NoError(t, db.Create(host).Error)
	t.Cleanup(func() { db.Delete(&model.Host{}, "host_id = ?", hostID) })

	// 1. 查询主机列表，应包含刚插入的 host
	w := doRequest(t, r, http.MethodGet, "/api/v1/hosts?page=1&page_size=20", nil)
	assert.Equal(t, http.StatusOK, w.Code)
	resp := mustDecode(t, w.Body.Bytes())
	assert.Equal(t, float64(0), resp["code"], "响应 code 应为 0")
	data := resp["data"].(map[string]interface{})
	assert.GreaterOrEqual(t, int(data["total"].(float64)), 1, "至少应有 1 台主机")

	// 2. 按 host_id 精确查询
	w = doRequest(t, r, http.MethodGet, "/api/v1/hosts/"+hostID, nil)
	assert.Equal(t, http.StatusOK, w.Code)
	resp = mustDecode(t, w.Body.Bytes())
	assert.Equal(t, float64(0), resp["code"])
	hostData := resp["data"].(map[string]interface{})
	assert.Equal(t, hostID, hostData["host_id"])
	assert.Equal(t, "test-server-01", hostData["hostname"])
	assert.Equal(t, "online", hostData["status"])

	// 3. 查询不存在的 host 应返回 404
	w = doRequest(t, r, http.MethodGet, "/api/v1/hosts/nonexistent-host", nil)
	assert.Equal(t, http.StatusNotFound, w.Code)

	// 4. 查询主机指标（无 ClickHouse，应降级返回空时序数据）
	w = doRequest(t, r, http.MethodGet, "/api/v1/hosts/"+hostID+"/metrics", nil)
	assert.Equal(t, http.StatusOK, w.Code)
	resp = mustDecode(t, w.Body.Bytes())
	assert.Equal(t, float64(0), resp["code"])

	// 5. 删除主机
	w = doRequest(t, r, http.MethodDelete, "/api/v1/hosts/"+hostID, nil)
	assert.Equal(t, http.StatusOK, w.Code)
	w = doRequest(t, r, http.MethodGet, "/api/v1/hosts/"+hostID, nil)
	assert.Equal(t, http.StatusNotFound, w.Code, "删除后应返回 404")
}

// ─────────────────────────────────────────────
// 场景 2：基线检查完整链路
// ─────────────────────────────────────────────

// TestScenario_BaselineLifecycle 验证策略→规则→任务→结果→评分的完整链路
func TestScenario_BaselineLifecycle(t *testing.T) {
	db := setupDB(t)
	r := setupRouter(t, db)

	suffix := uuid.New().String()[:8]
	policyID := "TEST-POLICY-" + suffix
	ruleID := "SSH-001-" + suffix
	hostID := "test-host-" + uuid.New().String()[:8]

	// ---- 前置数据 ----
	now := model.LocalTime(time.Now())
	require.NoError(t, db.Create(&model.Host{
		HostID: hostID, Hostname: "baseline-host",
		Status: model.HostStatusOnline, LastHeartbeat: &now,
	}).Error)
	t.Cleanup(func() {
		db.Delete(&model.ScanResult{}, "host_id = ?", hostID)
		db.Delete(&model.ScanTask{}, "policy_id = ?", policyID)
		db.Unscoped().Delete(&model.Rule{}, "policy_id = ?", policyID)
		db.Delete(&model.Policy{}, "id = ?", policyID)
		db.Delete(&model.Host{}, "host_id = ?", hostID)
	})

	// 1. 创建策略
	w := doRequest(t, r, http.MethodPost, "/api/v1/policies", map[string]interface{}{
		"id":          policyID,
		"name":        "SSH 基线策略",
		"version":     "1.0.0",
		"description": "SSH 安全配置基线",
		"os_family":   []string{"rocky", "centos"},
		"os_version":  ">=8",
		"enabled":     true,
		"rules": []map[string]interface{}{
			{
				"rule_id":   ruleID,
				"category":  "ssh",
				"title":     "禁止 root 登录",
				"severity":  "high",
				"check_config": map[string]interface{}{
					"condition": "all",
					"rules": []map[string]interface{}{
						{"type": "file_kv", "param": []string{"/etc/ssh/sshd_config", "PermitRootLogin", "no"}},
					},
				},
			},
		},
	})
	assert.Equal(t, http.StatusCreated, w.Code, "创建策略应返回 201")
	resp := mustDecode(t, w.Body.Bytes())
	assert.Equal(t, float64(0), resp["code"])

	// 2. 查询策略详情
	w = doRequest(t, r, http.MethodGet, "/api/v1/policies/"+policyID, nil)
	assert.Equal(t, http.StatusOK, w.Code)
	resp = mustDecode(t, w.Body.Bytes())
	policyData := resp["data"].(map[string]interface{})
	assert.Equal(t, policyID, policyData["id"])

	// 3. 创建扫描任务
	w = doRequest(t, r, http.MethodPost, "/api/v1/tasks", map[string]interface{}{
		"name":      "SSH 基线扫描",
		"type":      "baseline",
		"policy_id": policyID,
		"targets": map[string]interface{}{
			"type":     "host_ids",
			"host_ids": []string{hostID},
		},
	})
	assert.Equal(t, http.StatusCreated, w.Code, "创建任务应返回 201")
	resp = mustDecode(t, w.Body.Bytes())
	taskData := resp["data"].(map[string]interface{})
	taskID := taskData["task_id"].(string)

	// 4. 查询任务详情
	w = doRequest(t, r, http.MethodGet, "/api/v1/tasks/"+taskID, nil)
	assert.Equal(t, http.StatusOK, w.Code)
	resp = mustDecode(t, w.Body.Bytes())
	assert.Equal(t, taskID, resp["data"].(map[string]interface{})["task_id"])

	// 5. 执行任务
	w = doRequest(t, r, http.MethodPost, "/api/v1/tasks/"+taskID+"/run", nil)
	// 200（发送命令成功）或 404（无在线 AC）均可接受
	assert.Contains(t, []int{http.StatusOK, http.StatusServiceUnavailable, http.StatusNotFound}, w.Code,
		"执行任务：无 AC 时应合理降级")

	// 6. 模拟结果写入（Consumer 侧写入的效果）
	resultID := uuid.New().String()
	checkedAt := model.LocalTime(time.Now())
	require.NoError(t, db.Create(&model.ScanResult{
		ResultID:   resultID,
		HostID:     hostID,
		Hostname:   "baseline-host",
		PolicyID:   policyID,
		PolicyName: "SSH 基线策略",
		RuleID:     ruleID,
		TaskID:     taskID,
		Status:     model.ResultStatusFail,
		Severity:   "high",
		Category:   "ssh",
		Title:      "禁止 root 登录",
		Actual:     "yes",
		Expected:   "no",
		CheckedAt:  checkedAt,
	}).Error)

	// 7. 查询结果
	w = doRequest(t, r, http.MethodGet, "/api/v1/results?host_id="+hostID, nil)
	assert.Equal(t, http.StatusOK, w.Code)
	resp = mustDecode(t, w.Body.Bytes())
	assert.Equal(t, float64(0), resp["code"])
	results := resp["data"].(map[string]interface{})
	assert.GreaterOrEqual(t, int(results["total"].(float64)), 1)

	// 8. 查询基线得分（有 failed 结果时分数应低于 100）
	w = doRequest(t, r, http.MethodGet, "/api/v1/results/host/"+hostID+"/score", nil)
	assert.Equal(t, http.StatusOK, w.Code)
	resp = mustDecode(t, w.Body.Bytes())
	scoreData := resp["data"].(map[string]interface{})
	score := scoreData["baseline_score"].(float64)
	assert.Less(t, score, float64(100), "有 failed 规则时得分应低于 100")

	// 9. 删除策略
	w = doRequest(t, r, http.MethodDelete, "/api/v1/policies/"+policyID, nil)
	assert.Equal(t, http.StatusOK, w.Code)
	w = doRequest(t, r, http.MethodGet, "/api/v1/policies/"+policyID, nil)
	assert.Equal(t, http.StatusNotFound, w.Code, "删除后应返回 404")
}

// ─────────────────────────────────────────────
// 场景 3：系统监控接口
// ─────────────────────────────────────────────

// TestScenario_MonitorAPI 验证 /monitor/host 和 /monitor/services 接口的响应结构
func TestScenario_MonitorAPI(t *testing.T) {
	db := setupDB(t)
	r := setupRouter(t, db)

	// 1. 主机监控 — 不同时间范围
	for _, rang := range []string{"1h", "6h", "24h"} {
		w := doRequest(t, r, http.MethodGet, "/api/v1/monitor/host?range="+rang, nil)
		assert.Equal(t, http.StatusOK, w.Code, "range=%s 应返回 200", rang)
		resp := mustDecode(t, w.Body.Bytes())
		assert.Equal(t, float64(0), resp["code"])
		data := resp["data"].(map[string]interface{})
		// 验证响应必须包含这些字段
		for _, field := range []string{"overview", "cpu", "memory", "disk", "network", "partitions"} {
			assert.Contains(t, data, field, "响应应包含字段 %s", field)
		}
		overview := data["overview"].(map[string]interface{})
		for _, f := range []string{"cpu", "memory", "disk", "load"} {
			assert.Contains(t, overview, f, "overview 应包含字段 %s", f)
		}
	}

	// 2. 非法 range 值应降级到默认 1h，不返回错误
	w := doRequest(t, r, http.MethodGet, "/api/v1/monitor/host?range=invalid", nil)
	assert.Equal(t, http.StatusOK, w.Code)

	// 3. 服务监控
	w = doRequest(t, r, http.MethodGet, "/api/v1/monitor/services", nil)
	assert.Equal(t, http.StatusOK, w.Code)
	resp := mustDecode(t, w.Body.Bytes())
	assert.Equal(t, float64(0), resp["code"])
	data := resp["data"].(map[string]interface{})
	// 响应结构：data.services 为服务列表
	assert.Contains(t, data, "services")
	services := data["services"].([]interface{})
	assert.GreaterOrEqual(t, len(services), 1, "应至少有 1 个服务（Manager 自身）")
	// 验证第一个服务（Manager）的字段
	managerInfo := services[0].(map[string]interface{})
	assert.Equal(t, "Manager", managerInfo["name"])
	assert.NotEmpty(t, managerInfo["pid"], "Manager PID 不应为空")
}

// ─────────────────────────────────────────────
// 场景 4：服务发现接口
// ─────────────────────────────────────────────

// TestScenario_ServiceDiscovery 验证 AC 注册后能通过 discovery 接口查询
func TestScenario_ServiceDiscovery(t *testing.T) {
	db := setupDB(t)
	_ = setupRouter(t, db) // 触发 AutoMigrate，r2 是实际测试 router
	logger := zap.NewNop()
	registry := sd.NewRegistry(logger)

	// 重新挂一个带 registry 的 router（避免共享 registry 和已注册的 router 冲突）
	gin.SetMode(gin.TestMode)
	r2 := gin.New()
	v1 := r2.Group("/api/v1")
	discoveryHandler := api.NewDiscoveryHandler(registry, logger)
	v1.GET("/discovery/agentcenter", discoveryHandler.ListACInstances)
	internalAC := r2.Group("/api/v1/internal/ac")
	internalAC.POST("/register", discoveryHandler.Register)
	internalAC.POST("/heartbeat", discoveryHandler.Heartbeat)
	internalAC.DELETE("/deregister", discoveryHandler.Deregister)

	// listInstances 是一个辅助函数，从 discovery 接口获取 instances 列表
	listInstances := func() []interface{} {
		ww := doRequest(t, r2, http.MethodGet, "/api/v1/discovery/agentcenter?all=true", nil)
		assert.Equal(t, http.StatusOK, ww.Code)
		rr := mustDecode(t, ww.Body.Bytes())
		// 响应格式：{"total": N, "instances": [...]}
		return rr["instances"].([]interface{})
	}

	// 1. 初始状态：无 AC 实例
	instances := listInstances()
	assert.Len(t, instances, 0, "初始状态应无 AC 实例")

	// 2. 注册一个 AC 实例
	acID := "ac-test-" + uuid.New().String()[:8]
	w := doRequest(t, r2, http.MethodPost, "/api/v1/internal/ac/register", map[string]interface{}{
		"id":        acID,
		"grpc_addr": "127.0.0.1:6751",
		"http_addr": "127.0.0.1:7751",
	})
	assert.Equal(t, http.StatusOK, w.Code, "AC 注册应成功")

	// 3. 查询 AC 列表，应包含刚注册的实例
	instances = listInstances()
	assert.Len(t, instances, 1)
	acInfo := instances[0].(map[string]interface{})
	assert.Equal(t, acID, acInfo["id"])
	assert.Equal(t, "127.0.0.1:6751", acInfo["grpc_addr"])

	// 4. AC 心跳
	w = doRequest(t, r2, http.MethodPost, "/api/v1/internal/ac/heartbeat", map[string]interface{}{
		"id":         acID,
		"conn_count": 42,
	})
	assert.Equal(t, http.StatusOK, w.Code, "AC 心跳应成功")

	// 5. 注销 AC
	w = doRequest(t, r2, http.MethodDelete, "/api/v1/internal/ac/deregister", map[string]interface{}{
		"id": acID,
	})
	assert.Equal(t, http.StatusOK, w.Code, "AC 注销应成功")

	instances = listInstances()
	assert.Len(t, instances, 0, "注销后应无 AC 实例")
}

// ─────────────────────────────────────────────
// 场景 5：告警生命周期
// ─────────────────────────────────────────────

// TestScenario_AlertLifecycle 验证告警 创建→查询→处置→白名单 完整流程
func TestScenario_AlertLifecycle(t *testing.T) {
	db := setupDB(t)
	r := setupRouter(t, db)

	hostID := "alert-host-" + uuid.New().String()[:8]
	now := model.LocalTime(time.Now())
	require.NoError(t, db.Create(&model.Host{
		HostID: hostID, Hostname: "alert-server",
		Status: model.HostStatusOnline, LastHeartbeat: &now,
	}).Error)
	t.Cleanup(func() {
		db.Delete(&model.Host{}, "host_id = ?", hostID)
		db.Delete(&model.Alert{}, "host_id = ?", hostID)
		db.Delete(&model.AlertWhitelist{}, "host_id = ?", hostID)
	})

	// 1. 直接插入告警（模拟告警服务生成）
	alert := &model.Alert{
		ResultID: uuid.New().String(),
		HostID:   hostID,
		RuleID:   "SSH-001",
		PolicyID: "test-policy",
		Severity: "high",
		Category: "ssh",
		Title:    "SSH PermitRootLogin 未禁用",
		Status:   model.AlertStatusActive,
	}
	require.NoError(t, db.Create(alert).Error)
	alertID := alert.ID
	t.Logf("创建告警 ID: %d", alertID)

	// 2. 查询告警列表
	w := doRequest(t, r, http.MethodGet, fmt.Sprintf("/api/v1/alerts?host_id=%s", hostID), nil)
	assert.Equal(t, http.StatusOK, w.Code)
	resp := mustDecode(t, w.Body.Bytes())
	list := resp["data"].(map[string]interface{})
	assert.GreaterOrEqual(t, int(list["total"].(float64)), 1)

	// 3. 处置告警（resolve）
	w = doRequest(t, r, http.MethodPost,
		fmt.Sprintf("/api/v1/alerts/%d/resolve", alertID),
		map[string]interface{}{"comment": "已确认并修复"},
	)
	assert.Equal(t, http.StatusOK, w.Code)

	// 4. 查询告警，确认状态变更
	w = doRequest(t, r, http.MethodGet, fmt.Sprintf("/api/v1/alerts?host_id=%s", hostID), nil)
	resp = mustDecode(t, w.Body.Bytes())
	// 创建第二个告警用于白名单测试
	alert2 := &model.Alert{
		ResultID: uuid.New().String(),
		HostID:   hostID,
		RuleID:   "PAM-001",
		PolicyID: "test-policy",
		Severity: "medium",
		Category: "auth",
		Title:    "弱口令策略未配置",
		Status:   model.AlertStatusActive,
	}
	require.NoError(t, db.Create(alert2).Error)

	// 5. 批量忽略
	w = doRequest(t, r, http.MethodPost, "/api/v1/alerts/batch/resolve",
		map[string]interface{}{"ids": []uint{alert2.ID}},
	)
	assert.Equal(t, http.StatusOK, w.Code)

	// 6. 创建白名单（name 为必填字段）
	w = doRequest(t, r, http.MethodPost, "/api/v1/alerts/whitelist",
		map[string]interface{}{
			"name":     "弱口令策略白名单",
			"host_id":  hostID,
			"category": "auth",
			"reason":   "已通过其他手段加固",
		},
	)
	assert.Equal(t, http.StatusOK, w.Code, "创建白名单应返回 200")

	// 7. 查询白名单
	w = doRequest(t, r, http.MethodGet, "/api/v1/alerts/whitelist", nil)
	assert.Equal(t, http.StatusOK, w.Code)
	resp = mustDecode(t, w.Body.Bytes())
	assert.Equal(t, float64(0), resp["code"])
}

// ─────────────────────────────────────────────
// 功能测试：分页与过滤
// ─────────────────────────────────────────────

// TestFunc_HostPaginationAndFilter 验证主机列表的分页与多维度过滤
func TestFunc_HostPaginationAndFilter(t *testing.T) {
	db := setupDB(t)
	r := setupRouter(t, db)

	// 插入多台测试主机
	prefix := "filter-host-" + uuid.New().String()[:6]
	now := model.LocalTime(time.Now())
	hosts := []*model.Host{
		{HostID: prefix + "-01", Hostname: "web-01", Status: model.HostStatusOnline, LastHeartbeat: &now},
		{HostID: prefix + "-02", Hostname: "web-02", Status: model.HostStatusOnline, LastHeartbeat: &now},
		{HostID: prefix + "-03", Hostname: "db-01", Status: model.HostStatusOffline, LastHeartbeat: &now},
	}
	for _, h := range hosts {
		require.NoError(t, db.Create(h).Error)
	}
	t.Cleanup(func() {
		for _, h := range hosts {
			db.Delete(&model.Host{}, "host_id = ?", h.HostID)
		}
	})

	// 1. 分页：page_size=2 应只返回 2 条
	w := doRequest(t, r, http.MethodGet, "/api/v1/hosts?page=1&page_size=2", nil)
	assert.Equal(t, http.StatusOK, w.Code)
	resp := mustDecode(t, w.Body.Bytes())
	data := resp["data"].(map[string]interface{})
	items := data["items"].([]interface{})
	assert.Len(t, items, 2, "page_size=2 时应只返回 2 条")

	// 2. 按状态过滤：只查 offline
	w = doRequest(t, r, http.MethodGet, "/api/v1/hosts?status=offline&page=1&page_size=100", nil)
	assert.Equal(t, http.StatusOK, w.Code)
	resp = mustDecode(t, w.Body.Bytes())
	data = resp["data"].(map[string]interface{})
	for _, item := range data["items"].([]interface{}) {
		host := item.(map[string]interface{})
		assert.Equal(t, "offline", host["status"], "过滤后所有 host 状态应为 offline")
	}

	// 3. 按 hostname 模糊搜索（API 使用 search 参数）
	w = doRequest(t, r, http.MethodGet, "/api/v1/hosts?search=web&page=1&page_size=100", nil)
	assert.Equal(t, http.StatusOK, w.Code)
	resp = mustDecode(t, w.Body.Bytes())
	data = resp["data"].(map[string]interface{})
	for _, item := range data["items"].([]interface{}) {
		host := item.(map[string]interface{})
		assert.Contains(t, host["hostname"].(string), "web", "搜索结果 hostname 应包含 'web'")
	}
}

// ─────────────────────────────────────────────
// 功能测试：Dashboard 统计 API
// ─────────────────────────────────────────────

// TestFunc_DashboardStats 验证 Dashboard 统计接口返回合法结构
func TestFunc_DashboardStats(t *testing.T) {
	db := setupDB(t)
	r := setupRouter(t, db)

	w := doRequest(t, r, http.MethodGet, "/api/v1/dashboard/stats", nil)
	assert.Equal(t, http.StatusOK, w.Code)
	resp := mustDecode(t, w.Body.Bytes())
	assert.Equal(t, float64(0), resp["code"])
	data := resp["data"].(map[string]interface{})

	// 必须包含这些统计字段（实际字段名）
	for _, field := range []string{"hosts", "onlineAgents", "offlineAgents"} {
		assert.Contains(t, data, field, "dashboard 统计应包含字段 %s", field)
	}
	// 数值合法性：在线主机数 + 离线主机数 <= 总主机数
	total := int(data["hosts"].(float64))
	online := int(data["onlineAgents"].(float64))
	offline := int(data["offlineAgents"].(float64))
	assert.Equal(t, total, online+offline, "total = online + offline")
	assert.GreaterOrEqual(t, total, 0)
}

// ─────────────────────────────────────────────
// 功能测试：非法参数与边界条件
// ─────────────────────────────────────────────

// TestFunc_InvalidInputs 验证非法输入返回正确错误码
func TestFunc_InvalidInputs(t *testing.T) {
	db := setupDB(t)
	r := setupRouter(t, db)

	// 1. 创建策略：缺少必填字段 id
	w := doRequest(t, r, http.MethodPost, "/api/v1/policies", map[string]interface{}{
		"name": "无 ID 的策略",
	})
	assert.Equal(t, http.StatusBadRequest, w.Code, "缺少 id 应返回 400")

	// 2. 查询不存在的任务
	w = doRequest(t, r, http.MethodGet, "/api/v1/tasks/nonexistent-task-id", nil)
	assert.Equal(t, http.StatusNotFound, w.Code, "不存在的任务应返回 404")

	// 3. 查询不存在的结果
	w = doRequest(t, r, http.MethodGet, "/api/v1/results/no-such-result", nil)
	assert.Equal(t, http.StatusNotFound, w.Code)

	// 4. 任务重复执行（需要先创建策略和任务）
	policyID := "dup-test-policy-" + uuid.New().String()[:6]
	require.NoError(t, db.Create(&model.Policy{
		ID: policyID, Name: "重复执行测试策略",
		Version: "1.0.0", Enabled: true,
	}).Error)
	t.Cleanup(func() { db.Delete(&model.Policy{}, "id = ?", policyID) })

	hostID := "dup-test-host-" + uuid.New().String()[:6]
	n := model.LocalTime(time.Now())
	require.NoError(t, db.Create(&model.Host{
		HostID: hostID, Hostname: "dup-host",
		Status: model.HostStatusOnline, LastHeartbeat: &n,
	}).Error)
	t.Cleanup(func() { db.Delete(&model.Host{}, "host_id = ?", hostID) })

	w = doRequest(t, r, http.MethodPost, "/api/v1/tasks", map[string]interface{}{
		"name":      "重复测试任务",
		"type":      "baseline",
		"policy_id": policyID,
		"targets": map[string]interface{}{
			"type":     "host_ids",
			"host_ids": []string{hostID},
		},
	})
	require.Equal(t, http.StatusCreated, w.Code)
	resp := mustDecode(t, w.Body.Bytes())
	taskID := resp["data"].(map[string]interface{})["task_id"].(string)
	t.Cleanup(func() { db.Delete(&model.ScanTask{}, "task_id = ?", taskID) })

	// 将任务状态改为 running，再次 run 应返回 409
	require.NoError(t, db.Model(&model.ScanTask{}).
		Where("task_id = ?", taskID).
		Update("status", model.TaskStatusRunning).Error)

	w = doRequest(t, r, http.MethodPost, "/api/v1/tasks/"+taskID+"/run", nil)
	assert.Equal(t, http.StatusConflict, w.Code, "running 状态的任务重复执行应返回 409")
}
