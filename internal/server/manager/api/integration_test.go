//go:build integration
// +build integration

// Package api 提供 HTTP API 处理器集成测试
package api

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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/manager/biz"
	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// setupTestDB 创建测试数据库（使用 MySQL 环境）
func setupTestDB(t *testing.T) *gorm.DB {
	// 从环境变量读取测试数据库配置，如果没有则使用默认值
	testDBHost := os.Getenv("TEST_DB_HOST")
	if testDBHost == "" {
		// 检查是否在容器中运行（检查 /.dockerenv 文件）
		if _, err := os.Stat("/.dockerenv"); err == nil {
			// 在容器中，使用 host.docker.internal 访问宿主机 MySQL（macOS/Windows）
			// 对于 Linux，可以使用环境变量指定为 172.17.0.1
			testDBHost = "host.docker.internal"
		} else {
			// 在本地，使用 127.0.0.1
			testDBHost = "127.0.0.1"
		}
	}
	testDBPort := os.Getenv("TEST_DB_PORT")
	if testDBPort == "" {
		testDBPort = "3306"
	}
	testDBUser := os.Getenv("TEST_DB_USER")
	if testDBUser == "" {
		testDBUser = "mxcwpp_user"
	}
	testDBPassword := os.Getenv("TEST_DB_PASSWORD")
	if testDBPassword == "" {
		testDBPassword = "mxcwpp_password"
	}
	testDBName := os.Getenv("TEST_DB_NAME")
	if testDBName == "" {
		testDBName = "mxcwpp_test"
	}

	// 构建 MySQL DSN
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?charset=utf8mb4&parseTime=True&loc=Local",
		testDBUser, testDBPassword, testDBHost, testDBPort, testDBName)

	// 连接数据库
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	require.NoError(t, err)

	// 禁用外键检查，以便可以独立创建表
	db.Exec("SET FOREIGN_KEY_CHECKS=0")
	defer db.Exec("SET FOREIGN_KEY_CHECKS=1")

	// 使用 DisableForeignKeyConstraintWhenMigrating 选项来避免外键约束问题
	// 只在测试数据库中，不会影响生产环境
	db2 := db.Session(&gorm.Session{AllowGlobalUpdate: true})
	db2.Migrator().DropTable(
		&model.ScanResult{},
		&model.Host{},
		&model.Policy{},
		&model.Rule{},
		&model.ScanTask{},
		&model.Process{},
		&model.Port{},
		&model.AssetUser{},
		&model.SystemConfig{},
	)

	// 创建表（ScanResult 必须先创建，因为 Host 有外键指向它）
	err = db2.AutoMigrate(
		&model.ScanResult{},
		&model.Host{},
		&model.Policy{},
		&model.Rule{},
		&model.ScanTask{},
		&model.Process{},
		&model.Port{},
		&model.AssetUser{},
		&model.SystemConfig{},
	)
	require.NoError(t, err)

	return db
}

// setupTestRouter 创建测试路由
func setupTestRouter(db *gorm.DB) *gin.Engine {
	gin.SetMode(gin.TestMode)
	logger := zap.NewNop()

	router := gin.New()
	apiV1 := router.Group("/api/v1")

	// 创建基线得分缓存
	scoreCache := biz.NewBaselineScoreCache(db, logger, 5*time.Minute)
	metricsService := biz.NewMetricsService(db, nil, nil, logger)

	// 注册 API
	hostsHandler := NewHostsHandler(db, logger, scoreCache, metricsService)
	policiesHandler := NewPoliciesHandler(db, logger)
	tasksHandler := NewTasksHandler(db, logger)
	resultsHandler := NewResultsHandler(db, logger)
	assetsHandler := NewAssetsHandler(db, logger)
	systemConfigHandler := NewSystemConfigHandler(db, logger, "./uploads", "/uploads")

	apiV1.GET("/hosts", hostsHandler.ListHosts)
	apiV1.GET("/hosts/:host_id", hostsHandler.GetHost)
	apiV1.GET("/policies", policiesHandler.ListPolicies)
	apiV1.GET("/policies/:policy_id", policiesHandler.GetPolicy)
	apiV1.POST("/policies", policiesHandler.CreatePolicy)
	apiV1.PUT("/policies/:policy_id", policiesHandler.UpdatePolicy)
	apiV1.DELETE("/policies/:policy_id", policiesHandler.DeletePolicy)
	apiV1.GET("/tasks", tasksHandler.ListTasks)
	apiV1.GET("/tasks/:task_id", tasksHandler.GetTask)
	apiV1.POST("/tasks", tasksHandler.CreateTask)
	apiV1.POST("/tasks/:task_id/run", tasksHandler.RunTask)
	apiV1.GET("/results", resultsHandler.ListResults)
	apiV1.GET("/results/:result_id", resultsHandler.GetResult)
	apiV1.GET("/results/host/:host_id/score", resultsHandler.GetHostBaselineScore)
	apiV1.GET("/assets/processes", assetsHandler.ListProcesses)
	apiV1.GET("/assets/ports", assetsHandler.ListPorts)
	apiV1.GET("/assets/users", assetsHandler.ListUsers)

	// 系统配置 API
	systemConfig := apiV1.Group("/system-config")
	{
		systemConfig.GET("/site", systemConfigHandler.GetSiteConfig)
		systemConfig.PUT("/site", systemConfigHandler.UpdateSiteConfig)
		systemConfig.POST("/upload-logo", systemConfigHandler.UploadLogo)
		systemConfig.GET("/kubernetes-image", systemConfigHandler.GetKubernetesImageConfig)
		systemConfig.PUT("/kubernetes-image", systemConfigHandler.UpdateKubernetesImageConfig)
	}

	// 静态文件服务（用于访问上传的 Logo）
	router.Static("/uploads", "./uploads")

	return router
}

// TestPoliciesAPI 测试策略 API
func TestPoliciesAPI(t *testing.T) {
	db := setupTestDB(t)
	router := setupTestRouter(db)

	// 1. 创建策略
	createPolicyReq := map[string]interface{}{
		"id":          "TEST_POLICY_001",
		"name":        "测试策略",
		"version":     "1.0.0",
		"description": "这是一个测试策略",
		"os_family":   []string{"rocky", "centos"},
		"os_version":  ">=9",
		"enabled":     true,
		"rules": []map[string]interface{}{
			{
				"rule_id":     "TEST_RULE_001",
				"category":    "ssh",
				"title":       "测试规则",
				"description": "这是一个测试规则",
				"severity":    "high",
				"check_config": map[string]interface{}{
					"condition": "all",
					"rules": []map[string]interface{}{
						{
							"type":  "file_kv",
							"param": []string{"/etc/ssh/sshd_config", "PermitRootLogin", "no"},
						},
					},
				},
				"fix_config": map[string]interface{}{
					"suggestion": "修改配置文件",
				},
			},
		},
	}

	body, _ := json.Marshal(createPolicyReq)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/policies", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)

	var createResp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &createResp)
	require.NoError(t, err)
	assert.Equal(t, float64(0), createResp["code"])

	// 2. 获取策略列表
	req = httptest.NewRequest(http.MethodGet, "/api/v1/policies", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var listResp map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &listResp)
	require.NoError(t, err)
	assert.Equal(t, float64(0), listResp["code"])

	data := listResp["data"].(map[string]interface{})
	items := data["items"].([]interface{})
	assert.Greater(t, len(items), 0)

	// 3. 获取策略详情
	req = httptest.NewRequest(http.MethodGet, "/api/v1/policies/TEST_POLICY_001", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// 4. 更新策略
	updatePolicyReq := map[string]interface{}{
		"name":        "更新后的测试策略",
		"description": "更新后的描述",
		"enabled":     false,
	}

	body, _ = json.Marshal(updatePolicyReq)
	req = httptest.NewRequest(http.MethodPut, "/api/v1/policies/TEST_POLICY_001", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// 5. 删除策略
	req = httptest.NewRequest(http.MethodDelete, "/api/v1/policies/TEST_POLICY_001", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// TestTasksAPI 测试任务 API
func TestTasksAPI(t *testing.T) {
	db := setupTestDB(t)
	router := setupTestRouter(db)

	// 先创建策略（任务需要策略）
	policy := &model.Policy{
		ID:          "TEST_POLICY_001",
		Name:        "测试策略",
		Version:     "1.0.0",
		Description: "测试策略",
		OSFamily:    model.StringArray{"rocky"},
		OSVersion:   ">=9",
		Enabled:     true,
	}
	db.Create(policy)

	// 创建主机（任务需要主机）
	host := &model.Host{
		HostID:    "test-host-001",
		Hostname:  "test-host",
		OSFamily:  "rocky",
		OSVersion: "9.3",
		Status:    model.HostStatusOnline,
	}
	db.Create(host)

	// 1. 创建任务
	createTaskReq := map[string]interface{}{
		"name": "测试任务",
		"type": "baseline_scan",
		"targets": map[string]interface{}{
			"type": "all",
		},
		"policy_id": "TEST_POLICY_001",
		"rule_ids":  []string{},
	}

	body, _ := json.Marshal(createTaskReq)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tasks", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)

	var createResp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &createResp)
	require.NoError(t, err)
	assert.Equal(t, float64(0), createResp["code"])

	data := createResp["data"].(map[string]interface{})
	taskID := data["task_id"].(string)
	assert.NotEmpty(t, taskID)

	// 2. 获取任务列表
	req = httptest.NewRequest(http.MethodGet, "/api/v1/tasks", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// 3. 获取任务详情
	req = httptest.NewRequest(http.MethodGet, "/api/v1/tasks/"+taskID, nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// 4. 执行任务
	req = httptest.NewRequest(http.MethodPost, "/api/v1/tasks/"+taskID+"/run", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// TestResultsAPI 测试结果 API
func TestResultsAPI(t *testing.T) {
	db := setupTestDB(t)
	router := setupTestRouter(db)

	// 创建测试数据
	host := &model.Host{
		HostID:    "test-host-001",
		Hostname:  "test-host",
		OSFamily:  "rocky",
		OSVersion: "9.3",
		Status:    model.HostStatusOnline,
	}
	db.Create(host)

	result := &model.ScanResult{
		ResultID:      "test-result-001",
		HostID:        "test-host-001",
		PolicyID:      "TEST_POLICY_001",
		RuleID:        "TEST_RULE_001",
		TaskID:        "test-task-001",
		Status:        model.ResultStatusPass,
		Severity:      "high",
		Category:      "ssh",
		Title:         "测试规则",
		Actual:        "no",
		Expected:      "no",
		FixSuggestion: "无需修复",
	}
	db.Create(result)

	// 1. 获取结果列表
	req := httptest.NewRequest(http.MethodGet, "/api/v1/results?host_id=test-host-001", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var listResp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &listResp)
	require.NoError(t, err)
	assert.Equal(t, float64(0), listResp["code"])

	// 2. 获取结果详情
	req = httptest.NewRequest(http.MethodGet, "/api/v1/results/test-result-001", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// 3. 获取主机基线得分
	req = httptest.NewRequest(http.MethodGet, "/api/v1/results/host/test-host-001/score", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// TestAssetsAPI 测试资产 API
func TestAssetsAPI(t *testing.T) {
	db := setupTestDB(t)
	router := setupTestRouter(db)

	// 创建测试主机
	host := &model.Host{
		HostID:    "test-host-001",
		Hostname:  "test-host",
		OSFamily:  "rocky",
		OSVersion: "9.3",
		Status:    model.HostStatusOnline,
	}
	db.Create(host)

	// 创建测试进程数据
	process := &model.Process{
		ID:          "test-process-001",
		HostID:      "test-host-001",
		PID:         "1234",
		PPID:        "1",
		Cmdline:     "/usr/bin/python3 app.py",
		Exe:         "/usr/bin/python3",
		ExeHash:     "abc123",
		ContainerID: "",
		UID:         "1000",
		GID:         "1000",
		Username:    "user",
		Groupname:   "user",
	}
	db.Create(process)

	// 创建测试端口数据
	port := &model.Port{
		ID:          "test-port-001",
		HostID:      "test-host-001",
		Protocol:    "tcp",
		Port:        8080,
		State:       "LISTEN",
		PID:         "1234",
		ProcessName: "python3",
		ContainerID: "",
	}
	db.Create(port)

	// 创建测试账户数据
	assetUser := &model.AssetUser{
		ID:          "test-user-001",
		HostID:      "test-host-001",
		Username:    "testuser",
		UID:         "1001",
		GID:         "1001",
		Groupname:   "testgroup",
		HomeDir:     "/home/testuser",
		Shell:       "/bin/bash",
		Comment:     "Test User",
		HasPassword: true,
	}
	db.Create(assetUser)

	// 1. 测试获取进程列表
	t.Run("获取进程列表", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/assets/processes?host_id=test-host-001", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Equal(t, float64(0), resp["code"])

		data := resp["data"].(map[string]interface{})
		total := data["total"].(float64)
		assert.Greater(t, int(total), 0)

		items := data["items"].([]interface{})
		assert.Greater(t, len(items), 0)
	})

	// 2. 测试获取端口列表
	t.Run("获取端口列表", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/assets/ports?host_id=test-host-001&protocol=tcp", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Equal(t, float64(0), resp["code"])

		data := resp["data"].(map[string]interface{})
		total := data["total"].(float64)
		assert.Greater(t, int(total), 0)

		items := data["items"].([]interface{})
		assert.Greater(t, len(items), 0)
	})

	// 3. 测试获取账户列表
	t.Run("获取账户列表", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/assets/users?host_id=test-host-001", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Equal(t, float64(0), resp["code"])

		data := resp["data"].(map[string]interface{})
		total := data["total"].(float64)
		assert.Greater(t, int(total), 0)

		items := data["items"].([]interface{})
		assert.Greater(t, len(items), 0)
	})

	// 4. 测试分页功能
	t.Run("测试分页功能", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/assets/processes?page=1&page_size=10", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Equal(t, float64(0), resp["code"])

		data := resp["data"].(map[string]interface{})
		items := data["items"].([]interface{})
		assert.LessOrEqual(t, len(items), 10)
	})
}

// TestCreatePolicyAPI_ValidRequest 测试创建策略 API - 有效请求
func TestCreatePolicyAPI_ValidRequest(t *testing.T) {
	db := setupTestDB(t)
	router := setupTestRouter(db)

	createPolicyReq := map[string]interface{}{
		"id":          "POLICY_FIX_001",
		"name":        "修复测试策略",
		"version":     "1.0.0",
		"description": "用于测试 API 修复",
		"os_family":   []string{"rocky", "centos"},
		"os_version":  ">=9",
		"enabled":     true,
		"rules": []map[string]interface{}{
			{
				"rule_id":     "RULE_FIX_001",
				"category":    "ssh",
				"title":       "SSH 配置检查",
				"description": "检查 SSH 配置",
				"severity":    "high",
				"check_config": map[string]interface{}{
					"condition": "all",
					"rules": []map[string]interface{}{
						{
							"type":  "file_kv",
							"param": []string{"/etc/ssh/sshd_config", "PermitRootLogin", "no"},
						},
					},
				},
				"fix_config": map[string]interface{}{
					"suggestion": "修改配置文件",
				},
			},
		},
	}

	body, _ := json.Marshal(createPolicyReq)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/policies", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// 应该返回 201 Created
	assert.Equal(t, http.StatusCreated, w.Code, "期望 HTTP 201，但收到 %d", w.Code)

	var createResp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &createResp)
	require.NoError(t, err)
	assert.Equal(t, float64(0), createResp["code"], "期望返回码为 0，但实际为 %v", createResp["code"])
}

// TestCreatePolicyAPI_NoCheckConfig 测试创建策略 API - 不包含 CheckConfig（修复前会返回 400）
func TestCreatePolicyAPI_NoCheckConfig(t *testing.T) {
	db := setupTestDB(t)
	router := setupTestRouter(db)

	// 故意不提供 check_config，测试 API 是否能接受
	createPolicyReq := map[string]interface{}{
		"id":      "POLICY_NO_CONFIG",
		"name":    "无配置的策略",
		"enabled": true,
		"rules": []map[string]interface{}{
			{
				"rule_id": "RULE_NO_CONFIG",
				"title":   "规则无配置",
				// 注意：这里故意不提供 check_config
			},
		},
	}

	body, _ := json.Marshal(createPolicyReq)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/policies", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// 修复后应该返回 201（因为 check_config 不是必填的）
	assert.Equal(t, http.StatusCreated, w.Code, "期望 HTTP 201，但收到 %d，响应：%s", w.Code, w.Body.String())
}

// TestRunTaskAPI_Running 测试执行任务 API - 任务已在执行中（应返回 409 而不是 400）
func TestRunTaskAPI_Running(t *testing.T) {
	db := setupTestDB(t)
	router := setupTestRouter(db)

	// 创建策略
	policy := &model.Policy{
		ID:      "POLICY_RUN_TEST",
		Name:    "运行测试策略",
		Enabled: true,
	}
	db.Create(policy)

	// 创建已在运行中的任务
	task := &model.ScanTask{
		TaskID:   "TASK_RUNNING_001",
		PolicyID: "POLICY_RUN_TEST",
		Status:   model.TaskStatusRunning,
	}
	db.Create(task)

	// 尝试执行已在运行中的任务
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tasks/TASK_RUNNING_001/run", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// 修复后应该返回 409 Conflict 而不是 400 Bad Request
	assert.Equal(t, http.StatusConflict, w.Code, "期望 HTTP 409，但收到 %d", w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, float64(409), resp["code"], "期望返回码为 409，但实际为 %v", resp["code"])
}

// TestRunTaskAPI_Success 测试执行任务 API - 成功执行
func TestRunTaskAPI_Success(t *testing.T) {
	db := setupTestDB(t)
	router := setupTestRouter(db)

	// 创建策略
	policy := &model.Policy{
		ID:      "POLICY_RUN_SUCCESS",
		Name:    "成功运行测试策略",
		Enabled: true,
	}
	db.Create(policy)

	// 创建处于 pending 状态的任务
	task := &model.ScanTask{
		TaskID:   "TASK_PENDING_001",
		PolicyID: "POLICY_RUN_SUCCESS",
		Status:   model.TaskStatusPending,
	}
	db.Create(task)

	// 执行任务
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tasks/TASK_PENDING_001/run", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// 应该返回 200 OK
	assert.Equal(t, http.StatusOK, w.Code, "期望 HTTP 200，但收到 %d", w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, float64(0), resp["code"], "期望返回码为 0，但实际为 %v", resp["code"])
}
