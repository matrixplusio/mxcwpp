//go:build e2e
// +build e2e

// Package e2e 提供端到端测试，测试 Agent + Server + Plugin 完整流程
package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/proto"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"

	"github.com/imkerbos/mxsec-platform/api/proto/bridge"
	grpcProto "github.com/imkerbos/mxsec-platform/api/proto/grpc"
	"github.com/imkerbos/mxsec-platform/internal/server/agentcenter/service"
	"github.com/imkerbos/mxsec-platform/internal/server/agentcenter/transfer"
	"github.com/imkerbos/mxsec-platform/internal/server/config"
	"github.com/imkerbos/mxsec-platform/internal/server/model"
	"github.com/imkerbos/mxsec-platform/plugins/baseline/engine"
)

// TestAgentServerPluginE2E 测试 Agent + Server + Plugin 完整流程
func TestAgentServerPluginE2E(t *testing.T) {
	// 1. 设置测试环境
	logger := zap.NewNop()
	db := setupTestDB(t)
	defer func() {
		sqlDB, _ := db.DB()
		if sqlDB != nil {
			sqlDB.Close()
		}
	}()

	// 2. 启动 gRPC Server（使用随机端口）
	_, listener, _, cleanup := setupGRPCServer(t, db, logger)
	defer cleanup()

	// 获取 Server 地址
	serverAddr := listener.Addr().String()

	// 3. 创建测试主机和策略
	hostID := uuid.New().String()
	policyID := uuid.New().String()
	ruleID := uuid.New().String()

	setupTestData(t, db, hostID, policyID, ruleID)

	// 4. 模拟 Agent 连接 Server
	conn, client := connectToServer(t, serverAddr)
	defer conn.Close()

	// 5. 测试心跳上报
	t.Run("心跳上报", func(t *testing.T) {
		testHeartbeat(t, client, hostID, db)
	})

	// 6. 测试任务下发和执行
	t.Run("任务下发和执行", func(t *testing.T) {
		testTaskDispatchAndExecution(t, db, client, hostID, policyID, ruleID)
	})

	// 7. 测试检测结果上报和存储
	t.Run("检测结果上报和存储", func(t *testing.T) {
		testResultReportAndStorage(t, db, client, hostID, ruleID)
	})

	// 8. 测试基线得分计算
	t.Run("基线得分计算", func(t *testing.T) {
		testBaselineScoreCalculation(t, db, hostID)
	})
}

// setupTestDB 创建测试数据库（使用 MySQL）
func setupTestDB(t *testing.T) *gorm.DB {
	// 从环境变量读取测试数据库配置，如果没有则使用默认值
	testDBHost := os.Getenv("TEST_DB_HOST")
	if testDBHost == "" {
		testDBHost = "127.0.0.1"
	}
	testDBPort := os.Getenv("TEST_DB_PORT")
	if testDBPort == "" {
		testDBPort = "3306"
	}
	testDBUser := os.Getenv("TEST_DB_USER")
	if testDBUser == "" {
		testDBUser = "root"
	}
	testDBPassword := os.Getenv("TEST_DB_PASSWORD")
	if testDBPassword == "" {
		testDBPassword = "123456"
	}
	testDBName := os.Getenv("TEST_DB_NAME")
	if testDBName == "" {
		testDBName = "mxsec_test"
	}

	// 构建 MySQL DSN
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?charset=utf8mb4&parseTime=True&loc=Local",
		testDBUser, testDBPassword, testDBHost, testDBPort, testDBName)

	// 连接数据库
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("连接测试数据库失败: %v\n请确保 MySQL 已启动，并设置环境变量：TEST_DB_HOST, TEST_DB_PORT, TEST_DB_USER, TEST_DB_PASSWORD, TEST_DB_NAME", err)
	}

	// 迁移数据库（注意顺序：先创建被引用的表，再创建有外键的表）
	// 先创建基础表（无外键依赖）
	err = db.AutoMigrate(
		&model.Policy{},
		&model.Host{},
	)
	require.NoError(t, err)

	// 再创建依赖基础表的表
	err = db.AutoMigrate(
		&model.Rule{}, // 依赖 Policy
	)
	require.NoError(t, err)

	// 最后创建依赖多个表的表
	err = db.AutoMigrate(
		&model.ScanTask{},   // 依赖 Policy
		&model.ScanResult{}, // 依赖 Host 和 Rule
		&model.Process{},    // 资产表：进程
		&model.Port{},       // 资产表：端口
		&model.AssetUser{},  // 资产表：账户
	)
	require.NoError(t, err)

	return db
}

// setupGRPCServer 启动 gRPC Server
// 返回 gRPC Server、监听器、Transfer 服务和清理函数
func setupGRPCServer(t *testing.T, db *gorm.DB, logger *zap.Logger) (*grpc.Server, net.Listener, *transfer.Service, func()) {
	// 创建监听器（随机端口）
	listener, err := net.Listen("tcp", ":0")
	require.NoError(t, err)

	// 创建 gRPC Server（测试环境不使用 mTLS）
	grpcServer := grpc.NewServer()

	// 创建测试配置（测试环境不使用 mTLS）
	cfg := &config.Config{
		MTLS: config.MTLSConfig{
			ServerCert: "",
			ServerKey:  "",
		},
	}

	// 创建 Transfer 服务
	transferService := transfer.NewService(db, logger, cfg)

	// 注册服务
	grpcProto.RegisterTransferServer(grpcServer, transferService)

	// 创建 context 用于控制任务调度器的生命周期
	ctx, cancel := context.WithCancel(context.Background())

	// 启动任务调度器（在 goroutine 中，每 1 秒检查一次，测试环境加快速度）
	taskService := service.NewTaskService(db, logger)
	taskDone := make(chan struct{})
	go func() {
		defer close(taskDone)
		ticker := time.NewTicker(1 * time.Second) // 测试环境：每 1 秒检查一次
		defer ticker.Stop()

		// 立即执行一次
		if err := taskService.DispatchPendingTasks(transferService); err != nil {
			// 忽略数据库关闭错误（测试清理阶段）
			if err.Error() != "sql: database is closed" {
				t.Logf("分发任务失败: %v", err)
			}
		}

		// 定时执行
		for {
			select {
			case <-ctx.Done():
				return // 收到取消信号，退出
			case <-ticker.C:
				// 检查 context 是否已取消
				select {
				case <-ctx.Done():
					return
				default:
				}
				if err := taskService.DispatchPendingTasks(transferService); err != nil {
					// 忽略数据库关闭错误（测试清理阶段）
					if err.Error() != "sql: database is closed" {
						t.Logf("分发任务失败: %v", err)
					}
				}
			}
		}
	}()

	// 启动 Server（在 goroutine 中）
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		if err := grpcServer.Serve(listener); err != nil {
			t.Logf("gRPC Server 启动失败: %v", err)
		}
	}()

	// 等待 Server 启动
	time.Sleep(100 * time.Millisecond)

	// 返回清理函数
	cleanup := func() {
		// 取消任务调度器的 context
		cancel()
		// 等待任务调度器退出（最多等待 2 秒，给 ticker 一个周期的时间）
		select {
		case <-taskDone:
		case <-time.After(2 * time.Second):
			// 静默处理，不输出日志（避免测试输出噪音）
		}

		// 优雅停止 gRPC Server
		grpcServer.GracefulStop()
		// 等待 Server 退出（最多等待 2 秒）
		select {
		case <-serverDone:
		case <-time.After(2 * time.Second):
			// 静默处理，不输出日志（避免测试输出噪音）
		}
	}

	return grpcServer, listener, transferService, cleanup
}

// setupTestData 创建测试数据
func setupTestData(t *testing.T, db *gorm.DB, hostID, policyID, ruleID string) {
	// 创建主机
	host := &model.Host{
		HostID:    hostID,
		Hostname:  "test-host",
		OSFamily:  "rocky",
		OSVersion: "9.3",
		Status:    model.HostStatusOnline,
	}
	require.NoError(t, db.Create(host).Error)

	// 创建策略
	policy := &model.Policy{
		ID:        policyID,
		Name:      "测试策略",
		OSFamily:  model.StringArray{"rocky"},
		OSVersion: ">=9",
		Enabled:   true,
	}
	require.NoError(t, db.Create(policy).Error)

	// 创建规则
	rule := &model.Rule{
		RuleID:      ruleID,
		PolicyID:    policyID,
		Category:    "ssh",
		Title:       "禁止 root 远程登录",
		Description: "SSH 配置应禁止 root 远程登录",
		Severity:    "high",
		CheckConfig: model.CheckConfig{
			Condition: "all",
			Rules: []model.CheckRule{
				{
					Type:  "file_kv",
					Param: []string{"/etc/ssh/sshd_config", "PermitRootLogin", "no"},
				},
			},
		},
		FixConfig: model.FixConfig{
			Suggestion: "修改 /etc/ssh/sshd_config 中的 PermitRootLogin 为 no",
		},
	}
	require.NoError(t, db.Create(rule).Error)
}

// connectToServer 连接到 Server
func connectToServer(t *testing.T, serverAddr string) (*grpc.ClientConn, grpcProto.TransferClient) {
	conn, err := grpc.NewClient(serverAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)

	client := grpcProto.NewTransferClient(conn)
	return conn, client
}

// testHeartbeat 测试心跳上报
func testHeartbeat(t *testing.T, client grpcProto.TransferClient, hostID string, db *gorm.DB) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 创建双向流
	stream, err := client.Transfer(ctx)
	require.NoError(t, err)

	// 发送心跳数据
	heartbeat := &grpcProto.PackagedData{
		AgentId:      hostID,
		Hostname:     "test-host",
		Version:      "1.0.0",
		IntranetIpv4: []string{"192.168.1.100"},
		Records:      []*grpcProto.EncodedRecord{},
	}

	err = stream.Send(heartbeat)
	require.NoError(t, err)

	// 等待处理
	time.Sleep(200 * time.Millisecond)

	// 验证主机已更新
	var host model.Host
	err = db.Where("host_id = ?", hostID).First(&host).Error
	require.NoError(t, err)
	assert.Equal(t, "test-host", host.Hostname)
	assert.Equal(t, model.HostStatusOnline, host.Status)
	assert.NotNil(t, host.LastHeartbeat)

	// 关闭流
	stream.CloseSend()
}

// testTaskDispatchAndExecution 测试任务下发和执行
func testTaskDispatchAndExecution(t *testing.T, db *gorm.DB, client grpcProto.TransferClient, hostID, policyID, ruleID string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 创建扫描任务
	taskID := uuid.New().String()
	task := &model.ScanTask{
		TaskID:     taskID,
		Name:       "测试任务",
		Type:       model.TaskTypeBaselineScan,
		TargetType: model.TargetTypeHostIDs,
		TargetConfig: model.TargetConfig{
			HostIDs: []string{hostID},
		},
		PolicyID: policyID,
		RuleIDs:  model.StringArray{},
		Status:   model.TaskStatusPending,
	}
	require.NoError(t, db.Create(task).Error)

	// 创建双向流
	stream, err := client.Transfer(ctx)
	require.NoError(t, err)

	// 先发送心跳建立连接
	heartbeat := &grpcProto.PackagedData{
		AgentId:      hostID,
		Hostname:     "test-host",
		Version:      "1.0.0",
		IntranetIpv4: []string{"192.168.1.100"},
		Records:      []*grpcProto.EncodedRecord{},
	}
	err = stream.Send(heartbeat)
	require.NoError(t, err)

	// 等待任务调度器分发任务
	time.Sleep(1 * time.Second)

	// 接收任务（应该收到基线检查任务）
	receivedTask := false
	go func() {
		for {
			cmd, err := stream.Recv()
			if err != nil {
				return
			}
			// Command 包含 tasks 数组，检查是否有基线检查任务（data_type=8000）
			for _, task := range cmd.Tasks {
				if task.DataType == 8000 {
					receivedTask = true
					t.Logf("收到任务: %s", task.Token)
					return
				}
			}
		}
	}()

	// 等待接收任务
	time.Sleep(2 * time.Second)
	assert.True(t, receivedTask, "应该收到基线检查任务")

	stream.CloseSend()
}

// testResultReportAndStorage 测试检测结果上报和存储
func testResultReportAndStorage(t *testing.T, db *gorm.DB, client grpcProto.TransferClient, hostID, ruleID string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 创建双向流
	stream, err := client.Transfer(ctx)
	require.NoError(t, err)

	// 发送心跳建立连接
	heartbeat := &grpcProto.PackagedData{
		AgentId:      hostID,
		Hostname:     "test-host",
		Version:      "1.0.0",
		IntranetIpv4: []string{"192.168.1.100"},
		Records:      []*grpcProto.EncodedRecord{},
	}
	err = stream.Send(heartbeat)
	require.NoError(t, err)

	// 发送检测结果（使用 bridge.Record 格式）
	bridgeRecord := &bridge.Record{
		DataType:  8000, // 基线检查结果
		Timestamp: time.Now().UnixNano(),
		Data: &bridge.Payload{
			Fields: map[string]string{
				"rule_id":        ruleID,
				"policy_id":      "test-policy",
				"status":         "fail",
				"severity":       "high",
				"category":       "ssh",
				"title":          "禁止 root 远程登录",
				"actual":         "PermitRootLogin yes",
				"expected":       "PermitRootLogin no",
				"fix_suggestion": "修改 /etc/ssh/sshd_config",
				"checked_at":     time.Now().Format(time.RFC3339),
			},
		},
	}

	// 序列化为 protobuf
	recordData, err := proto.Marshal(bridgeRecord)
	require.NoError(t, err)

	resultRecord := &grpcProto.EncodedRecord{
		DataType:  8000, // 基线检查结果
		Data:      recordData,
		Timestamp: time.Now().UnixNano(),
	}

	resultPackage := &grpcProto.PackagedData{
		AgentId:      hostID,
		Hostname:     "test-host",
		Version:      "1.0.0",
		IntranetIpv4: []string{"192.168.1.100"},
		Records:      []*grpcProto.EncodedRecord{resultRecord},
	}

	err = stream.Send(resultPackage)
	require.NoError(t, err)

	// 等待处理
	time.Sleep(500 * time.Millisecond)

	// 验证结果已存储
	var result model.ScanResult
	err = db.Where("host_id = ? AND rule_id = ?", hostID, ruleID).First(&result).Error
	require.NoError(t, err)
	assert.Equal(t, model.ResultStatusFail, result.Status)
	assert.Equal(t, "high", result.Severity)
	assert.Equal(t, "ssh", result.Category)

	stream.CloseSend()
}

// testBaselineScoreCalculation 测试基线得分计算
func testBaselineScoreCalculation(t *testing.T, db *gorm.DB, hostID string) {
	// 使用独立的 hostID 避免与其他测试冲突
	testHostID := hostID + "-score-test"

	// 创建多个检测结果
	ruleIDs := []string{uuid.New().String(), uuid.New().String(), uuid.New().String()}
	now := time.Now()

	for i, ruleID := range ruleIDs {
		result := &model.ScanResult{
			ResultID:  uuid.New().String(),
			HostID:    testHostID,
			RuleID:    ruleID,
			Status:    model.ResultStatusPass,
			Severity:  "high",
			Category:  "ssh",
			Title:     fmt.Sprintf("规则 %d", i+1),
			CheckedAt: now.Add(time.Duration(i) * time.Second),
		}
		if i == 0 {
			result.Status = model.ResultStatusFail // 第一个规则失败
		}
		require.NoError(t, db.Create(result).Error)
	}

	// 查询主机最新的检测结果（模拟得分计算逻辑）
	var latestResults []struct {
		RuleID   string
		Status   string
		Severity string
	}

	subQuery := db.Model(&model.ScanResult{}).
		Select("rule_id, MAX(checked_at) as max_checked_at").
		Where("host_id = ?", testHostID).
		Group("rule_id")

	err := db.Table("scan_results").
		Select("scan_results.rule_id, scan_results.status, scan_results.severity").
		Joins("INNER JOIN (?) AS latest ON scan_results.rule_id = latest.rule_id AND scan_results.checked_at = latest.max_checked_at", subQuery).
		Where("scan_results.host_id = ?", testHostID).
		Find(&latestResults).Error
	require.NoError(t, err)

	// 验证结果
	assert.GreaterOrEqual(t, len(latestResults), 3, "应该有至少3条规则的结果")

	// 计算得分
	passCount := 0
	failCount := 0
	for _, result := range latestResults {
		if result.Status == "pass" {
			passCount++
		} else if result.Status == "fail" {
			failCount++
		}
	}

	assert.Equal(t, 2, passCount, "应该有2条规则通过")
	assert.Equal(t, 1, failCount, "应该有1条规则失败")
}

// TestBaselinePluginE2E 测试 Baseline Plugin 完整流程
func TestBaselinePluginE2E(t *testing.T) {
	logger := zap.NewNop()
	checkEngine := engine.NewEngine(logger)
	ctx := context.Background()

	// 加载示例策略
	exampleDir := filepath.Join("..", "..", "plugins", "baseline", "config", "examples")
	policyFile := filepath.Join(exampleDir, "password-policy.json")

	if _, err := os.Stat(policyFile); os.IsNotExist(err) {
		t.Skipf("示例规则文件不存在: %s", policyFile)
		return
	}

	// 读取策略文件
	data, err := os.ReadFile(policyFile)
	require.NoError(t, err)

	var policy engine.Policy
	err = json.Unmarshal(data, &policy)
	require.NoError(t, err)

	// 执行检查
	results := checkEngine.Execute(ctx, []*engine.Policy{&policy}, "rocky", "9.3")

	// 验证结果
	assert.Greater(t, len(results), 0, "应该有检查结果")

	// 验证结果格式
	for _, result := range results {
		assert.NotEmpty(t, result.RuleID, "规则ID不应为空")
		assert.NotEmpty(t, result.Status, "状态不应为空")
		assert.Contains(t, []string{"pass", "fail", "error", "na"}, string(result.Status), "状态应该是有效值")
	}
}

// TestAssetCollectionE2E 测试资产采集端到端流程
func TestAssetCollectionE2E(t *testing.T) {
	// 1. 设置测试环境
	logger := zap.NewNop()
	db := setupTestDB(t)
	defer func() {
		sqlDB, _ := db.DB()
		if sqlDB != nil {
			sqlDB.Close()
		}
	}()

	// 2. 启动 gRPC Server（使用随机端口）
	_, listener, _, cleanup := setupGRPCServer(t, db, logger)
	defer cleanup()

	// 获取 Server 地址
	serverAddr := listener.Addr().String()

	// 3. 创建测试主机
	hostID := uuid.New().String()
	setupTestHost(t, db, hostID)

	// 4. 模拟 Agent 连接 Server
	conn, client := connectToServer(t, serverAddr)
	defer conn.Close()

	// 5. 测试进程资产采集
	t.Run("进程资产采集", func(t *testing.T) {
		testProcessAssetCollection(t, db, client, hostID)
	})

	// 6. 测试端口资产采集
	t.Run("端口资产采集", func(t *testing.T) {
		testPortAssetCollection(t, db, client, hostID)
	})

	// 7. 测试账户资产采集
	t.Run("账户资产采集", func(t *testing.T) {
		testUserAssetCollection(t, db, client, hostID)
	})
}

// setupTestHost 创建测试主机
func setupTestHost(t *testing.T, db *gorm.DB, hostID string) {
	host := &model.Host{
		HostID:    hostID,
		Hostname:  "test-host-asset",
		OSFamily:  "rocky",
		OSVersion: "9.3",
		Status:    model.HostStatusOnline,
	}
	require.NoError(t, db.Create(host).Error)
}

// testProcessAssetCollection 测试进程资产采集
func testProcessAssetCollection(t *testing.T, db *gorm.DB, client grpcProto.TransferClient, hostID string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 创建双向流
	stream, err := client.Transfer(ctx)
	require.NoError(t, err)

	// 先发送心跳建立连接
	heartbeat := &grpcProto.PackagedData{
		AgentId:      hostID,
		Hostname:     "test-host-asset",
		Version:      "1.0.0",
		IntranetIpv4: []string{"192.168.1.100"},
		Records:      []*grpcProto.EncodedRecord{},
	}
	err = stream.Send(heartbeat)
	require.NoError(t, err)

	// 准备进程资产数据
	processAssets := []map[string]interface{}{
		{
			"pid":          "1",
			"ppid":         "0",
			"cmdline":      "/sbin/init",
			"exe":          "/sbin/init",
			"exe_hash":     "abc123def456",
			"container_id": "",
			"uid":          "0",
			"gid":          "0",
			"username":     "root",
			"groupname":    "root",
			"collected_at": time.Now().Format(time.RFC3339),
		},
		{
			"pid":          "100",
			"ppid":         "1",
			"cmdline":      "/usr/bin/sshd",
			"exe":          "/usr/bin/sshd",
			"exe_hash":     "def456ghi789",
			"container_id": "",
			"uid":          "0",
			"gid":          "0",
			"username":     "root",
			"groupname":    "root",
			"collected_at": time.Now().Format(time.RFC3339),
		},
	}

	// 序列化资产数据
	assetData, err := json.Marshal(processAssets)
	require.NoError(t, err)

	// 创建 bridge.Record
	bridgeRecord := &bridge.Record{
		DataType:  5050, // 进程数据类型
		Timestamp: time.Now().UnixNano(),
		Data: &bridge.Payload{
			Fields: map[string]string{
				"data": string(assetData),
			},
		},
	}

	// 序列化为 protobuf
	recordData, err := proto.Marshal(bridgeRecord)
	require.NoError(t, err)

	assetRecord := &grpcProto.EncodedRecord{
		DataType:  5050, // 进程数据类型
		Data:      recordData,
		Timestamp: time.Now().UnixNano(),
	}

	assetPackage := &grpcProto.PackagedData{
		AgentId:      hostID,
		Hostname:     "test-host-asset",
		Version:      "1.0.0",
		IntranetIpv4: []string{"192.168.1.100"},
		Records:      []*grpcProto.EncodedRecord{assetRecord},
	}

	err = stream.Send(assetPackage)
	require.NoError(t, err)

	// 等待处理
	time.Sleep(500 * time.Millisecond)

	// 验证进程数据已存储
	var processes []model.Process
	err = db.Where("host_id = ?", hostID).Find(&processes).Error
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(processes), 2, "应该有至少2个进程")

	// 验证进程数据内容
	foundInit := false
	foundSSHD := false
	for _, proc := range processes {
		if proc.PID == "1" && proc.Cmdline == "/sbin/init" {
			foundInit = true
			assert.Equal(t, "0", proc.PPID)
			assert.Equal(t, "root", proc.Username)
		}
		if proc.PID == "100" && proc.Cmdline == "/usr/bin/sshd" {
			foundSSHD = true
			assert.Equal(t, "1", proc.PPID)
			assert.Equal(t, "root", proc.Username)
		}
	}
	assert.True(t, foundInit, "应该找到 init 进程")
	assert.True(t, foundSSHD, "应该找到 sshd 进程")

	stream.CloseSend()
}

// testPortAssetCollection 测试端口资产采集
func testPortAssetCollection(t *testing.T, db *gorm.DB, client grpcProto.TransferClient, hostID string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 创建双向流
	stream, err := client.Transfer(ctx)
	require.NoError(t, err)

	// 先发送心跳建立连接
	heartbeat := &grpcProto.PackagedData{
		AgentId:      hostID,
		Hostname:     "test-host-asset",
		Version:      "1.0.0",
		IntranetIpv4: []string{"192.168.1.100"},
		Records:      []*grpcProto.EncodedRecord{},
	}
	err = stream.Send(heartbeat)
	require.NoError(t, err)

	// 准备端口资产数据
	portAssets := []map[string]interface{}{
		{
			"protocol":     "tcp",
			"port":         22,
			"state":        "LISTEN",
			"pid":          "100",
			"process_name": "sshd",
			"container_id": "",
			"collected_at": time.Now().Format(time.RFC3339),
		},
		{
			"protocol":     "tcp",
			"port":         80,
			"state":        "LISTEN",
			"pid":          "200",
			"process_name": "nginx",
			"container_id": "",
			"collected_at": time.Now().Format(time.RFC3339),
		},
		{
			"protocol":     "udp",
			"port":         53,
			"state":        "LISTEN",
			"pid":          "300",
			"process_name": "systemd-resolved",
			"container_id": "",
			"collected_at": time.Now().Format(time.RFC3339),
		},
	}

	// 序列化资产数据
	assetData, err := json.Marshal(portAssets)
	require.NoError(t, err)

	// 创建 bridge.Record
	bridgeRecord := &bridge.Record{
		DataType:  5051, // 端口数据类型
		Timestamp: time.Now().UnixNano(),
		Data: &bridge.Payload{
			Fields: map[string]string{
				"data": string(assetData),
			},
		},
	}

	// 序列化为 protobuf
	recordData, err := proto.Marshal(bridgeRecord)
	require.NoError(t, err)

	assetRecord := &grpcProto.EncodedRecord{
		DataType:  5051, // 端口数据类型
		Data:      recordData,
		Timestamp: time.Now().UnixNano(),
	}

	assetPackage := &grpcProto.PackagedData{
		AgentId:      hostID,
		Hostname:     "test-host-asset",
		Version:      "1.0.0",
		IntranetIpv4: []string{"192.168.1.100"},
		Records:      []*grpcProto.EncodedRecord{assetRecord},
	}

	err = stream.Send(assetPackage)
	require.NoError(t, err)

	// 等待处理
	time.Sleep(500 * time.Millisecond)

	// 验证端口数据已存储
	var ports []model.Port
	err = db.Where("host_id = ?", hostID).Find(&ports).Error
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(ports), 3, "应该有至少3个端口")

	// 验证端口数据内容
	foundSSH := false
	foundHTTP := false
	foundDNS := false
	for _, port := range ports {
		if port.Protocol == "tcp" && port.Port == 22 {
			foundSSH = true
			assert.Equal(t, "LISTEN", port.State)
			assert.Equal(t, "100", port.PID)
			assert.Equal(t, "sshd", port.ProcessName)
		}
		if port.Protocol == "tcp" && port.Port == 80 {
			foundHTTP = true
			assert.Equal(t, "LISTEN", port.State)
			assert.Equal(t, "200", port.PID)
			assert.Equal(t, "nginx", port.ProcessName)
		}
		if port.Protocol == "udp" && port.Port == 53 {
			foundDNS = true
			assert.Equal(t, "LISTEN", port.State)
			assert.Equal(t, "300", port.PID)
			assert.Equal(t, "systemd-resolved", port.ProcessName)
		}
	}
	assert.True(t, foundSSH, "应该找到 SSH 端口")
	assert.True(t, foundHTTP, "应该找到 HTTP 端口")
	assert.True(t, foundDNS, "应该找到 DNS 端口")

	stream.CloseSend()
}

// testUserAssetCollection 测试账户资产采集
func testUserAssetCollection(t *testing.T, db *gorm.DB, client grpcProto.TransferClient, hostID string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 创建双向流
	stream, err := client.Transfer(ctx)
	require.NoError(t, err)

	// 先发送心跳建立连接
	heartbeat := &grpcProto.PackagedData{
		AgentId:      hostID,
		Hostname:     "test-host-asset",
		Version:      "1.0.0",
		IntranetIpv4: []string{"192.168.1.100"},
		Records:      []*grpcProto.EncodedRecord{},
	}
	err = stream.Send(heartbeat)
	require.NoError(t, err)

	// 准备账户资产数据
	userAssets := []map[string]interface{}{
		{
			"username":     "root",
			"uid":          "0",
			"gid":          "0",
			"groupname":    "root",
			"home_dir":     "/root",
			"shell":        "/bin/bash",
			"comment":      "root",
			"has_password": true,
			"collected_at": time.Now().Format(time.RFC3339),
		},
		{
			"username":     "testuser",
			"uid":          "1000",
			"gid":          "1000",
			"groupname":    "testuser",
			"home_dir":     "/home/testuser",
			"shell":        "/bin/bash",
			"comment":      "Test User",
			"has_password": true,
			"collected_at": time.Now().Format(time.RFC3339),
		},
		{
			"username":     "nobody",
			"uid":          "99",
			"gid":          "99",
			"groupname":    "nobody",
			"home_dir":     "/",
			"shell":        "/sbin/nologin",
			"comment":      "Unprivileged User",
			"has_password": false,
			"collected_at": time.Now().Format(time.RFC3339),
		},
	}

	// 序列化资产数据
	assetData, err := json.Marshal(userAssets)
	require.NoError(t, err)

	// 创建 bridge.Record
	bridgeRecord := &bridge.Record{
		DataType:  5052, // 账户数据类型
		Timestamp: time.Now().UnixNano(),
		Data: &bridge.Payload{
			Fields: map[string]string{
				"data": string(assetData),
			},
		},
	}

	// 序列化为 protobuf
	recordData, err := proto.Marshal(bridgeRecord)
	require.NoError(t, err)

	assetRecord := &grpcProto.EncodedRecord{
		DataType:  5052, // 账户数据类型
		Data:      recordData,
		Timestamp: time.Now().UnixNano(),
	}

	assetPackage := &grpcProto.PackagedData{
		AgentId:      hostID,
		Hostname:     "test-host-asset",
		Version:      "1.0.0",
		IntranetIpv4: []string{"192.168.1.100"},
		Records:      []*grpcProto.EncodedRecord{assetRecord},
	}

	err = stream.Send(assetPackage)
	require.NoError(t, err)

	// 等待处理
	time.Sleep(500 * time.Millisecond)

	// 验证账户数据已存储
	var users []model.AssetUser
	err = db.Where("host_id = ?", hostID).Find(&users).Error
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(users), 3, "应该有至少3个账户")

	// 验证账户数据内容
	foundRoot := false
	foundTestUser := false
	foundNobody := false
	for _, user := range users {
		if user.Username == "root" {
			foundRoot = true
			assert.Equal(t, "0", user.UID)
			assert.Equal(t, "0", user.GID)
			assert.Equal(t, "/root", user.HomeDir)
			assert.Equal(t, "/bin/bash", user.Shell)
			assert.True(t, user.HasPassword)
		}
		if user.Username == "testuser" {
			foundTestUser = true
			assert.Equal(t, "1000", user.UID)
			assert.Equal(t, "1000", user.GID)
			assert.Equal(t, "/home/testuser", user.HomeDir)
			assert.True(t, user.HasPassword)
		}
		if user.Username == "nobody" {
			foundNobody = true
			assert.Equal(t, "99", user.UID)
			assert.Equal(t, "99", user.GID)
			assert.Equal(t, "/sbin/nologin", user.Shell)
			assert.False(t, user.HasPassword)
		}
	}
	assert.True(t, foundRoot, "应该找到 root 账户")
	assert.True(t, foundTestUser, "应该找到 testuser 账户")
	assert.True(t, foundNobody, "应该找到 nobody 账户")

	stream.CloseSend()
}
