//go:build perf
// +build perf

// Package perf 提供面向 Manager HTTP API 和 AgentCenter gRPC 的性能测试
//
// 目标：验证系统满足 1000 台主机并发、百万级数据量的性能要求
//
// 运行方式：
//
//	# 启动依赖
//	make dev-docker-up
//
//	# 全量性能测试（含数据种植）
//	go test -v -tags perf ./tests/perf/... -timeout 10m
//
//	# 仅运行 Benchmark
//	go test -tags perf -bench=. -benchmem -benchtime=30s ./tests/perf/...
package perf_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/proto"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	bridgepb "github.com/matrixplusio/mxcwpp/api/proto/bridge"
	grpcProto "github.com/matrixplusio/mxcwpp/api/proto/grpc"
	"github.com/matrixplusio/mxcwpp/internal/server/agentcenter/transfer"
	"github.com/matrixplusio/mxcwpp/internal/server/config"
	managerAPI "github.com/matrixplusio/mxcwpp/internal/server/manager/api"
	"github.com/matrixplusio/mxcwpp/internal/server/manager/biz"
	"github.com/matrixplusio/mxcwpp/internal/server/manager/sd"
	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// ─────────────────────────────────────────────
// 基础设施
// ─────────────────────────────────────────────

const (
	targetHosts   = 1000      // 目标主机数量
	targetResults = 1_000_000 // 目标结果数量（百万级）
	concurrency   = 100       // API 并发客户端数
)

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func openDB(tb testing.TB) *gorm.DB {
	tb.Helper()
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?charset=utf8mb4&parseTime=True&loc=Local",
		envOr("TEST_DB_USER", "root"),
		envOr("TEST_DB_PASSWORD", "123456"),
		envOr("TEST_DB_HOST", "127.0.0.1"),
		envOr("TEST_DB_PORT", "3306"),
		envOr("TEST_DB_NAME", "mxcwpp_perf"),
	)
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{
		Logger: logger.Discard, // 性能测试期间禁用 GORM 日志
	})
	require.NoError(tb, err, "无法连接性能测试 DB，请设置 TEST_DB_* 环境变量")
	return db
}

// setupPerfRouter 构建性能测试 Router（无 JWT、无审计中间件）
func setupPerfRouter(db *gorm.DB) *gin.Engine {
	gin.SetMode(gin.TestMode)
	log := zap.NewNop()
	scoreCache := biz.NewBaselineScoreCache(db, log, 5*time.Minute)
	metricsService := biz.NewMetricsService(db, nil, nil, log)
	registry := sd.NewRegistry(log)

	r := gin.New()
	v1 := r.Group("/api/v1")

	hostsHandler := managerAPI.NewHostsHandler(db, log, scoreCache, metricsService)
	v1.GET("/hosts", hostsHandler.ListHosts)
	v1.GET("/hosts/:host_id", hostsHandler.GetHost)
	v1.GET("/hosts/status-distribution", hostsHandler.GetHostStatusDistribution)

	resultsHandler := managerAPI.NewResultsHandler(db, log)
	v1.GET("/results", resultsHandler.ListResults)
	v1.GET("/results/host/:host_id/score", resultsHandler.GetHostBaselineScore)

	dashHandler := managerAPI.NewDashboardHandler(db, log, nil)
	v1.GET("/dashboard/stats", dashHandler.GetDashboardStats)

	monitorHandler := managerAPI.NewMonitorHandler(db, nil, registry, log)
	v1.GET("/monitor/host", monitorHandler.GetHostMonitor)
	v1.GET("/monitor/services", monitorHandler.GetServicesMonitor)

	return r
}

// seedHosts 向数据库批量写入 n 台测试主机，返回写入的 hostID 列表
// 已存在时跳过（支持重复运行）
func seedHosts(tb testing.TB, db *gorm.DB, n int) []string {
	tb.Helper()
	require.NoError(tb, db.AutoMigrate(&model.Host{}))

	hostIDs := make([]string, n)
	batch := make([]*model.Host, 0, 500)

	for i := range n {
		hostID := fmt.Sprintf("perf-host-%06d", i)
		hostIDs[i] = hostID
		now := model.LocalTime(time.Now().Add(-time.Duration(i) * time.Second))
		status := model.HostStatusOnline
		if i%10 == 0 {
			status = model.HostStatusOffline
		}
		batch = append(batch, &model.Host{
			HostID:        hostID,
			Hostname:      fmt.Sprintf("perf-server-%06d", i),
			Status:        status,
			LastHeartbeat: &now,
			AgentVersion:  "1.0.0",
			IPv4:          model.StringArray{fmt.Sprintf("10.0.%d.%d", i/256, i%256)},
		})

		if len(batch) >= 500 || i == n-1 {
			db.Clauses(
			// ON DUPLICATE KEY UPDATE 幂等写入
			).Create(&batch)
			batch = batch[:0]
		}
	}
	tb.Logf("种植 %d 台主机完成", n)
	return hostIDs
}

// seedResults 向数据库批量写入 n 条扫描结果
func seedResults(tb testing.TB, db *gorm.DB, hostIDs []string, total int) {
	tb.Helper()
	require.NoError(tb, db.AutoMigrate(&model.ScanResult{}))

	const batchSize = 5000
	batch := make([]*model.ScanResult, 0, batchSize)

	for i := range total {
		hostID := hostIDs[i%len(hostIDs)]
		status := model.ResultStatusPass
		if i%3 == 0 {
			status = model.ResultStatusFail
		}
		batch = append(batch, &model.ScanResult{
			ResultID:  fmt.Sprintf("perf-result-%08d", i),
			HostID:    hostID,
			Hostname:  fmt.Sprintf("perf-server-%s", hostID[len(hostID)-6:]),
			PolicyID:  "perf-policy-001",
			RuleID:    fmt.Sprintf("RULE-%04d", i%100),
			TaskID:    "perf-task-001",
			Status:    status,
			Severity:  "high",
			Category:  "ssh",
			Title:     fmt.Sprintf("检查项 %d", i%100),
			CheckedAt: model.LocalTime(time.Now().Add(-time.Duration(i) * time.Second)),
		})

		if len(batch) >= batchSize || i == total-1 {
			if err := db.Create(&batch).Error; err != nil {
				tb.Logf("批量插入结果出错（可能是重复，忽略）: %v", err)
			}
			batch = batch[:0]
			if i%50000 == 0 {
				tb.Logf("结果种植进度: %d/%d", i, total)
			}
		}
	}
	tb.Logf("种植 %d 条结果完成", total)
}

// doGet 执行 HTTP GET，返回状态码和响应体
func doGet(r *gin.Engine, path string) (int, map[string]interface{}) {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	var resp map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	return w.Code, resp
}

// doPost 执行 HTTP POST
func doPost(r *gin.Engine, path string, body interface{}) (int, map[string]interface{}) {
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewBuffer(b))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	var resp map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	return w.Code, resp
}

// ─────────────────────────────────────────────
// 性能测试：ListHosts — 1000 台主机查询
// ─────────────────────────────────────────────

// TestPerf_ListHosts_1000 验证 1000 台主机下列表 API 的响应时间和正确性
func TestPerf_ListHosts_1000(t *testing.T) {
	db := openDB(t)
	seedHosts(t, db, targetHosts)
	r := setupPerfRouter(db)

	// 1. 不分页获取总数
	code, resp := doGet(r, "/api/v1/hosts?page=1&page_size=1")
	require.Equal(t, http.StatusOK, code)
	total := int(resp["data"].(map[string]interface{})["total"].(float64))
	assert.GreaterOrEqual(t, total, targetHosts, "DB 中应至少有 %d 台主机", targetHosts)

	// 2. 分页响应时间：每页 20 条，查第 1/10/50 页
	for _, page := range []int{1, 10, 50} {
		start := time.Now()
		code, resp = doGet(r, fmt.Sprintf("/api/v1/hosts?page=%d&page_size=20", page))
		elapsed := time.Since(start)
		assert.Equal(t, http.StatusOK, code)
		t.Logf("ListHosts page=%d: %v", page, elapsed)
		assert.Less(t, elapsed, 500*time.Millisecond,
			"第 %d 页响应时间应 < 500ms，实际 %v", page, elapsed)
	}

	// 3. 状态过滤
	start := time.Now()
	code, _ = doGet(r, "/api/v1/hosts?status=online&page=1&page_size=20")
	elapsed := time.Since(start)
	assert.Equal(t, http.StatusOK, code)
	t.Logf("ListHosts status=online: %v", elapsed)
	assert.Less(t, elapsed, 500*time.Millisecond)

	// 4. 主机状态分布统计
	start = time.Now()
	code, resp = doGet(r, "/api/v1/hosts/status-distribution")
	elapsed = time.Since(start)
	assert.Equal(t, http.StatusOK, code)
	t.Logf("GetHostStatusDistribution: %v", elapsed)
	assert.Less(t, elapsed, 200*time.Millisecond)
}

// ─────────────────────────────────────────────
// 性能测试：ListResults — 百万级数据量
// ─────────────────────────────────────────────

// TestPerf_ListResults_1M 验证百万级结果数据下分页查询性能
func TestPerf_ListResults_1M(t *testing.T) {
	if os.Getenv("SEED_1M") != "1" {
		t.Skip("跳过 1M 数据种植（设置 SEED_1M=1 启用）")
	}

	db := openDB(t)
	hostIDs := seedHosts(t, db, targetHosts)
	seedResults(t, db, hostIDs, targetResults)
	r := setupPerfRouter(db)

	cases := []struct {
		name    string
		path    string
		maxTime time.Duration
	}{
		{"默认分页第1页", "/api/v1/results?page=1&page_size=20", 500 * time.Millisecond},
		{"默认分页第100页", "/api/v1/results?page=100&page_size=20", 1 * time.Second},
		{"按主机过滤", "/api/v1/results?host_id=perf-host-000001&page=1&page_size=20", 500 * time.Millisecond},
		{"按状态过滤(failed)", "/api/v1/results?status=failed&page=1&page_size=20", 500 * time.Millisecond},
		{"主机得分计算", "/api/v1/results/host/perf-host-000001/score", 200 * time.Millisecond},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			start := time.Now()
			code, _ := doGet(r, c.path)
			elapsed := time.Since(start)
			t.Logf("%s: %v", c.name, elapsed)
			assert.Equal(t, http.StatusOK, code)
			assert.Less(t, elapsed, c.maxTime,
				"响应时间 %v 超过目标 %v", elapsed, c.maxTime)
		})
	}
}

// ─────────────────────────────────────────────
// 性能测试：100 并发客户端同时请求 API
// ─────────────────────────────────────────────

// TestPerf_ConcurrentAPIClients verifies the API handles 100 concurrent clients
func TestPerf_ConcurrentAPIClients(t *testing.T) {
	db := openDB(t)
	seedHosts(t, db, targetHosts)
	r := setupPerfRouter(db)

	const requests = 1000 // 总请求数
	endpoints := []string{
		"/api/v1/hosts?page=1&page_size=20",
		"/api/v1/hosts/status-distribution",
		"/api/v1/dashboard/stats",
		"/api/v1/monitor/host?range=1h",
		"/api/v1/monitor/services",
	}

	var (
		wg      sync.WaitGroup
		success atomic.Int64
		failed  atomic.Int64
		latSum  atomic.Int64
	)

	sem := make(chan struct{}, concurrency)
	start := time.Now()

	for i := range requests {
		wg.Add(1)
		sem <- struct{}{}
		go func(idx int) {
			defer wg.Done()
			defer func() { <-sem }()

			ep := endpoints[idx%len(endpoints)]
			reqStart := time.Now()
			code, _ := doGet(r, ep)
			latSum.Add(time.Since(reqStart).Milliseconds())

			if code == http.StatusOK {
				success.Add(1)
			} else {
				failed.Add(1)
				t.Logf("请求失败 [%s] -> HTTP %d", ep, code)
			}
		}(i)
	}

	wg.Wait()
	elapsed := time.Since(start)

	s := success.Load()
	f := failed.Load()
	avgLat := time.Duration(latSum.Load()/requests) * time.Millisecond
	qps := float64(requests) / elapsed.Seconds()

	t.Logf("并发测试结果:")
	t.Logf("  并发数    : %d", concurrency)
	t.Logf("  总请求数  : %d", requests)
	t.Logf("  成功      : %d (%.1f%%)", s, float64(s)/float64(requests)*100)
	t.Logf("  失败      : %d", f)
	t.Logf("  总耗时    : %v", elapsed)
	t.Logf("  平均延迟  : %v", avgLat)
	t.Logf("  QPS       : %.0f req/s", qps)

	// 验收标准
	errRate := float64(f) / float64(requests) * 100
	assert.Less(t, errRate, 1.0, "并发请求错误率应 < 1%%")
	assert.Greater(t, qps, float64(50), "QPS 应 > 50 req/s（当前: %.0f）", qps)
}

// ─────────────────────────────────────────────
// Benchmark：ListHosts
// ─────────────────────────────────────────────

// BenchmarkAPI_ListHosts 基准测试：ListHosts 每次请求耗时
func BenchmarkAPI_ListHosts(b *testing.B) {
	db := openDB(b)
	seedHosts(b, db, targetHosts)
	r := setupPerfRouter(db)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			code, _ := doGet(r, "/api/v1/hosts?page=1&page_size=20")
			if code != http.StatusOK {
				b.Errorf("期望 200，得到 %d", code)
			}
		}
	})
}

// BenchmarkAPI_DashboardStats 基准测试：Dashboard 统计
func BenchmarkAPI_DashboardStats(b *testing.B) {
	db := openDB(b)
	seedHosts(b, db, targetHosts)
	r := setupPerfRouter(db)

	b.ResetTimer()
	for b.Loop() {
		code, _ := doGet(r, "/api/v1/dashboard/stats")
		if code != http.StatusOK {
			b.Errorf("期望 200，得到 %d", code)
		}
	}
}

// ─────────────────────────────────────────────
// 性能场景：1000 AgentCenter gRPC 并发连接
// ─────────────────────────────────────────────

// TestPerf_1000AgentConcurrentConnections 验证 AgentCenter 支持 1000 个并发 gRPC 连接
func TestPerf_1000AgentConcurrentConnections(t *testing.T) {
	db := openDB(t)
	log := zap.NewNop()
	cfg := &config.Config{MTLS: config.MTLSConfig{}, Metrics: config.MetricsConfig{MySQL: config.MySQLMetricsConfig{BatchSize: 100, FlushInterval: 5 * time.Second, RetentionDays: 7}}}
	svc := transfer.NewService(db, log, cfg)

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	srv := grpc.NewServer(
		grpc.MaxConcurrentStreams(2000),
	)
	grpcProto.RegisterTransferServer(srv, svc)
	go func() { _ = srv.Serve(lis) }()
	defer srv.GracefulStop()

	addr := lis.Addr().String()

	const agents = 1000
	const msgsPerAgent = 1

	var (
		wg         sync.WaitGroup
		totalSent  atomic.Int64
		connErrors atomic.Int64
		sendErrors atomic.Int64
	)

	start := time.Now()

	// 分批启动：每批 100，避免瞬间 SYN flood
	for batch := 0; batch < agents/100; batch++ {
		for i := range 100 {
			idx := batch*100 + i
			wg.Add(1)
			go func(agentIdx int) {
				defer wg.Done()

				conn, err := grpc.NewClient(addr,
					grpc.WithTransportCredentials(insecure.NewCredentials()),
				)
				if err != nil {
					connErrors.Add(1)
					return
				}
				defer conn.Close()

				client := grpcProto.NewTransferClient(conn)
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()

				stream, err := client.Transfer(ctx)
				if err != nil {
					connErrors.Add(1)
					return
				}
				defer stream.CloseSend()

				payload := &bridgepb.Payload{
					Fields: map[string]string{
						"cpu_usage": fmt.Sprintf("%.1f", float64(agentIdx%100)),
						"mem_usage": "60.0",
					},
				}
				data, _ := proto.Marshal(payload)
				pkg := &grpcProto.PackagedData{
					AgentId:  fmt.Sprintf("perf-agent-%06d", agentIdx),
					Hostname: fmt.Sprintf("perf-host-%06d", agentIdx),
					Version:  "perf/1.0.0",
					Records: []*grpcProto.EncodedRecord{
						{DataType: 1000, Timestamp: time.Now().UnixNano(), Data: data},
					},
				}
				for range msgsPerAgent {
					if err := stream.Send(pkg); err != nil {
						sendErrors.Add(1)
						return
					}
					totalSent.Add(1)
				}
			}(idx)
		}
		// 每批间隔 10ms，避免连接风暴
		time.Sleep(10 * time.Millisecond)
	}

	wg.Wait()
	elapsed := time.Since(start)

	sent := totalSent.Load()
	cErr := connErrors.Load()
	sErr := sendErrors.Load()
	totalErr := cErr + sErr
	errRate := float64(totalErr) / float64(agents) * 100
	throughput := float64(sent) / elapsed.Seconds()

	t.Logf("=== 1000 Agent 并发性能报告 ===")
	t.Logf("  Agent 数量     : %d", agents)
	t.Logf("  总发送消息     : %d", sent)
	t.Logf("  连接错误       : %d", cErr)
	t.Logf("  发送错误       : %d", sErr)
	t.Logf("  错误率         : %.2f%%", errRate)
	t.Logf("  总耗时         : %v", elapsed)
	t.Logf("  消息吞吐量     : %.0f msg/s", throughput)

	// 验收标准：1000 Agent 并发，错误率 < 1%
	assert.Less(t, errRate, 1.0,
		"1000 Agent 并发错误率应 < 1%%，实际 %.2f%%", errRate)
	// 消息吞吐量应能满足 1000 hosts × 1 msg/60s = 17 msg/s，目标 >100 msg/s
	assert.Greater(t, throughput, float64(100),
		"消息吞吐量应 > 100 msg/s，实际 %.0f msg/s", throughput)
}

// ─────────────────────────────────────────────
// Benchmark：gRPC Transfer 吞吐量
// ─────────────────────────────────────────────

// BenchmarkGRPC_Transfer_Throughput gRPC 消息吞吐量基准测试
func BenchmarkGRPC_Transfer_Throughput(b *testing.B) {
	db := openDB(b)
	log := zap.NewNop()
	cfg := &config.Config{MTLS: config.MTLSConfig{}, Metrics: config.MetricsConfig{MySQL: config.MySQLMetricsConfig{BatchSize: 100, FlushInterval: 5 * time.Second, RetentionDays: 7}}}
	svc := transfer.NewService(db, log, cfg)

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(b, err)
	srv := grpc.NewServer()
	grpcProto.RegisterTransferServer(srv, svc)
	go func() { _ = srv.Serve(lis) }()
	defer srv.GracefulStop()

	conn, err := grpc.NewClient(lis.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(b, err)
	defer conn.Close()

	client := grpcProto.NewTransferClient(conn)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stream, err := client.Transfer(ctx)
	require.NoError(b, err)

	payload := &bridgepb.Payload{
		Fields: map[string]string{"cpu_usage": "50.0", "mem_usage": "60.0"},
	}
	data, _ := proto.Marshal(payload)
	pkg := &grpcProto.PackagedData{
		AgentId:  "bench-agent",
		Hostname: "bench-host",
		Version:  "bench/1.0.0",
		Records: []*grpcProto.EncodedRecord{
			{DataType: 1000, Timestamp: time.Now().UnixNano(), Data: data},
		},
	}

	b.ResetTimer()
	for b.Loop() {
		if err := stream.Send(pkg); err != nil {
			b.Fatal(err)
		}
	}
}
