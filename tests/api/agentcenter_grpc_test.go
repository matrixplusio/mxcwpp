//go:build integration
// +build integration

// Package api_test 提供 AgentCenter gRPC 接口测试
//
// 运行方式：
//
//	go test -v -tags integration ./tests/api/... -run TestGRPC
package api_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/proto"

	bridgepb "github.com/imkerbos/mxsec-platform/api/proto/bridge"
	grpcProto "github.com/imkerbos/mxsec-platform/api/proto/grpc"
	"github.com/imkerbos/mxsec-platform/internal/server/agentcenter/transfer"
	"github.com/imkerbos/mxsec-platform/internal/server/config"
)

// ─────────────────────────────────────────────
// gRPC 测试基础设施
// ─────────────────────────────────────────────

// setupGRPCServer 启动内进程 gRPC 服务，返回地址和清理函数
func setupGRPCServer(t *testing.T) (addr string, cleanup func()) {
	t.Helper()
	logger := zap.NewNop()
	db := setupDB(t)

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	cfg := &config.Config{
		MTLS: config.MTLSConfig{},
		Metrics: config.MetricsConfig{
			MySQL: config.MySQLMetricsConfig{
				BatchSize:     100,
				FlushInterval: 5 * time.Second,
				RetentionDays: 7,
			},
		},
	}
	svc := transfer.NewService(db, logger, cfg)

	srv := grpc.NewServer()
	grpcProto.RegisterTransferServer(srv, svc)

	go func() { _ = srv.Serve(lis) }()

	return lis.Addr().String(), func() {
		srv.GracefulStop()
		lis.Close()
	}
}

// connectAgent 创建到 AgentCenter 的 gRPC 连接
func connectAgent(t *testing.T, addr string) (*grpc.ClientConn, grpcProto.TransferClient) {
	t.Helper()
	conn, err := grpc.NewClient(addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	return conn, grpcProto.NewTransferClient(conn)
}

// buildHeartbeat 构造 DataType=1000 心跳包
func buildHeartbeat(agentID, hostname string) *grpcProto.PackagedData {
	ts := time.Now().UnixNano()
	record := &bridgepb.Record{
		DataType:  1000,
		Timestamp: ts,
		Data: &bridgepb.Payload{
			Fields: map[string]string{
				"cpu_usage":  "45.2",
				"mem_usage":  "62.8",
				"disk_usage": "55.1",
				"load_1":     "1.3",
				"load_5":     "1.1",
				"load_15":    "0.9",
				"net_in":     "204800",
				"net_out":    "102400",
			},
		},
	}
	data, _ := proto.Marshal(record)
	return &grpcProto.PackagedData{
		AgentId:      agentID,
		Hostname:     hostname,
		Version:      "test/1.0.0",
		IntranetIpv4: []string{"192.168.1.100"},
		Records: []*grpcProto.EncodedRecord{
			{
				DataType:  1000,
				Timestamp: ts,
				Data:      data,
			},
		},
	}
}

// ─────────────────────────────────────────────
// 功能测试 1：单 Agent 连接 + 心跳上报
// ─────────────────────────────────────────────

// TestGRPC_SingleAgent_Heartbeat 验证单 Agent 建立 BiDi 流并发送心跳
func TestGRPC_SingleAgent_Heartbeat(t *testing.T) {
	addr, cleanup := setupGRPCServer(t)
	defer cleanup()

	conn, client := connectAgent(t, addr)
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	stream, err := client.Transfer(ctx)
	require.NoError(t, err, "建立 Transfer 流失败")

	agentID := "test-agent-single"

	// 发送 5 条心跳，每隔 200ms
	for i := 0; i < 5; i++ {
		pkg := buildHeartbeat(agentID, "test-host-single")
		require.NoError(t, stream.Send(pkg), "发送心跳第 %d 条失败", i+1)
		time.Sleep(200 * time.Millisecond)
	}

	// 关闭发送侧
	require.NoError(t, stream.CloseSend())
	t.Log("单 Agent 5 条心跳发送成功")
}

// ─────────────────────────────────────────────
// 功能测试 2：命令接收验证
// ─────────────────────────────────────────────

// TestGRPC_CommandReceive 验证 Agent 能接收 Server 下发的 Command（非阻塞测试）
func TestGRPC_CommandReceive(t *testing.T) {
	addr, cleanup := setupGRPCServer(t)
	defer cleanup()

	conn, client := connectAgent(t, addr)
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.Transfer(ctx)
	require.NoError(t, err)

	// 发送一条心跳
	require.NoError(t, stream.Send(buildHeartbeat("cmd-agent", "cmd-host")))

	// 后台监听 Command，验证不会崩溃
	cmdReceived := make(chan bool, 1)
	go func() {
		for {
			_, err := stream.Recv()
			if err == io.EOF || err != nil {
				cmdReceived <- false
				return
			}
			cmdReceived <- true
		}
	}()

	// 等待 1s，期间 Server 可能下发 Command（或不下发，两种情况都正常）
	select {
	case <-cmdReceived:
		t.Log("收到 Server Command")
	case <-time.After(1 * time.Second):
		t.Log("1s 内无 Command 下发（正常，Server 无待处理任务）")
	}
	_ = stream.CloseSend()
}

// ─────────────────────────────────────────────
// 场景测试：多类型 DataType 上报
// ─────────────────────────────────────────────

// TestGRPC_MultipleDataTypes 验证不同 DataType 的 Record 都被正常接受（不崩溃、不报错）
func TestGRPC_MultipleDataTypes(t *testing.T) {
	addr, cleanup := setupGRPCServer(t)
	defer cleanup()

	conn, client := connectAgent(t, addr)
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	stream, err := client.Transfer(ctx)
	require.NoError(t, err)

	agentID := "multi-dt-agent"

	// DataType 对照表（来自系统设计）
	dataTypes := []struct {
		dt   int32
		name string
	}{
		{1000, "心跳"},
		{1001, "插件心跳"},
		{6001, "FIM 事件"},
		{8000, "基线结果"},
		{9999, "未知类型（应被忽略）"},
	}

	for _, dt := range dataTypes {
		ts := time.Now().UnixNano()
		record := &bridgepb.Record{
			DataType:  dt.dt,
			Timestamp: ts,
			Data: &bridgepb.Payload{
				Fields: map[string]string{"test_field": "test_value"},
			},
		}
		data, _ := proto.Marshal(record)
		pkg := &grpcProto.PackagedData{
			AgentId:  agentID,
			Hostname: "multi-dt-host",
			Version:  "test/1.0.0",
			Records: []*grpcProto.EncodedRecord{
				{DataType: dt.dt, Timestamp: ts, Data: data},
			},
		}
		require.NoError(t, stream.Send(pkg), "发送 DataType=%d (%s) 失败", dt.dt, dt.name)
	}

	require.NoError(t, stream.CloseSend())
	t.Logf("成功发送 %d 种 DataType 的 Record", len(dataTypes))
}

// ─────────────────────────────────────────────
// 性能场景：10 并发 Agent 连接
// ─────────────────────────────────────────────

// TestGRPC_ConcurrentAgents_10 验证 10 个 Agent 同时连接的正确性
func TestGRPC_ConcurrentAgents_10(t *testing.T) {
	addr, cleanup := setupGRPCServer(t)
	defer cleanup()

	const agents = 10
	const msgsPerAgent = 5

	var (
		wg        sync.WaitGroup
		totalSent atomic.Int64
		errCount  atomic.Int64
	)

	for i := range agents {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			conn, client := connectAgent(t, addr)
			defer conn.Close()

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			stream, err := client.Transfer(ctx)
			if err != nil {
				t.Logf("Agent %d 建流失败: %v", idx, err)
				errCount.Add(1)
				return
			}
			defer stream.CloseSend()

			agentID := fmt.Sprintf("concurrent-agent-%03d", idx)
			for j := range msgsPerAgent {
				if err := stream.Send(buildHeartbeat(agentID, "concurrent-host")); err != nil {
					t.Logf("Agent %d 第 %d 条失败: %v", idx, j, err)
					errCount.Add(1)
					return
				}
				totalSent.Add(1)
			}
		}(i)
	}

	wg.Wait()

	expected := int64(agents * msgsPerAgent)
	assert.Equal(t, int64(0), errCount.Load(), "所有 Agent 均应无错误")
	assert.Equal(t, expected, totalSent.Load(),
		"10 Agent × %d msg = %d 条全部发出", msgsPerAgent, expected)
	t.Logf("10 并发 Agent，共发送 %d 条消息，错误 %d", totalSent.Load(), errCount.Load())
}

// ─────────────────────────────────────────────
// 性能场景：100 并发 Agent 连接（轻量压测）
// ─────────────────────────────────────────────

// TestGRPC_ConcurrentAgents_100 验证 100 个 Agent 并发连接的稳定性
func TestGRPC_ConcurrentAgents_100(t *testing.T) {
	if testing.Short() {
		t.Skip("跳过 100 Agent 测试（-short）")
	}

	addr, cleanup := setupGRPCServer(t)
	defer cleanup()

	const agents = 100
	const msgsPerAgent = 3

	var (
		wg        sync.WaitGroup
		totalSent atomic.Int64
		errCount  atomic.Int64
	)

	start := time.Now()

	for i := range agents {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			conn, client := connectAgent(t, addr)
			defer conn.Close()

			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()

			stream, err := client.Transfer(ctx)
			if err != nil {
				errCount.Add(1)
				return
			}
			defer stream.CloseSend()

			agentID := fmt.Sprintf("load-agent-%04d", idx)
			for range msgsPerAgent {
				if err := stream.Send(buildHeartbeat(agentID, "load-host")); err != nil {
					errCount.Add(1)
					return
				}
				totalSent.Add(1)
			}
		}(i)
	}

	wg.Wait()
	elapsed := time.Since(start)

	sent := totalSent.Load()
	errs := errCount.Load()
	qps := float64(sent) / elapsed.Seconds()

	t.Logf("100 并发 Agent | 发送 %d 条 | 错误 %d | 耗时 %v | QPS %.0f msg/s",
		sent, errs, elapsed, qps)

	// 错误率不超过 1%
	errRate := float64(errs) / float64(agents*msgsPerAgent) * 100
	assert.Less(t, errRate, 1.0, "错误率应低于 1%%")
}

// ─────────────────────────────────────────────
// 场景：断线重连
// ─────────────────────────────────────────────

// TestGRPC_Reconnect 验证 Agent 断连后能重新建立流
func TestGRPC_Reconnect(t *testing.T) {
	addr, cleanup := setupGRPCServer(t)
	defer cleanup()

	agentID := "reconnect-agent"

	for round := 1; round <= 3; round++ {
		conn, client := connectAgent(t, addr)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		stream, err := client.Transfer(ctx)
		require.NoError(t, err, "第 %d 次连接应成功", round)

		require.NoError(t, stream.Send(buildHeartbeat(agentID, "reconnect-host")),
			"第 %d 次心跳应成功", round)
		require.NoError(t, stream.CloseSend())
		conn.Close()
		cancel()

		t.Logf("第 %d 次连接断开重连成功", round)
	}
}
