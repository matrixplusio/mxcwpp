// stress 是 MxCwpp AgentCenter 压测工具
// 模拟 N 个 Agent 并发通过 gRPC BiDi 流发送心跳，验证 AC → Kafka → Consumer 链路
//
// 用法：
//
//	go run ./cmd/tools/stress \
//	  --target localhost:6751 \
//	  --agents 1000 \
//	  --duration 60s \
//	  --interval 5s \
//	  --report-interval 10s
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/proto"

	bridgeProto "github.com/matrixplusio/mxcwpp/api/proto/bridge"
	grpcProto "github.com/matrixplusio/mxcwpp/api/proto/grpc"
)

var (
	target         = flag.String("target", "localhost:6751", "AgentCenter gRPC 地址")
	agentCount     = flag.Int("agents", 100, "模拟 Agent 数量")
	duration       = flag.Duration("duration", 60*time.Second, "压测时长")
	msgInterval    = flag.Duration("interval", 5*time.Second, "每个 Agent 发送消息间隔")
	reportInterval = flag.Duration("report-interval", 10*time.Second, "统计报告输出间隔")
	useTLS         = flag.Bool("tls", false, "是否使用 TLS 连接")
	insecureTLS    = flag.Bool("insecure-tls", false, "跳过 TLS 证书验证（测试环境）")
)

// 全局计数器（原子操作）
var (
	totalSent    int64
	totalErrors  int64
	activeAgents int64
)

func main() {
	flag.Parse()

	log.Printf("MxCwpp AgentCenter 压测工具启动")
	log.Printf("目标: %s | Agent 数: %d | 时长: %v | 消息间隔: %v",
		*target, *agentCount, *duration, *msgInterval)

	ctx, cancel := context.WithTimeout(context.Background(), *duration)
	defer cancel()

	// 系统信号处理（支持 Ctrl+C 提前终止）
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("收到终止信号，正在停止...")
		cancel()
	}()

	// 启动统计报告 goroutine
	go reportLoop(ctx)

	// 并发启动所有 Agent goroutine
	var wg sync.WaitGroup
	for i := 0; i < *agentCount; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			runAgent(ctx, idx)
		}(i)
		// 渐进式启动，避免瞬间连接风暴（每 10ms 启动 10 个）
		if i%10 == 9 {
			time.Sleep(10 * time.Millisecond)
		}
	}

	wg.Wait()
	printFinalReport()
}

// runAgent 模拟单个 Agent 的 gRPC BiDi 流行为
func runAgent(ctx context.Context, idx int) {
	agentID := fmt.Sprintf("stress-agent-%06d", idx)
	hostname := fmt.Sprintf("stress-host-%06d", idx)

	conn, err := dialGRPC()
	if err != nil {
		atomic.AddInt64(&totalErrors, 1)
		return
	}
	defer conn.Close()

	client := grpcProto.NewTransferClient(conn)
	stream, err := client.Transfer(ctx)
	if err != nil {
		atomic.AddInt64(&totalErrors, 1)
		return
	}

	atomic.AddInt64(&activeAgents, 1)
	defer atomic.AddInt64(&activeAgents, -1)

	// 后台接收 Command（丢弃，仅验证连接正常）
	go func() {
		for {
			_, err := stream.Recv()
			if err != nil {
				return
			}
		}
	}()

	ticker := time.NewTicker(*msgInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			_ = stream.CloseSend()
			return
		case <-ticker.C:
			pkg := buildHeartbeatPackage(agentID, hostname)
			if err := stream.Send(pkg); err != nil {
				atomic.AddInt64(&totalErrors, 1)
				return
			}
			atomic.AddInt64(&totalSent, 1)
		}
	}
}

// buildHeartbeatPackage 构造心跳 PackagedData（DataType 1000）
func buildHeartbeatPackage(agentID, hostname string) *grpcProto.PackagedData {
	payload := &bridgeProto.Payload{
		Fields: map[string]string{
			"cpu_usage":  fmt.Sprintf("%.1f", rand.Float64()*100),
			"mem_usage":  fmt.Sprintf("%.1f", rand.Float64()*100),
			"disk_usage": fmt.Sprintf("%.1f", rand.Float64()*100),
			"load_1":     fmt.Sprintf("%.2f", rand.Float64()*4),
			"load_5":     fmt.Sprintf("%.2f", rand.Float64()*4),
			"load_15":    fmt.Sprintf("%.2f", rand.Float64()*4),
			"net_in":     fmt.Sprintf("%d", rand.Int63n(1024*1024)),
			"net_out":    fmt.Sprintf("%d", rand.Int63n(512*1024)),
		},
	}
	data, _ := proto.Marshal(payload)

	return &grpcProto.PackagedData{
		AgentId:      agentID,
		Hostname:     hostname,
		Version:      "stress/1.0.0",
		IntranetIpv4: []string{"10.0.0.1"},
		Records: []*grpcProto.EncodedRecord{
			{
				DataType:  1000,
				Timestamp: time.Now().UnixNano(),
				Data:      data,
			},
		},
	}
}

// dialGRPC 创建 gRPC 连接
func dialGRPC() (*grpc.ClientConn, error) {
	var opts []grpc.DialOption

	if *useTLS {
		tlsCfg := &tls.Config{}
		if *insecureTLS {
			tlsCfg.InsecureSkipVerify = true
		}
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	} else {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	// 连接超时 5s（NewClient 懒连接，通过 context 控制首次 RPC 超时）
	opts = append(opts, grpc.WithConnectParams(grpc.ConnectParams{
		MinConnectTimeout: 5 * time.Second,
	}))

	return grpc.NewClient(*target, opts...)
}

// reportLoop 定期输出实时统计
func reportLoop(ctx context.Context) {
	ticker := time.NewTicker(*reportInterval)
	defer ticker.Stop()

	var lastSent, lastErrors int64
	lastTime := time.Now()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := time.Now()
			elapsed := now.Sub(lastTime).Seconds()

			sent := atomic.LoadInt64(&totalSent)
			errors := atomic.LoadInt64(&totalErrors)
			active := atomic.LoadInt64(&activeAgents)

			qps := float64(sent-lastSent) / elapsed
			errRate := float64(0)
			if sent > 0 {
				errRate = float64(errors) / float64(sent) * 100
			}

			log.Printf("[STATS] 在线Agent: %d | QPS: %.1f msg/s | 累计发送: %d | 错误: %d (%.2f%%)",
				active, qps, sent, errors, errRate)

			lastSent, lastErrors, lastTime = sent, errors, now
			_ = lastErrors
		}
	}
}

// printFinalReport 输出最终压测报告
func printFinalReport() {
	sent := atomic.LoadInt64(&totalSent)
	errors := atomic.LoadInt64(&totalErrors)
	errRate := float64(0)
	if sent > 0 {
		errRate = float64(errors) / float64(sent) * 100
	}

	fmt.Println("\n========== 压测报告 ==========")
	fmt.Printf("Agent 数量  : %d\n", *agentCount)
	fmt.Printf("压测时长    : %v\n", *duration)
	fmt.Printf("消息间隔    : %v\n", *msgInterval)
	fmt.Printf("总发送消息  : %d\n", sent)
	fmt.Printf("总错误数    : %d\n", errors)
	fmt.Printf("错误率      : %.2f%%\n", errRate)
	if sent > 0 {
		avgQPS := float64(sent) / duration.Seconds()
		fmt.Printf("平均 QPS    : %.1f msg/s\n", avgQPS)
	}
	fmt.Println("==============================")

	if errRate > 5.0 {
		fmt.Println("[警告] 错误率超过 5%，请检查 AgentCenter 日志和 DLQ Topic")
		os.Exit(1)
	}
}
