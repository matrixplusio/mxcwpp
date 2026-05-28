package metrics

import (
	"context"
	"os"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/status"
)

// BuildInfoGauge AC 进程 build 元信息（value=1，labels 含 version/pid/commit）
// monitor.go 用 PromQL `mxsec_build_info{job="mxsec-agentcenter"}` 拉取 version + pid
var BuildInfoGauge = promauto.NewGaugeVec(prometheus.GaugeOpts{
	Name: "mxsec_build_info",
	Help: "AC 进程 build 元信息（value=1，labels 含 version/pid/commit）",
}, []string{"version", "pid", "commit"})

// SetBuildInfo 设置 AC build 元信息（main 启动时调一次）
func SetBuildInfo(version, commit string) {
	if version == "" {
		version = "dev"
	}
	if commit == "" {
		commit = "unknown"
	}
	BuildInfoGauge.WithLabelValues(version, strconv.Itoa(os.Getpid()), commit).Set(1)
}

// gRPC server-side metrics（business RED 指标）
//
// Rate     → rate(mxsec_ac_grpc_handled_total[1m])
// Errors   → rate(mxsec_ac_grpc_handled_total{code!="OK"}[1m])
// Duration → histogram_quantile(0.99, rate(mxsec_ac_grpc_duration_seconds_bucket[5m]))
var (
	grpcHandledTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "mxsec_ac_grpc_handled_total",
		Help: "Total number of RPCs completed on the AgentCenter gRPC server, regardless of success or failure.",
	}, []string{"grpc_type", "grpc_method", "grpc_code"})

	grpcDurationSeconds = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "mxsec_ac_grpc_duration_seconds",
		Help:    "Histogram of response latency (seconds) of gRPC handlers on AgentCenter, by method.",
		Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
	}, []string{"grpc_type", "grpc_method"})

	grpcStreamMessagesReceived = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "mxsec_ac_grpc_msg_received_total",
		Help: "Total number of stream messages received on AgentCenter (Agent → Server).",
	}, []string{"grpc_method"})

	grpcStreamMessagesSent = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "mxsec_ac_grpc_msg_sent_total",
		Help: "Total number of stream messages sent from AgentCenter (Server → Agent).",
	}, []string{"grpc_method"})
)

// UnaryServerInterceptor 记录 Unary RPC 的总数与延迟。
func UnaryServerInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		start := time.Now()
		resp, err := handler(ctx, req)
		code := status.Code(err).String()
		grpcHandledTotal.WithLabelValues("unary", info.FullMethod, code).Inc()
		grpcDurationSeconds.WithLabelValues("unary", info.FullMethod).Observe(time.Since(start).Seconds())
		return resp, err
	}
}

// StreamServerInterceptor 记录 Stream RPC 的总数、延迟与单向消息计数。
func StreamServerInterceptor() grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		start := time.Now()
		wrapped := &monitoredServerStream{ServerStream: ss, method: info.FullMethod}
		err := handler(srv, wrapped)
		code := status.Code(err).String()
		grpcHandledTotal.WithLabelValues("stream", info.FullMethod, code).Inc()
		grpcDurationSeconds.WithLabelValues("stream", info.FullMethod).Observe(time.Since(start).Seconds())
		return err
	}
}

// monitoredServerStream 包装 grpc.ServerStream，计数 RecvMsg/SendMsg。
type monitoredServerStream struct {
	grpc.ServerStream
	method string
}

func (m *monitoredServerStream) RecvMsg(msg any) error {
	err := m.ServerStream.RecvMsg(msg)
	if err == nil {
		grpcStreamMessagesReceived.WithLabelValues(m.method).Inc()
	}
	return err
}

func (m *monitoredServerStream) SendMsg(msg any) error {
	err := m.ServerStream.SendMsg(msg)
	if err == nil {
		grpcStreamMessagesSent.WithLabelValues(m.method).Inc()
	}
	return err
}
