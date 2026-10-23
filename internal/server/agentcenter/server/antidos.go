package server

import (
	"context"
	"sync"

	"go.uber.org/zap"
	"golang.org/x/time/rate"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// 批4 AC 抗 DoS：panic recovery + 单 IP 令牌桶限流拦截器。
//
// recovery 始终启用——单个 RPC 处理 panic 不应拖垮整个 AC 进程（500 台 agent 共用）。
// 限流默认关，由 grpc.anti_dos.per_ip_rps 灰度开启。

// recoveryUnaryInterceptor 捕获 unary handler 的 panic，转为 Internal 错误，避免进程崩溃。
func recoveryUnaryInterceptor(logger *zap.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp any, err error) {
		defer func() {
			if r := recover(); r != nil {
				logger.Error("gRPC unary panic recovered",
					zap.String("method", info.FullMethod),
					zap.Any("panic", r),
					zap.Stack("stack"))
				err = status.Errorf(codes.Internal, "internal server error")
			}
		}()
		return handler(ctx, req)
	}
}

// recoveryStreamInterceptor 捕获 stream handler 的 panic（含 Transfer 双向流）。
func recoveryStreamInterceptor(logger *zap.Logger) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) (err error) {
		defer func() {
			if r := recover(); r != nil {
				logger.Error("gRPC stream panic recovered",
					zap.String("method", info.FullMethod),
					zap.Any("panic", r),
					zap.Stack("stack"))
				err = status.Errorf(codes.Internal, "internal server error")
			}
		}()
		return handler(srv, ss)
	}
}

// ipRateLimiter 按客户端 IP 维护令牌桶，限制单 IP 新 RPC 速率。
// agent 集群 IP 数量有界，map 不会无限膨胀；故不做主动清理。
type ipRateLimiter struct {
	mu       sync.Mutex
	limiters map[string]*rate.Limiter
	rps      rate.Limit
	burst    int
}

func newIPRateLimiter(rps, burst int) *ipRateLimiter {
	if burst <= 0 {
		burst = rps
	}
	return &ipRateLimiter{
		limiters: make(map[string]*rate.Limiter),
		rps:      rate.Limit(rps),
		burst:    burst,
	}
}

func (l *ipRateLimiter) allow(ip string) bool {
	l.mu.Lock()
	lim, ok := l.limiters[ip]
	if !ok {
		lim = rate.NewLimiter(l.rps, l.burst)
		l.limiters[ip] = lim
	}
	l.mu.Unlock()
	return lim.Allow()
}

// clientIP 从 gRPC peer 取客户端 IP（无 peer 时返回 "unknown"，共用一个桶）。
func clientIP(ctx context.Context) string {
	if p, ok := peer.FromContext(ctx); ok && p.Addr != nil {
		return p.Addr.String()
	}
	return "unknown"
}

func (l *ipRateLimiter) unaryInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if !l.allow(clientIP(ctx)) {
			return nil, status.Errorf(codes.ResourceExhausted, "rate limit exceeded")
		}
		return handler(ctx, req)
	}
}

func (l *ipRateLimiter) streamInterceptor() grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if !l.allow(clientIP(ss.Context())) {
			return status.Errorf(codes.ResourceExhausted, "rate limit exceeded")
		}
		return handler(srv, ss)
	}
}
