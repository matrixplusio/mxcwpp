package server

import (
	"context"
	"testing"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	grpcProto "github.com/matrixplusio/mxcwpp/api/proto/grpc"
)

// TestRequireClientCertUnary 无客户端证书时：Transfer（enroll 入口）放行，其余 RPC 拒绝。
func TestRequireClientCertUnary(t *testing.T) {
	interceptor := requireClientCertUnary(zap.NewNop())
	called := false
	handler := func(ctx context.Context, req any) (any, error) {
		called = true
		return "ok", nil
	}

	// 无 TLS peer 的上下文 → hasVerifiedClientCert=false。
	ctx := context.Background()

	// 非 enroll 方法：拒绝。
	called = false
	_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: grpcProto.FileExt_Upload_FullMethodName}, handler)
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("非 enroll RPC 无证书应 Unauthenticated，得 %v", err)
	}
	if called {
		t.Fatal("非 enroll RPC 无证书不应进入 handler")
	}

	// Transfer 方法：放行（enroll 阶段允许无证书）。
	called = false
	if _, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: grpcProto.Transfer_Transfer_FullMethodName}, handler); err != nil {
		t.Fatalf("Transfer 无证书应放行，得 %v", err)
	}
	if !called {
		t.Fatal("Transfer 应进入 handler")
	}
}

func TestHasVerifiedClientCert_NoTLS(t *testing.T) {
	if hasVerifiedClientCert(context.Background()) {
		t.Fatal("无 TLS 上下文应返回 false")
	}
}
