package transfer

import (
	"context"
	"math/big"
	"testing"

	"google.golang.org/grpc/metadata"

	"github.com/matrixplusio/mxcwpp/internal/common/certissue"
	"github.com/matrixplusio/mxcwpp/internal/server/config"
)

func newSvc(mtls config.MTLSConfig) *Service {
	cfg := &config.Config{}
	cfg.MTLS = mtls
	return &Service{cfg: cfg}
}

func TestEnrollTokenValid(t *testing.T) {
	// 空配置令牌：迁移期不校验，任何令牌（含空）通过
	if !newSvc(config.MTLSConfig{}).enrollTokenValid("") {
		t.Fatal("空配置令牌应放行")
	}
	if !newSvc(config.MTLSConfig{}).enrollTokenValid("whatever") {
		t.Fatal("空配置令牌应放行任意令牌")
	}
	// 配置了令牌：必须精确匹配
	s := newSvc(config.MTLSConfig{EnrollToken: "secret-123"})
	if !s.enrollTokenValid("secret-123") {
		t.Fatal("匹配令牌应通过")
	}
	if s.enrollTokenValid("wrong") {
		t.Fatal("错误令牌应拒绝")
	}
	if s.enrollTokenValid("") {
		t.Fatal("空令牌应拒绝")
	}
}

func TestIsRevokedSerial(t *testing.T) {
	s := newSvc(config.MTLSConfig{RevokedSerials: []string{"1001", "2002"}})
	if !s.isRevokedSerial(big.NewInt(1001)) {
		t.Fatal("1001 应被吊销命中")
	}
	if s.isRevokedSerial(big.NewInt(3003)) {
		t.Fatal("3003 不应命中")
	}
	if s.isRevokedSerial(nil) {
		t.Fatal("nil 序列号不应命中")
	}
	if newSvc(config.MTLSConfig{}).isRevokedSerial(big.NewInt(1001)) {
		t.Fatal("空吊销名单不应命中")
	}
}

func TestEnrollTokenFromCtx(t *testing.T) {
	// 无 metadata
	if got := enrollTokenFromCtx(context.Background()); got != "" {
		t.Fatalf("无 metadata 应返回空，得 %q", got)
	}
	// 带 metadata
	md := metadata.Pairs(certissue.EnrollTokenMetaKey, "tok-xyz")
	ctx := metadata.NewIncomingContext(context.Background(), md)
	if got := enrollTokenFromCtx(ctx); got != "tok-xyz" {
		t.Fatalf("应取出 tok-xyz，得 %q", got)
	}
}

func TestPeerLeafCertNoTLS(t *testing.T) {
	// 无 peer / 无 TLS info 时返回 false（不 panic）
	if _, ok := peerLeafCert(context.Background()); ok {
		t.Fatal("无 TLS 上下文应返回 false")
	}
}
