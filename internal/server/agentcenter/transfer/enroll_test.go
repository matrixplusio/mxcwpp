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
	// fail-closed：服务端未配置令牌（空 want）→ 任何令牌（含空）一律无效。
	if newSvc(config.MTLSConfig{}).enrollTokenValid("") {
		t.Fatal("空配置令牌应拒绝空令牌")
	}
	if newSvc(config.MTLSConfig{}).enrollTokenValid("whatever") {
		t.Fatal("空配置令牌应拒绝任意令牌")
	}
	// 配置了令牌：constant-time 精确匹配。
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
	// 前缀/子串不得通过（固定长度 hash 比较，杜绝长度旁路）。
	if s.enrollTokenValid("secret-1") {
		t.Fatal("前缀令牌应拒绝")
	}
	if s.enrollTokenValid("secret-1234") {
		t.Fatal("超长令牌应拒绝")
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

// TestEnrollTokenRoundTrip agent 侧写入的 metadata 必须被 AC 侧的真实读取逻辑原样读回。
//
// 这是一条跨端契约：写在 agent（certissue.WithEnrollToken），读在 AC
// （enrollTokenFromCtx）。两侧各自的单测都无法发现 key 或写法漂移——表现会是
// "agent 明明配了令牌却一律 enroll 被拒"，而服务端日志只说令牌无效。
func TestEnrollTokenRoundTrip(t *testing.T) {
	const token = "0123456789abcdef0123456789abcdef"

	// agent 侧构造出站 ctx，再按 gRPC 的传输语义转成服务端看到的入站 ctx。
	outCtx := certissue.WithEnrollToken(context.Background(), token)
	md, ok := metadata.FromOutgoingContext(outCtx)
	if !ok {
		t.Fatal("agent 侧未写入任何 metadata")
	}
	if got := enrollTokenFromCtx(metadata.NewIncomingContext(context.Background(), md)); got != token {
		t.Fatalf("AC 侧读到 %q，want %q", got, token)
	}

	// 令牌为空时不应写入 metadata：服务端会 fail-closed 拒绝，客户端不假装成功。
	empty := certissue.WithEnrollToken(context.Background(), "")
	if md, ok := metadata.FromOutgoingContext(empty); ok && len(md.Get(certissue.EnrollTokenMetaKey)) > 0 {
		t.Error("空令牌不应写入 metadata")
	}
}
