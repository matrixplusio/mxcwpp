package transfer

import (
	"context"
	"crypto/x509"
	"fmt"
	"math/big"
	"os"
	"runtime"

	"go.uber.org/zap"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"

	grpcProto "github.com/imkerbos/mxsec-platform/api/proto/grpc"
	"github.com/imkerbos/mxsec-platform/internal/common/certissue"
)

// peerLeafCert 从 gRPC 上下文取已验证的客户端叶子证书。
// 仅返回经 TLS 链校验通过（VerifiedChains 非空）的证书，未验证/无证书返回 (nil,false)。
func peerLeafCert(ctx context.Context) (*x509.Certificate, bool) {
	p, ok := peer.FromContext(ctx)
	if !ok || p.AuthInfo == nil {
		return nil, false
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return nil, false
	}
	chains := tlsInfo.State.VerifiedChains
	if len(chains) == 0 || len(chains[0]) == 0 {
		return nil, false
	}
	return chains[0][0], true
}

// enrollTokenFromCtx 从 gRPC metadata 取 agent 上报的 enroll 引导令牌。
func enrollTokenFromCtx(ctx context.Context) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}
	vals := md.Get(certissue.EnrollTokenMetaKey)
	if len(vals) == 0 {
		return ""
	}
	return vals[0]
}

// enrollTokenValid 校验 enroll 令牌。配置令牌为空表示迁移期不校验（仅受控内网），返回 true。
func (s *Service) enrollTokenValid(token string) bool {
	want := s.cfg.MTLS.EnrollToken
	if want == "" {
		return true
	}
	return token == want
}

// isRevokedSerial 判断证书序列号是否在吊销名单内。
// 吊销名单首次访问时构 map set，避免每连接 O(n) 线性扫描（500 台重连会高频命中此路径）。
func (s *Service) isRevokedSerial(serial *big.Int) bool {
	if serial == nil {
		return false
	}
	s.revokedOnce.Do(func() {
		serials := s.cfg.MTLS.RevokedSerials
		if len(serials) == 0 {
			return
		}
		set := make(map[string]struct{}, len(serials))
		for _, x := range serials {
			if x != "" {
				set[x] = struct{}{}
			}
		}
		s.revokedSet = set
	})
	_, ok := s.revokedSet[serial.String()]
	return ok
}

// acquireSignSlot 取一个在线签发槽位，限制并发签发数。
// RSA-4096 keygen 是 CPU 尖峰：500 台首装同时 enroll 会瞬间打满全部核心。
// 信号量把并发签发压到 ~NumCPU，多余请求排队（而非 OOM/CPU 饿死），平滑突发。
// 返回的 release 必须在签发完成后调用以归还槽位。
func (s *Service) acquireSignSlot(ctx context.Context) (release func(), err error) {
	s.signOnce.Do(func() {
		s.signSem = make(chan struct{}, max(runtime.NumCPU(), 2))
	})
	select {
	case s.signSem <- struct{}{}:
		return func() { <-s.signSem }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// signAndSendAgentCert 校验 enroll 令牌后，用 CA 给当前 agent 签发单机证书（CN=AgentID）并下发。
// 一机一证：失陷主机可单独吊销，私钥泄露不影响他机。
func (s *Service) signAndSendAgentCert(ctx context.Context, conn *Connection, hasClientCert bool) error {
	if !s.enrollTokenValid(enrollTokenFromCtx(conn.ctx)) {
		// 迁移期：legacy agent 已持有(共享)证书但未配 enroll 令牌 → 保持现状，安静跳过（Debug）。
		// 全新 agent 无任何证书却无有效令牌 → 安装配置问题，Warn 提示但不刷 ERROR/不阻断。
		if hasClientCert {
			s.logger.Debug("跳过单机证书签发：未配 enroll 令牌，沿用现有证书（迁移期正常）",
				zap.String("agent_id", conn.AgentID))
		} else {
			s.logger.Warn("无法签发单机证书：agent 无客户端证书且 enroll 令牌无效，请检查安装配置（ca_fingerprint/enroll_token）",
				zap.String("agent_id", conn.AgentID))
		}
		return nil
	}

	caCertPEM, err := os.ReadFile(s.cfg.MTLS.CACert)
	if err != nil {
		return fmt.Errorf("读取 CA 证书失败: %w", err)
	}
	caKeyPEM, err := os.ReadFile(s.cfg.MTLS.CAKey)
	if err != nil {
		return fmt.Errorf("读取 CA 私钥失败（per_agent_cert 需配置 mtls.ca_key）: %w", err)
	}

	// 限并发签发：RSA-4096 keygen 占满一核，突发首装时排队而非饿死 CPU。
	release, err := s.acquireSignSlot(ctx)
	if err != nil {
		return fmt.Errorf("等待签发槽位被取消: %w", err)
	}
	certPEM, keyPEM, err := certissue.SignAgentCert(caCertPEM, caKeyPEM, conn.AgentID, certissue.DefaultAgentCertValidity)
	release()
	if err != nil {
		return fmt.Errorf("签发单机证书失败: %w", err)
	}

	cmd := &grpcProto.Command{
		CertificateBundle: &grpcProto.CertificateBundle{
			CaCert:     caCertPEM,
			ClientCert: certPEM,
			ClientKey:  keyPEM,
		},
	}
	s.logger.Info("下发单机证书到 Agent",
		zap.String("agent_id", conn.AgentID),
		zap.Int("cert_size", len(certPEM)),
	)
	select {
	case conn.sendCh <- cmd:
		return nil
	case <-conn.ctx.Done():
		return fmt.Errorf("连接已关闭: %s", conn.AgentID)
	case <-ctx.Done():
		return ctx.Err()
	default:
		return fmt.Errorf("发送队列已满: %s", conn.AgentID)
	}
}
