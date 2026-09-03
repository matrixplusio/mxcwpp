package transfer

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"fmt"
	"math/big"
	"os"
	"runtime"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	grpcProto "github.com/matrixplusio/mxcwpp/api/proto/grpc"
	"github.com/matrixplusio/mxcwpp/internal/common/certissue"
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

// enrollTokenValid 校验 enroll 令牌（fail-closed）。
//
// 服务端未配置令牌（want==""）或 agent 未上报令牌（token==""）一律无效——绝不放行空令牌。
// 比较先各自取固定长度 SHA-256 摘要再做 constant-time compare，避免长度/内容旁路与时序侧信道。
// 生产模式下 want 的强度由 ValidateEnrollToken 在启动期强制（≥32、非占位符/弱值）。
func (s *Service) enrollTokenValid(token string) bool {
	want := s.cfg.MTLS.EnrollToken
	if want == "" || token == "" {
		return false
	}
	wantSum := sha256.Sum256([]byte(want))
	gotSum := sha256.Sum256([]byte(token))
	return subtle.ConstantTimeCompare(wantSum[:], gotSum[:]) == 1
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

// signAgentCertCommand 用 CA 给指定 AgentID 现签一张单机证书（CN=AgentID），封装为下发命令。
// 不做令牌校验（调用方负责），也不涉及连接注册；仅负责“读 CA → 限并发签发 → 组装 Command”。
func (s *Service) signAgentCertCommand(ctx context.Context, agentID string) (*grpcProto.Command, error) {
	caCertPEM, err := os.ReadFile(s.cfg.MTLS.CACert)
	if err != nil {
		return nil, fmt.Errorf("读取 CA 证书失败: %w", err)
	}
	caKeyPEM, err := os.ReadFile(s.cfg.MTLS.CAKey)
	if err != nil {
		return nil, fmt.Errorf("读取 CA 私钥失败（per_agent_cert 需配置 mtls.ca_key）: %w", err)
	}

	// 限并发签发：RSA-4096 keygen 占满一核，突发首装时排队而非饿死 CPU。
	release, err := s.acquireSignSlot(ctx)
	if err != nil {
		return nil, fmt.Errorf("等待签发槽位被取消: %w", err)
	}
	certPEM, keyPEM, err := certissue.SignAgentCert(caCertPEM, caKeyPEM, agentID, certissue.DefaultAgentCertValidity)
	release()
	if err != nil {
		return nil, fmt.Errorf("签发单机证书失败: %w", err)
	}

	return &grpcProto.Command{
		CertificateBundle: &grpcProto.CertificateBundle{
			CaCert:     caCertPEM,
			ClientCert: certPEM,
			ClientKey:  keyPEM,
		},
	}, nil
}

// enrollOnly 处理“无客户端证书”的首连：仅允许 enroll。
//
// 严格 fail-closed：要求 per_agent_cert 已开启且 enroll 令牌有效，才现签一机一证并**同步**下发；
// 随后结束该流（返回 nil），要求 agent 携证书重连走完整 mTLS。全程不注册在线连接、不处理心跳/records、
// 不下发插件任务、不触达其它 RPC。签发或发送失败一律终止 enroll，绝不半健康继续。
func (s *Service) enrollOnly(ctx context.Context, stream grpc.BidiStreamingServer[grpcProto.PackagedData, grpcProto.Command], agentID string) error {
	if !s.cfg.MTLS.PerAgentCert {
		return status.Error(codes.Unauthenticated, "无客户端证书且未开启 per_agent_cert，拒绝")
	}
	if !s.enrollTokenValid(enrollTokenFromCtx(stream.Context())) {
		s.logger.Warn("enroll 拒绝：缺少有效客户端证书且 enroll 令牌无效",
			zap.String("agent_id", agentID))
		return status.Error(codes.Unauthenticated, "enroll 令牌无效")
	}

	cmd, err := s.signAgentCertCommand(ctx, agentID)
	if err != nil {
		s.logger.Error("enroll 签发单机证书失败，终止（不进入业务面）",
			zap.String("agent_id", agentID), zap.Error(err))
		return status.Errorf(codes.Internal, "签发单机证书失败: %v", err)
	}
	if err := stream.Send(cmd); err != nil {
		s.logger.Error("enroll 下发单机证书失败，终止",
			zap.String("agent_id", agentID), zap.Error(err))
		return status.Errorf(codes.Unavailable, "下发单机证书失败: %v", err)
	}
	s.logger.Info("enroll 成功：已下发单机证书，等待 agent 携证书重连（首连不进入业务面）",
		zap.String("agent_id", agentID))
	return nil
}

// signAndSendAgentCert 为**已注册**连接（insecure_dev_mode 回退路径 / per-agent 重新下发）
// 校验令牌后签发单机证书并经 conn.sendCh 下发。生产首连走 enrollOnly，不经此路径。
func (s *Service) signAndSendAgentCert(ctx context.Context, conn *Connection, hasClientCert bool) error {
	if !s.enrollTokenValid(enrollTokenFromCtx(conn.ctx)) {
		if hasClientCert {
			s.logger.Debug("跳过单机证书签发：未配 enroll 令牌，沿用现有证书（迁移期正常）",
				zap.String("agent_id", conn.AgentID))
		} else {
			s.logger.Warn("无法签发单机证书：agent 无客户端证书且 enroll 令牌无效，请检查安装配置（ca_fingerprint/enroll_token）",
				zap.String("agent_id", conn.AgentID))
		}
		return nil
	}

	cmd, err := s.signAgentCertCommand(ctx, conn.AgentID)
	if err != nil {
		return err
	}
	s.logger.Info("下发单机证书到 Agent",
		zap.String("agent_id", conn.AgentID),
		zap.Int("cert_size", len(cmd.CertificateBundle.ClientCert)),
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
