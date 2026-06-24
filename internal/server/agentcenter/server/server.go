// Package server 提供 gRPC Server 创建和配置
package server

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"

	_ "github.com/matrixplusio/mxcwpp/internal/common/compressor" // 注册 Snappy 解压器（Agent 端压缩，Server 端解压）
	acmetrics "github.com/matrixplusio/mxcwpp/internal/server/agentcenter/metrics"
	"github.com/matrixplusio/mxcwpp/internal/server/config"
)

// CreateGRPCServer 创建并配置 gRPC Server
func CreateGRPCServer(cfg *config.Config, logger *zap.Logger) (*grpc.Server, error) {
	var opts []grpc.ServerOption

	// 配置 mTLS（如果提供了证书）
	if cfg.MTLS.ServerCert != "" && cfg.MTLS.ServerKey != "" {
		// 加载服务器证书和密钥
		cert, err := tls.LoadX509KeyPair(cfg.MTLS.ServerCert, cfg.MTLS.ServerKey)
		if err != nil {
			return nil, fmt.Errorf("加载服务器证书失败: %w", err)
		}

		// 创建 TLS 配置
		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
		}

		// 如果提供了 CA 证书，配置客户端证书验证（mTLS）
		if cfg.MTLS.CACert != "" {
			caCert, err := os.ReadFile(cfg.MTLS.CACert)
			if err != nil {
				return nil, fmt.Errorf("读取 CA 证书失败: %w", err)
			}

			caCertPool := x509.NewCertPool()
			if !caCertPool.AppendCertsFromPEM(caCert) {
				return nil, fmt.Errorf("解析 CA 证书失败")
			}

			// 把 CA 加入服务端 presented chain，使首连 pin CA 指纹的 agent 能在握手中看到 CA。
			// 默认 TLS 只发叶子证书，pin 会 fail-closed 挡住 enroll；附带 CA 后 pin 才能匹配。
			if caBlock, _ := pem.Decode(caCert); caBlock != nil {
				tlsConfig.Certificates[0].Certificate = append(tlsConfig.Certificates[0].Certificate, caBlock.Bytes)
			}

			tlsConfig.ClientCAs = caCertPool
			// 保留 VerifyClientCertIfGiven：首连 enroll 的 agent 尚无客户端证书，需放行以签发单机证书。
			// 真正的强制鉴权在应用层（transfer.Transfer：EnforceAgentID + CN==AgentID 绑定），
			// 单一监听端口无法对 enroll 与正常流分别设 ClientAuth，故用 TLS 放行 + 应用层强制的组合。
			tlsConfig.ClientAuth = tls.VerifyClientCertIfGiven

			// 证书吊销：握手期拒绝吊销序列号，覆盖该监听上的所有服务（Transfer / FileExt）。
			if revoked := buildRevokedSet(cfg.MTLS.RevokedSerials); len(revoked) > 0 {
				tlsConfig.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
					for _, raw := range rawCerts {
						cert, err := x509.ParseCertificate(raw)
						if err != nil {
							continue
						}
						if cert.SerialNumber != nil && revoked[cert.SerialNumber.String()] {
							logger.Warn("拒绝已吊销证书", zap.String("serial", cert.SerialNumber.String()))
							return fmt.Errorf("客户端证书已吊销: %s", cert.SerialNumber.String())
						}
					}
					return nil
				}
			}
			logger.Info("已启用 mTLS（客户端证书验证）",
				zap.String("cert", cfg.MTLS.ServerCert),
				zap.String("ca_cert", cfg.MTLS.CACert),
				zap.String("client_auth", "VerifyClientCertIfGiven + 应用层强制 CN 绑定"),
				zap.Bool("enforce_agent_id", cfg.MTLS.EnforceAgentID),
				zap.Bool("per_agent_cert", cfg.MTLS.PerAgentCert),
				zap.Int("revoked_serials", len(cfg.MTLS.RevokedSerials)),
			)
		} else {
			logger.Warn("未配置 CA 证书，仅启用服务器 TLS（不验证客户端证书）")
		}

		creds := credentials.NewTLS(tlsConfig)
		opts = append(opts, grpc.Creds(creds))
	} else {
		logger.Warn("未配置 mTLS 证书，使用不安全连接（仅用于开发）")
	}

	// 配置 keepalive 参数，允许客户端频繁发送 ping
	// P2-4: 加 MaxConnectionAge + MaxConnectionAgeGrace 强制长连接定期重置, 防 LB 倾斜.
	keepaliveParams := keepalive.ServerParameters{
		Time:                  60 * time.Second, // 服务端每 60 秒发送 ping（如果没有活跃流）
		Timeout:               10 * time.Second, // ping 超时时间
		MaxConnectionAge:      12 * time.Hour,   // P2-4: 连接 12h 强制重连, LB 重均衡
		MaxConnectionAgeGrace: 5 * time.Minute,  // 给客户端 5min 优雅迁移
		MaxConnectionIdle:     30 * time.Minute, // 空闲 30min 主动关
	}

	// 配置 enforcement policy，允许客户端更频繁的 ping
	keepaliveEnforcementPolicy := keepalive.EnforcementPolicy{
		MinTime:             10 * time.Second, // 允许客户端最小 ping 间隔 10 秒（小于 Agent 的 30 秒）
		PermitWithoutStream: true,             // 即使没有活跃流也允许 ping
	}

	opts = append(opts,
		grpc.KeepaliveParams(keepaliveParams),
		grpc.KeepaliveEnforcementPolicy(keepaliveEnforcementPolicy),
		// P2-4: 大消息上限提到 16MB (默认 4MB), 防 SBOM / 漏洞情报 / 包文件传输被截
		grpc.MaxRecvMsgSize(16*1024*1024),
		grpc.MaxSendMsgSize(16*1024*1024),
	)

	// 批4 抗 DoS：panic recovery 始终在拦截器链首（保护后续拦截器与 handler），
	// 之后接指标拦截器；per_ip_rps>0 时再插入单 IP 令牌桶限流。
	antiDoS := cfg.Server.GRPC.AntiDoS
	unaryChain := []grpc.UnaryServerInterceptor{recoveryUnaryInterceptor(logger)}
	streamChain := []grpc.StreamServerInterceptor{recoveryStreamInterceptor(logger)}
	if antiDoS.PerIPRPS > 0 {
		ipLimiter := newIPRateLimiter(antiDoS.PerIPRPS, antiDoS.PerIPBurst)
		unaryChain = append(unaryChain, ipLimiter.unaryInterceptor())
		streamChain = append(streamChain, ipLimiter.streamInterceptor())
		logger.Info("AC gRPC 单 IP 限流已启用",
			zap.Int("per_ip_rps", antiDoS.PerIPRPS), zap.Int("per_ip_burst", antiDoS.PerIPBurst))
	}
	// 服务端指标：暴露 mxcwpp_ac_grpc_handled_total / duration_seconds 给 Prometheus 抓取
	unaryChain = append(unaryChain, acmetrics.UnaryServerInterceptor())
	streamChain = append(streamChain, acmetrics.StreamServerInterceptor())
	opts = append(opts,
		grpc.ChainUnaryInterceptor(unaryChain...),
		grpc.ChainStreamInterceptor(streamChain...),
	)

	// 每连接最大并发流上限：防单个 agent 连接开海量流耗尽服务端资源。
	if antiDoS.MaxConcurrentStreams > 0 {
		opts = append(opts, grpc.MaxConcurrentStreams(antiDoS.MaxConcurrentStreams))
		logger.Info("AC gRPC MaxConcurrentStreams 已设置", zap.Uint32("max", antiDoS.MaxConcurrentStreams))
	}

	logger.Info("gRPC Server keepalive 配置",
		zap.Duration("server_keepalive_time", keepaliveParams.Time),
		zap.Duration("min_client_ping_time", 10*time.Second),
	)

	return grpc.NewServer(opts...), nil
}

// buildRevokedSet 把吊销序列号列表转为 set，便于握手期 O(1) 查询。
func buildRevokedSet(serials []string) map[string]bool {
	if len(serials) == 0 {
		return nil
	}
	set := make(map[string]bool, len(serials))
	for _, s := range serials {
		if s != "" {
			set[s] = true
		}
	}
	return set
}
