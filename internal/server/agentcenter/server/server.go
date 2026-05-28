// Package server 提供 gRPC Server 创建和配置
package server

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"

	_ "github.com/imkerbos/mxsec-platform/internal/common/compressor" // 注册 Snappy 解压器（Agent 端压缩，Server 端解压）
	acmetrics "github.com/imkerbos/mxsec-platform/internal/server/agentcenter/metrics"
	"github.com/imkerbos/mxsec-platform/internal/server/config"
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

			tlsConfig.ClientCAs = caCertPool
			tlsConfig.ClientAuth = tls.VerifyClientCertIfGiven // 验证客户端证书（如果提供），允许无证书连接
			logger.Info("已启用 mTLS（客户端证书验证）",
				zap.String("cert", cfg.MTLS.ServerCert),
				zap.String("ca_cert", cfg.MTLS.CACert),
				zap.String("client_auth", "VerifyClientCertIfGiven（允许无证书首次连接）"),
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
	keepaliveParams := keepalive.ServerParameters{
		Time:    60 * time.Second, // 服务端每 60 秒发送 ping（如果没有活跃流）
		Timeout: 10 * time.Second, // ping 超时时间
	}

	// 配置 enforcement policy，允许客户端更频繁的 ping
	keepaliveEnforcementPolicy := keepalive.EnforcementPolicy{
		MinTime:             10 * time.Second, // 允许客户端最小 ping 间隔 10 秒（小于 Agent 的 30 秒）
		PermitWithoutStream: true,             // 即使没有活跃流也允许 ping
	}

	opts = append(opts,
		grpc.KeepaliveParams(keepaliveParams),
		grpc.KeepaliveEnforcementPolicy(keepaliveEnforcementPolicy),
		// 服务端指标：暴露 mxsec_ac_grpc_handled_total / duration_seconds 给 Prometheus 抓取
		grpc.UnaryInterceptor(acmetrics.UnaryServerInterceptor()),
		grpc.StreamInterceptor(acmetrics.StreamServerInterceptor()),
	)

	logger.Info("gRPC Server keepalive 配置",
		zap.Duration("server_keepalive_time", keepaliveParams.Time),
		zap.Duration("min_client_ping_time", 10*time.Second),
	)

	return grpc.NewServer(opts...), nil
}
