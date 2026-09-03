package sdclient

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"time"
)

// MTLSConfig 是 SD Client 内部通信的 mTLS 配置。
//
// 启用后:
//   - manager_addr 必须是 https:// 前缀
//   - 客户端证书 ClientCert/ClientKey 必须存在且未过期
//   - 服务端必须用 CACert 签名,SAN 必须匹配 ManagerHost(可选)
//
// 配置优先级:
//   - 同时配置 MTLSConfig 与 X-Internal-Secret 时, mTLS 优先生效;
//     Secret 仍发送供 Manager 端二次校验(纵深防御)。
//   - 仅配置 Secret 不配 MTLSConfig,继续走 v1 行为(HTTP + Secret)。
//
// 详见 docs/architecture.md §7 安全与通信 + docs/multi-tenant.md §1.
type MTLSConfig struct {
	Enabled    bool   // 是否启用 mTLS
	CACertPath string // PEM CA 证书(用于校验 Manager 端证书)
	ClientCert string // PEM 客户端证书路径
	ClientKey  string // PEM 客户端私钥路径
	ServerName string // 期望 Manager 证书 SAN; 留空时不强制
}

// buildHTTPClient 根据 MTLSConfig 构造 *http.Client。
// 未启用 mTLS 时返回默认 client (与 v1 行为一致)。
func buildHTTPClient(cfg MTLSConfig, timeout time.Duration) (*http.Client, error) {
	if !cfg.Enabled {
		return &http.Client{Timeout: timeout}, nil
	}

	cert, err := tls.LoadX509KeyPair(cfg.ClientCert, cfg.ClientKey)
	if err != nil {
		return nil, fmt.Errorf("load client cert/key: %w", err)
	}

	caPool, err := loadCAPool(cfg.CACertPath)
	if err != nil {
		return nil, err
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caPool,
		MinVersion:   tls.VersionTLS12,
		ServerName:   cfg.ServerName,
	}

	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig:       tlsCfg,
			ResponseHeaderTimeout: timeout,
		},
	}, nil
}

func loadCAPool(path string) (*x509.CertPool, error) {
	if path == "" {
		return nil, fmt.Errorf("mtls.ca_cert_path is required when mtls.enabled=true")
	}
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read ca cert: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("ca cert pem invalid: %s", path)
	}
	return pool, nil
}
