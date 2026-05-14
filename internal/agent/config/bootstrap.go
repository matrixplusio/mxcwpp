// Package config 提供配置引导功能
package config

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"go.uber.org/zap"
)

// BootstrapConfig 是引导配置（最小配置，用于首次连接）
type BootstrapConfig struct {
	// Server 地址（可通过构建时嵌入或环境变量）
	ServerURL string
	// 临时 Token（可选，用于首次认证）
	BootstrapToken string
	// Agent ID 文件路径
	IDFile string
	// 证书存储目录
	CertDir string
	// 日志配置（本地日志）
	Log LogConfig
}

// BootstrapFromServer 从 Server 引导配置（下载证书和配置）
func BootstrapFromServer(bootstrap *BootstrapConfig, logger *zap.Logger) (*Config, error) {
	// 1. 确保目录存在
	if err := os.MkdirAll(bootstrap.CertDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create cert directory: %w", err)
	}

	// 2. 检查是否已有证书（非首次启动）
	caCertPath := filepath.Join(bootstrap.CertDir, "ca.crt")
	clientCertPath := filepath.Join(bootstrap.CertDir, "client.crt")
	clientKeyPath := filepath.Join(bootstrap.CertDir, "client.key")

	hasCert := false
	if _, err := os.Stat(caCertPath); err == nil {
		if _, err := os.Stat(clientCertPath); err == nil {
			if _, err := os.Stat(clientKeyPath); err == nil {
				hasCert = true
			}
		}
	}

	// 3. 如果没有证书，从 Server 下载
	if !hasCert {
		logger.Info("no certificates found, downloading from server")
		if err := downloadCertificates(bootstrap, logger); err != nil {
			return nil, fmt.Errorf("failed to download certificates: %w", err)
		}
		logger.Info("certificates downloaded successfully")
	}

	// 4. 构建本地配置
	local := LocalConfig{
		IDFile: bootstrap.IDFile,
		Server: ServerConfig{
			AgentCenter: AgentCenterConfig{
				PrivateHost: extractHostFromURL(bootstrap.ServerURL),
			},
		},
		TLS: TLSConfig{
			CAFile:   caCertPath,
			CertFile: clientCertPath,
			KeyFile:  clientKeyPath,
		},
		Log: bootstrap.Log,
	}

	cfg := &Config{
		Local: local,
		Remote: RemoteConfig{
			Loaded: false,
		},
	}

	return cfg, nil
}

// downloadCertificates 从 Server 下载证书
func downloadCertificates(bootstrap *BootstrapConfig, logger *zap.Logger) error {
	// 创建 HTTP 客户端（跳过 TLS 验证，因为还没有证书）
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // 首次连接跳过验证
			},
		},
		Timeout: 30 * time.Second,
	}

	// 构建下载 URL
	certURL := fmt.Sprintf("%s/api/v1/agent/certificates", bootstrap.ServerURL)

	// 下载证书（token 通过 Header 传递，避免在 URL/日志中泄漏）
	req, err := http.NewRequest(http.MethodGet, certURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create certificate request: %w", err)
	}
	if bootstrap.BootstrapToken != "" {
		req.Header.Set("X-Bootstrap-Token", bootstrap.BootstrapToken)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to request certificates: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to download certificates: status %d", resp.StatusCode)
	}

	// TODO: 解析响应（JSON 格式的证书数据）
	// 这里需要根据 Server API 的实际响应格式来实现
	// 示例格式：
	// {
	//   "ca_cert": "-----BEGIN CERTIFICATE-----\n...",
	//   "client_cert": "-----BEGIN CERTIFICATE-----\n...",
	//   "client_key": "-----BEGIN PRIVATE KEY-----\n..."
	// }

	// 临时实现：从 gRPC Command 中获取证书（见 receiveCommands）
	// 这里先返回错误，提示需要通过 gRPC 获取
	return fmt.Errorf("certificate download via HTTP not implemented yet, use gRPC bootstrap")
}

// extractHostFromURL 从 URL 中提取主机地址
func extractHostFromURL(url string) string {
	// 简单实现：假设 URL 格式为 http://host:port 或 https://host:port
	// 提取 host:port 部分
	// TODO: 使用 url.Parse 更准确地解析
	if len(url) > 7 && url[:7] == "http://" {
		return url[7:]
	}
	if len(url) > 8 && url[:8] == "https://" {
		return url[8:]
	}
	return url
}

// SaveCertificates 保存证书到文件
func SaveCertificates(certDir string, caCert, clientCert, clientKey []byte) error {
	// 保存 CA 证书
	caCertPath := filepath.Join(certDir, "ca.crt")
	if err := os.WriteFile(caCertPath, caCert, 0644); err != nil {
		return fmt.Errorf("failed to save CA cert: %w", err)
	}

	// 保存客户端证书
	clientCertPath := filepath.Join(certDir, "client.crt")
	if err := os.WriteFile(clientCertPath, clientCert, 0644); err != nil {
		return fmt.Errorf("failed to save client cert: %w", err)
	}

	// 保存客户端密钥（更严格的权限）
	clientKeyPath := filepath.Join(certDir, "client.key")
	if err := os.WriteFile(clientKeyPath, clientKey, 0600); err != nil {
		return fmt.Errorf("failed to save client key: %w", err)
	}

	return nil
}

// ValidateCertificates 验证证书是否有效
func ValidateCertificates(caCertPath, clientCertPath, clientKeyPath string) error {
	// 读取 CA 证书
	caCertData, err := os.ReadFile(caCertPath)
	if err != nil {
		return fmt.Errorf("failed to read CA cert: %w", err)
	}

	// 解析 CA 证书
	block, _ := pem.Decode(caCertData)
	if block == nil {
		return fmt.Errorf("failed to decode CA cert PEM")
	}

	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse CA cert: %w", err)
	}

	// 读取客户端证书
	clientCertData, err := os.ReadFile(clientCertPath)
	if err != nil {
		return fmt.Errorf("failed to read client cert: %w", err)
	}

	// 解析客户端证书
	block, _ = pem.Decode(clientCertData)
	if block == nil {
		return fmt.Errorf("failed to decode client cert PEM")
	}

	clientCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse client cert: %w", err)
	}

	// 验证客户端证书是否由 CA 签名
	roots := x509.NewCertPool()
	roots.AddCert(caCert)

	// 指定证书用途为客户端认证，避免 "incompatible key usage" 错误
	opts := x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	if _, err := clientCert.Verify(opts); err != nil {
		return fmt.Errorf("failed to verify client cert: %w", err)
	}

	// 验证密钥是否匹配
	clientKeyData, err := os.ReadFile(clientKeyPath)
	if err != nil {
		return fmt.Errorf("failed to read client key: %w", err)
	}

	_, err = tls.X509KeyPair(clientCertData, clientKeyData)
	if err != nil {
		return fmt.Errorf("client cert and key mismatch: %w", err)
	}

	return nil
}
