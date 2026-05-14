// Package config 提供配置同步功能
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/imkerbos/mxsec-platform/api/proto/grpc"
)

// SyncFromServer 从 Server 下发的 AgentConfig 同步配置
func (c *Config) SyncFromServer(agentConfig *grpc.AgentConfig) error {
	if agentConfig == nil {
		return nil
	}

	remote := RemoteConfig{
		Loaded: true,
	}

	// 心跳间隔
	if agentConfig.HeartbeatInterval > 0 {
		remote.HeartbeatInterval = time.Duration(agentConfig.HeartbeatInterval) * time.Second
	} else {
		remote.HeartbeatInterval = 60 * time.Second // 默认值
	}

	// 工作目录
	if agentConfig.WorkDir != "" {
		remote.WorkDir = agentConfig.WorkDir
	} else {
		remote.WorkDir = "/var/lib/mxsec-agent" // 默认值
	}

	// 产品名称
	if agentConfig.Product != "" {
		remote.Product = agentConfig.Product
	} else {
		remote.Product = "mxsec-agent" // 默认值
	}

	// 版本
	if agentConfig.Version != "" {
		remote.Version = agentConfig.Version
	} else {
		remote.Version = "1.0.0" // 默认值
	}

	// 额外配置
	if agentConfig.Extra != nil {
		remote.Extra = make(map[string]string)
		for k, v := range agentConfig.Extra {
			remote.Extra[k] = v
		}
	}

	c.UpdateRemoteConfig(&remote)
	return nil
}

// SyncCertificatesFromServer 从 Server 下发的证书包同步证书
func (c *Config) SyncCertificatesFromServer(certBundle *grpc.CertificateBundle, certDir string) error {
	if certBundle == nil {
		return nil
	}

	// 确保证书目录存在
	if err := os.MkdirAll(certDir, 0755); err != nil {
		return fmt.Errorf("failed to create cert directory: %w", err)
	}

	// 保存证书到文件
	if err := SaveCertificates(certDir, certBundle.CaCert, certBundle.ClientCert, certBundle.ClientKey); err != nil {
		return fmt.Errorf("failed to save certificates: %w", err)
	}

	// 更新本地配置中的证书路径
	c.Local.TLS.CAFile = fmt.Sprintf("%s/ca.crt", certDir)
	c.Local.TLS.CertFile = fmt.Sprintf("%s/client.crt", certDir)
	c.Local.TLS.KeyFile = fmt.Sprintf("%s/client.key", certDir)

	// 验证证书
	if err := ValidateCertificates(c.Local.TLS.CAFile, c.Local.TLS.CertFile, c.Local.TLS.KeyFile); err != nil {
		return fmt.Errorf("certificate validation failed: %w", err)
	}

	return nil
}

// ParseAgentConfigFromJSON 从 JSON 字符串解析 AgentConfig（用于测试或兼容）
func ParseAgentConfigFromJSON(jsonStr string) (*grpc.AgentConfig, error) {
	var agentConfig grpc.AgentConfig
	if err := json.Unmarshal([]byte(jsonStr), &agentConfig); err != nil {
		return nil, fmt.Errorf("failed to parse agent config JSON: %w", err)
	}
	return &agentConfig, nil
}
