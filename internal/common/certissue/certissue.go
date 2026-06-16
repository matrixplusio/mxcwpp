// Package certissue 提供按 AgentID 在线签发单机客户端证书的能力。
//
// 用于 Agent↔AC mTLS 信任链改造：每台 agent 一张独立证书（CN=AgentID），
// 取代全网共享的单张 agent 证书。失陷主机可单独吊销，私钥泄露不影响他机。
// AC 持有 CA 证书 + CA 私钥，在 agent enroll 时按其上报的 AgentID 现场签发。
package certissue

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// DefaultAgentCertValidity 单机证书默认有效期（1 年，配合定期轮换）。
const DefaultAgentCertValidity = 365 * 24 * time.Hour

// EnrollTokenMetaKey 是 agent 通过 gRPC metadata 上报 enroll 引导令牌时使用的 key。
// AC 经 metadata.FromIncomingContext 读取并校验，令牌不进入 proto 消息体（避免落日志）。
const EnrollTokenMetaKey = "x-enroll-token"

// ParseRSAPrivateKey 解析 PEM 编码的 RSA 私钥，兼容 PKCS#1 与 PKCS#8 格式。
func ParseRSAPrivateKey(pemData []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("私钥不是有效 PEM")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("PKCS1 与 PKCS8 解析均失败: %w", err)
	}
	rsaKey, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("私钥不是 RSA 类型: %T", parsed)
	}
	return rsaKey, nil
}

// SignAgentCert 用 CA 证书 + CA 私钥给单台 agent 签发独立客户端证书。
//
// CommonName 设为 agentID，供 AC 在应用层校验 TLS peer 证书 CN 与上报 AgentID 一致。
// validity<=0 时使用 DefaultAgentCertValidity。
// 返回新签发的 certPEM 与 keyPEM；不修改入参。
func SignAgentCert(caCertPEM, caKeyPEM []byte, agentID string, validity time.Duration) (certPEM, keyPEM []byte, err error) {
	if strings.TrimSpace(agentID) == "" {
		return nil, nil, fmt.Errorf("agentID 不能为空")
	}
	if validity <= 0 {
		validity = DefaultAgentCertValidity
	}

	caBlock, _ := pem.Decode(caCertPEM)
	if caBlock == nil {
		return nil, nil, fmt.Errorf("CA 证书不是有效 PEM")
	}
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("解析 CA 证书失败: %w", err)
	}
	caKey, err := ParseRSAPrivateKey(caKeyPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("解析 CA 私钥失败: %w", err)
	}

	now := time.Now().UTC()
	agentKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, fmt.Errorf("生成 Agent 私钥失败: %w", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()),
		Subject: pkix.Name{
			Country:            []string{"CN"},
			Organization:       []string{"Matrix Cloud Security Platform"},
			OrganizationalUnit: []string{"Agent"},
			CommonName:         agentID,
		},
		NotBefore:   now.Add(-time.Hour),
		NotAfter:    now.Add(validity),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, caCert, &agentKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("签发 Agent 证书失败: %w", err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(agentKey)})
	return certPEM, keyPEM, nil
}

// CAFingerprint 计算 CA 证书 DER 的 SHA256 十六进制指纹，供 agent 首连 pin。
func CAFingerprint(caCertPEM []byte) (string, error) {
	block, _ := pem.Decode(caCertPEM)
	if block == nil {
		return "", fmt.Errorf("CA 证书不是有效 PEM")
	}
	return FingerprintDER(block.Bytes), nil
}
