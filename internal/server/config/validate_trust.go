package config

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/matrixplusio/mxcwpp/internal/common/certissue"
)

// validateAgentTrust 对 Agent↔AC 信任链做生产级 fail-fast 校验（E-SEC-3）。
//
// 只有全部满足才允许 AgentCenter 启动：
//   - ca_cert / ca_key / server_cert / server_key 均配置、可读；
//   - ca_cert 确为可签发 CA、未过期；ca_key 与 ca_cert 公钥配对；
//   - server_cert/server_key 配对、含 ServerAuth、未过期、且由该 CA 签发；
//   - enroll_token 存在且强（≥32、非占位符/弱值）；
//   - per_agent_cert 与 enforce_agent_id 均开启（一机一证 + 强制身份绑定）。
//
// 任一不满足即拒绝启动，杜绝“看似健康、信任面失效”的静默半失效。
func (c *Config) validateAgentTrust() error {
	m := c.MTLS
	for _, f := range []struct{ name, path string }{
		{"mtls.ca_cert", m.CACert},
		{"mtls.ca_key", m.CAKey},
		{"mtls.server_cert", m.ServerCert},
		{"mtls.server_key", m.ServerKey},
	} {
		if strings.TrimSpace(f.path) == "" {
			return fmt.Errorf("生产信任配置缺少 %s（需 CA + 服务端证书/私钥以启用 mTLS + 一机一证）", f.name)
		}
	}

	now := time.Now()

	// --- CA 证书 ---
	caPEM, err := os.ReadFile(m.CACert)
	if err != nil {
		return fmt.Errorf("读取 mtls.ca_cert 失败: %w", err)
	}
	caCert, err := parsePEMCertificate(caPEM)
	if err != nil {
		return fmt.Errorf("解析 mtls.ca_cert 失败: %w", err)
	}
	// 必须是 CA；若显式声明了 KeyUsage 扩展，则必须含 CertSign（未声明扩展时 KeyUsage==0，
	// 按 RFC 允许签发，与 x509 链构建的宽松策略一致）。
	if !caCert.IsCA {
		return fmt.Errorf("mtls.ca_cert 不是 CA（缺少 IsCA / BasicConstraints）")
	}
	if caCert.KeyUsage != 0 && caCert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return fmt.Errorf("mtls.ca_cert 声明了 KeyUsage 但缺少 CertSign，无法签发证书")
	}
	if now.Before(caCert.NotBefore) || now.After(caCert.NotAfter) {
		return fmt.Errorf("mtls.ca_cert 不在有效期内（%s ~ %s）", caCert.NotBefore, caCert.NotAfter)
	}

	// --- CA 私钥，且与 CA 证书公钥配对 ---
	caKeyPEM, err := os.ReadFile(m.CAKey)
	if err != nil {
		return fmt.Errorf("读取 mtls.ca_key 失败: %w", err)
	}
	caKey, err := certissue.ParseRSAPrivateKey(caKeyPEM)
	if err != nil {
		return fmt.Errorf("解析 mtls.ca_key 失败: %w", err)
	}
	caPub, ok := caCert.PublicKey.(*rsa.PublicKey)
	if !ok || !caKey.PublicKey.Equal(caPub) {
		return fmt.Errorf("mtls.ca_key 与 mtls.ca_cert 不配对（无法用于签发单机证书）")
	}

	// --- 服务端证书/私钥配对 ---
	srvPair, err := tls.LoadX509KeyPair(m.ServerCert, m.ServerKey)
	if err != nil {
		return fmt.Errorf("mtls.server_cert / mtls.server_key 加载或配对失败: %w", err)
	}
	srvLeaf, err := x509.ParseCertificate(srvPair.Certificate[0])
	if err != nil {
		return fmt.Errorf("解析 mtls.server_cert 失败: %w", err)
	}
	if now.Before(srvLeaf.NotBefore) || now.After(srvLeaf.NotAfter) {
		return fmt.Errorf("mtls.server_cert 不在有效期内（%s ~ %s）", srvLeaf.NotBefore, srvLeaf.NotAfter)
	}
	if !slices.Contains(srvLeaf.ExtKeyUsage, x509.ExtKeyUsageServerAuth) {
		return fmt.Errorf("mtls.server_cert 缺少 ServerAuth 用途")
	}
	// 服务端证书必须由该 CA 签发。
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	if _, err := srvLeaf.Verify(x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		return fmt.Errorf("mtls.server_cert 非由 mtls.ca_cert 签发: %w", err)
	}

	// --- enroll 令牌与强制开关 ---
	if err := ValidateEnrollToken(m.EnrollToken); err != nil {
		return err
	}
	if !m.PerAgentCert {
		return fmt.Errorf("生产模式要求 mtls.per_agent_cert=true（一机一证），当前为 false")
	}
	if !m.EnforceAgentID {
		return fmt.Errorf("生产模式要求 mtls.enforce_agent_id=true（强制客户端证书 CN==AgentID），当前为 false")
	}
	return nil
}

// parsePEMCertificate 解析 PEM 中的第一张证书。
func parsePEMCertificate(pemData []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("不是有效 PEM 证书")
	}
	return x509.ParseCertificate(block.Bytes)
}
