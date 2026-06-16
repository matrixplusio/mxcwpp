package cluster

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/imkerbos/mxsec-platform/internal/common/certissue"
)

// LoadCertificatesFromDir 从目录加载已有证书。
// 如果目录不存在或证书不完整，返回 nil, nil。
func LoadCertificatesFromDir(dir string) (*CertificateBundle, error) {
	required := []string{"ca.crt", "ca.key", "server.crt", "server.key", "agent.crt", "agent.key", "client.crt", "client.key"}
	for _, name := range required {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			return nil, nil // 不完整，返回 nil 表示需要重新生成
		}
	}
	bundle := &CertificateBundle{}
	files := map[string]*[]byte{
		"ca.crt":     &bundle.CACert,
		"ca.key":     &bundle.CAKey,
		"server.crt": &bundle.ServerCert,
		"server.key": &bundle.ServerKey,
		"agent.crt":  &bundle.AgentCert,
		"agent.key":  &bundle.AgentKey,
		"client.crt": &bundle.ClientCert,
		"client.key": &bundle.ClientKey,
	}
	for name, dst := range files {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, fmt.Errorf("读取证书文件 %s 失败: %w", name, err)
		}
		*dst = data
	}
	return bundle, nil
}

// SaveCertificatesToDir 将证书写入目录，供后续复用。
func SaveCertificatesToDir(dir string, bundle *CertificateBundle) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	files := map[string][]byte{
		"ca.crt":     bundle.CACert,
		"ca.key":     bundle.CAKey,
		"server.crt": bundle.ServerCert,
		"server.key": bundle.ServerKey,
		"agent.crt":  bundle.AgentCert,
		"agent.key":  bundle.AgentKey,
		"client.crt": bundle.ClientCert,
		"client.key": bundle.ClientKey,
	}
	for name, content := range files {
		mode := os.FileMode(0o644)
		if strings.HasSuffix(name, ".key") {
			mode = 0o600
		}
		if err := os.WriteFile(filepath.Join(dir, name), content, mode); err != nil {
			return fmt.Errorf("写入证书 %s 失败: %w", name, err)
		}
	}
	return nil
}

type CertificateBundle struct {
	CACert     []byte
	CAKey      []byte
	ServerCert []byte
	ServerKey  []byte
	AgentCert  []byte
	AgentKey   []byte
	ClientCert []byte
	ClientKey  []byte
}

// GenerateCertificates 生成部署 bundle 使用的 mTLS 证书。
func GenerateCertificates(cfg *Config) (*CertificateBundle, error) {
	now := time.Now().UTC()
	caKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, fmt.Errorf("生成 CA 私钥失败: %w", err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()),
		Subject: pkix.Name{
			Country:            []string{"CN"},
			Organization:       []string{"Matrix Cloud Security Platform"},
			OrganizationalUnit: []string{"CA"},
			CommonName:         "mxsec-ca",
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("生成 CA 证书失败: %w", err)
	}

	serverKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, fmt.Errorf("生成 Server 私钥失败: %w", err)
	}
	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano() + 1),
		Subject: pkix.Name{
			Country:            []string{"CN"},
			Organization:       []string{"Matrix Cloud Security Platform"},
			OrganizationalUnit: []string{"Server"},
			CommonName:         "mxsec-server",
		},
		NotBefore:   now.Add(-time.Hour),
		NotAfter:    now.AddDate(5, 0, 0),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: nil,
		DNSNames:    nil,
	}
	ips, dns := cfg.SANValues()
	for _, value := range ips {
		if parsed := net.ParseIP(value); parsed != nil {
			serverTemplate.IPAddresses = append(serverTemplate.IPAddresses, parsed)
		}
	}
	serverTemplate.DNSNames = append(serverTemplate.DNSNames, dns...)
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caTemplate, &serverKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("生成 Server 证书失败: %w", err)
	}

	agentKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, fmt.Errorf("生成 Agent 私钥失败: %w", err)
	}
	agentTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano() + 2),
		Subject: pkix.Name{
			Country:            []string{"CN"},
			Organization:       []string{"Matrix Cloud Security Platform"},
			OrganizationalUnit: []string{"Agent"},
			CommonName:         "mxsec-agent",
		},
		NotBefore:   now.Add(-time.Hour),
		NotAfter:    now.AddDate(5, 0, 0),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	agentDER, err := x509.CreateCertificate(rand.Reader, agentTemplate, caTemplate, &agentKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("生成 Agent 证书失败: %w", err)
	}

	bundle := &CertificateBundle{
		CACert:     pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		CAKey:      pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(caKey)}),
		ServerCert: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER}),
		ServerKey:  pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(serverKey)}),
		AgentCert:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: agentDER}),
		AgentKey:   pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(agentKey)}),
	}
	bundle.ClientCert = bundle.AgentCert
	bundle.ClientKey = bundle.AgentKey
	return bundle, nil
}

// SignAgentCert 用 bundle 中现有的 CA 给单台 agent 签发独立客户端证书。
// CommonName 设为 agentID，供 AC 在应用层校验 TLS peer 证书 CN 与上报 AgentID 一致（一机一证）。
// 与全网共享的 agent.crt 不同：每台 agent 一张，失陷可单独吊销，私钥泄露不影响他机。
// 返回新签发的 certPEM 与 keyPEM；CA 与 bundle 内其他证书不变。
func SignAgentCert(bundle *CertificateBundle, agentID string) (certPEM []byte, keyPEM []byte, err error) {
	if bundle == nil {
		return nil, nil, fmt.Errorf("bundle 为空")
	}
	return certissue.SignAgentCert(bundle.CACert, bundle.CAKey, agentID, 0)
}

// parseRSAPrivateKey 解析 PEM 编码的 RSA 私钥，兼容 PKCS#1 与 PKCS#8 格式。
func parseRSAPrivateKey(pemData []byte) (*rsa.PrivateKey, error) {
	return certissue.ParseRSAPrivateKey(pemData)
}

// ServerCertNeedsReissue 校验 bundle 中 server.crt 的 SAN 是否覆盖 cfg.SANValues()。
// 缺失任一 IP/DNS 返回 true，调用方需触发 ReissueServerCert。
// bundle 或 server.crt 解析失败也返回 true（保守重签）。
func ServerCertNeedsReissue(bundle *CertificateBundle, cfg *Config) (bool, error) {
	if bundle == nil || len(bundle.ServerCert) == 0 {
		return true, nil
	}
	block, _ := pem.Decode(bundle.ServerCert)
	if block == nil {
		return true, fmt.Errorf("server.crt 不是有效 PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return true, fmt.Errorf("解析 server.crt 失败: %w", err)
	}

	expectedIPs, expectedDNS := cfg.SANValues()
	haveDNS := map[string]struct{}{}
	for _, name := range cert.DNSNames {
		haveDNS[name] = struct{}{}
	}
	haveIP := map[string]struct{}{}
	for _, ip := range cert.IPAddresses {
		haveIP[ip.String()] = struct{}{}
	}
	for _, name := range expectedDNS {
		if _, ok := haveDNS[name]; !ok {
			return true, nil
		}
	}
	for _, value := range expectedIPs {
		parsed := net.ParseIP(value)
		if parsed == nil {
			continue
		}
		if _, ok := haveIP[parsed.String()]; !ok {
			return true, nil
		}
	}
	return false, nil
}

// ReissueServerCert 用 bundle 中现有的 CA 与 ServerKey 重签 server.crt，注入 cfg.SANValues()。
// 保留 CA 与 ServerKey 不变，避免影响已部署 agent 的 ca.crt 信任链。
// 重签成功后 bundle.ServerCert 被覆盖。
func ReissueServerCert(bundle *CertificateBundle, cfg *Config) error {
	if bundle == nil {
		return fmt.Errorf("bundle 为空")
	}
	caBlock, _ := pem.Decode(bundle.CACert)
	if caBlock == nil {
		return fmt.Errorf("CA 证书不是有效 PEM")
	}
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return fmt.Errorf("解析 CA 证书失败: %w", err)
	}
	caKey, err := parseRSAPrivateKey(bundle.CAKey)
	if err != nil {
		return fmt.Errorf("解析 CA 私钥失败: %w", err)
	}
	serverKey, err := parseRSAPrivateKey(bundle.ServerKey)
	if err != nil {
		return fmt.Errorf("解析 Server 私钥失败: %w", err)
	}

	now := time.Now().UTC()
	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano() + 1),
		Subject: pkix.Name{
			Country:            []string{"CN"},
			Organization:       []string{"Matrix Cloud Security Platform"},
			OrganizationalUnit: []string{"Server"},
			CommonName:         "mxsec-server",
		},
		NotBefore:   now.Add(-time.Hour),
		NotAfter:    now.AddDate(5, 0, 0),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	ips, dns := cfg.SANValues()
	for _, value := range ips {
		if parsed := net.ParseIP(value); parsed != nil {
			serverTemplate.IPAddresses = append(serverTemplate.IPAddresses, parsed)
		}
	}
	serverTemplate.DNSNames = append(serverTemplate.DNSNames, dns...)

	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("重签 Server 证书失败: %w", err)
	}
	bundle.ServerCert = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER})
	return nil
}
