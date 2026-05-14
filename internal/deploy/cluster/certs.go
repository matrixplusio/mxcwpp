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
