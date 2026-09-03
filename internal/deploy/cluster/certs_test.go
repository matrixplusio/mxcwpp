package cluster

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

// buildTestConfig 构造最小 Config，含两组 SAN 用于 reissue 测试。
func buildTestConfig(dns []string, ips []string) *Config {
	cfg := &Config{}
	cfg.Network.GRPC.Host = ""
	cfg.Network.UI.Host = ""
	cfg.Network.AdditionalSANs.DNS = dns
	cfg.Network.AdditionalSANs.IPs = ips
	return cfg
}

func TestServerCertNeedsReissue(t *testing.T) {
	cfg := buildTestConfig([]string{"mxcwpp-ac.example.com"}, []string{"10.0.0.1"})
	bundle, err := GenerateCertificates(cfg)
	if err != nil {
		t.Fatalf("GenerateCertificates: %v", err)
	}

	// 同 cfg 不需 reissue
	need, err := ServerCertNeedsReissue(bundle, cfg)
	if err != nil {
		t.Fatalf("ServerCertNeedsReissue: %v", err)
	}
	if need {
		t.Fatal("现 cert SAN 应覆盖 cfg，不应 reissue")
	}

	// cfg 增加新 SAN 后应需 reissue
	cfgChanged := buildTestConfig([]string{"mxcwpp-ac.example.com", "new-host.example.com"}, []string{"10.0.0.1", "10.0.0.2"})
	need, err = ServerCertNeedsReissue(bundle, cfgChanged)
	if err != nil {
		t.Fatalf("ServerCertNeedsReissue changed: %v", err)
	}
	if !need {
		t.Fatal("cfg 新增 SAN 但 cert 未含，应 reissue")
	}

	// nil bundle 视为需 reissue
	need, _ = ServerCertNeedsReissue(nil, cfg)
	if !need {
		t.Fatal("nil bundle 应需 reissue")
	}
}

func TestSignAgentCert(t *testing.T) {
	cfg := buildTestConfig([]string{"mxcwpp-ac.example.com"}, []string{"10.0.0.1"})
	bundle, err := GenerateCertificates(cfg)
	if err != nil {
		t.Fatalf("GenerateCertificates: %v", err)
	}

	const agentID = "agent-abc123"
	certPEM, keyPEM, err := SignAgentCert(bundle, agentID)
	if err != nil {
		t.Fatalf("SignAgentCert: %v", err)
	}
	if len(certPEM) == 0 || len(keyPEM) == 0 {
		t.Fatal("签发结果为空")
	}

	// 解析证书，CN 必须等于 agentID
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("agent cert PEM 解析失败")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("解析 agent cert: %v", err)
	}
	if cert.Subject.CommonName != agentID {
		t.Fatalf("CN 应为 %q，实际 %q", agentID, cert.Subject.CommonName)
	}

	// ExtKeyUsage 必须含 ClientAuth
	hasClientAuth := false
	for _, u := range cert.ExtKeyUsage {
		if u == x509.ExtKeyUsageClientAuth {
			hasClientAuth = true
		}
	}
	if !hasClientAuth {
		t.Fatal("agent cert 缺 ClientAuth ExtKeyUsage")
	}

	// 必须由 bundle 的 CA 签发（验签链）
	caBlock, _ := pem.Decode(bundle.CACert)
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		t.Fatalf("解析 CA: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Fatalf("agent cert 应由 bundle CA 签发: %v", err)
	}

	// cert 与 key 必须配对（能组成 TLS keypair）
	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		t.Fatalf("cert/key 不配对: %v", err)
	}

	// 两次签发 CN 相同但序列号不同（独立证书）
	cert2PEM, _, err := SignAgentCert(bundle, agentID)
	if err != nil {
		t.Fatalf("SignAgentCert 第二次: %v", err)
	}
	block2, _ := pem.Decode(cert2PEM)
	cert2, _ := x509.ParseCertificate(block2.Bytes)
	if cert.SerialNumber.Cmp(cert2.SerialNumber) == 0 {
		t.Fatal("两次签发序列号不应相同")
	}

	// 空 agentID 必须报错
	if _, _, err := SignAgentCert(bundle, ""); err == nil {
		t.Fatal("空 agentID 应报错")
	}
	if _, _, err := SignAgentCert(nil, agentID); err == nil {
		t.Fatal("nil bundle 应报错")
	}
}

func TestReissueServerCertPreservesCAAndKey(t *testing.T) {
	cfg := buildTestConfig([]string{"old.example.com"}, []string{"10.0.0.1"})
	bundle, err := GenerateCertificates(cfg)
	if err != nil {
		t.Fatalf("GenerateCertificates: %v", err)
	}

	origCA := append([]byte{}, bundle.CACert...)
	origCAKey := append([]byte{}, bundle.CAKey...)
	origServerKey := append([]byte{}, bundle.ServerKey...)
	origAgentCert := append([]byte{}, bundle.AgentCert...)
	origServerCert := append([]byte{}, bundle.ServerCert...)

	cfgNew := buildTestConfig([]string{"mxcwpp-ac.example.com"}, []string{"10.0.0.2", "10.0.0.3"})
	if err := ReissueServerCert(bundle, cfgNew); err != nil {
		t.Fatalf("ReissueServerCert: %v", err)
	}

	// CA + ServerKey + AgentCert 必须不变
	if string(bundle.CACert) != string(origCA) {
		t.Fatal("CA 证书被改动")
	}
	if string(bundle.CAKey) != string(origCAKey) {
		t.Fatal("CA 私钥被改动")
	}
	if string(bundle.ServerKey) != string(origServerKey) {
		t.Fatal("Server 私钥被改动")
	}
	if string(bundle.AgentCert) != string(origAgentCert) {
		t.Fatal("Agent 证书被改动")
	}
	if string(bundle.ServerCert) == string(origServerCert) {
		t.Fatal("Server 证书应被重签")
	}

	// 新 server.crt SAN 必须含 cfgNew 的全部值
	block, _ := pem.Decode(bundle.ServerCert)
	if block == nil {
		t.Fatal("新 server.crt PEM 解析失败")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("解析新 server.crt: %v", err)
	}
	dnsFound := false
	for _, name := range cert.DNSNames {
		if name == "mxcwpp-ac.example.com" {
			dnsFound = true
		}
	}
	if !dnsFound {
		t.Fatalf("新 server.crt DNS SAN 缺 mxcwpp-ac.example.com，实际: %v", cert.DNSNames)
	}
	ipFound := map[string]bool{}
	for _, ip := range cert.IPAddresses {
		ipFound[ip.String()] = true
	}
	if !ipFound["10.0.0.2"] || !ipFound["10.0.0.3"] {
		t.Fatalf("新 server.crt IP SAN 缺，实际: %v", cert.IPAddresses)
	}

	// 重签后 ServerCertNeedsReissue 应返回 false
	need, err := ServerCertNeedsReissue(bundle, cfgNew)
	if err != nil {
		t.Fatalf("ServerCertNeedsReissue after reissue: %v", err)
	}
	if need {
		t.Fatal("重签后不应再需 reissue")
	}
}
