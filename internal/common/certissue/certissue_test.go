package certissue

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

// newTestCA 生成一对自签 CA（cert PEM + key PEM）供测试。
func newTestCA(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen ca key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create ca cert: %v", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return certPEM, keyPEM
}

func TestSignAgentCertCNAndChain(t *testing.T) {
	caCertPEM, caKeyPEM := newTestCA(t)
	const agentID = "host-xyz"

	certPEM, keyPEM, err := SignAgentCert(caCertPEM, caKeyPEM, agentID, time.Hour)
	if err != nil {
		t.Fatalf("SignAgentCert: %v", err)
	}

	block, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	if cert.Subject.CommonName != agentID {
		t.Fatalf("CN = %q, want %q", cert.Subject.CommonName, agentID)
	}

	// 验链：由测试 CA 签发
	caBlock, _ := pem.Decode(caCertPEM)
	caCert, _ := x509.ParseCertificate(caBlock.Bytes)
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatalf("verify chain: %v", err)
	}
	if len(keyPEM) == 0 {
		t.Fatal("key empty")
	}

	// 异常输入
	if _, _, err := SignAgentCert(caCertPEM, caKeyPEM, "", time.Hour); err == nil {
		t.Fatal("空 agentID 应报错")
	}
	if _, _, err := SignAgentCert([]byte("not pem"), caKeyPEM, agentID, time.Hour); err == nil {
		t.Fatal("无效 CA cert 应报错")
	}
}

func TestFingerprintAndPin(t *testing.T) {
	caCertPEM, _ := newTestCA(t)
	fp, err := CAFingerprint(caCertPEM)
	if err != nil {
		t.Fatalf("CAFingerprint: %v", err)
	}
	if len(fp) != 64 {
		t.Fatalf("sha256 hex 应 64 字符，实际 %d", len(fp))
	}

	caBlock, _ := pem.Decode(caCertPEM)
	// 匹配（含冒号大写格式也应归一化通过）
	if err := VerifyChainPinnedCA([][]byte{caBlock.Bytes}, fp); err != nil {
		t.Fatalf("pin 应匹配: %v", err)
	}
	withColons := ""
	for i := 0; i < len(fp); i += 2 {
		if i > 0 {
			withColons += ":"
		}
		withColons += fp[i : i+2]
	}
	if err := VerifyChainPinnedCA([][]byte{caBlock.Bytes}, withColons); err != nil {
		t.Fatalf("冒号格式 pin 应匹配: %v", err)
	}

	// 不匹配
	if err := VerifyChainPinnedCA([][]byte{caBlock.Bytes}, "deadbeef"); err == nil {
		t.Fatal("错误指纹应拒绝")
	}
	if err := VerifyChainPinnedCA(nil, fp); err == nil {
		t.Fatal("空链应拒绝")
	}
}
