package certissue

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
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

func TestValidateFingerprint(t *testing.T) {
	caCertPEM, _ := newTestCA(t)
	fp, err := CAFingerprint(caCertPEM)
	if err != nil {
		t.Fatalf("CAFingerprint: %v", err)
	}
	if len(fp) != 64 {
		t.Fatalf("sha256 hex 应 64 字符，实际 %d", len(fp))
	}
	if err := ValidateFingerprint(fp); err != nil {
		t.Fatalf("合法指纹应通过: %v", err)
	}
	// 冒号 / 大写格式归一化后仍合法
	withColons := ""
	for i := 0; i < len(fp); i += 2 {
		if i > 0 {
			withColons += ":"
		}
		withColons += strings.ToUpper(fp[i : i+2])
	}
	if err := ValidateFingerprint(withColons); err != nil {
		t.Fatalf("冒号大写格式应归一化通过: %v", err)
	}
	for _, bad := range []string{"", "deadbeef", fp[:63], fp + "ab", "__PLACEHOLDER__"} {
		if err := ValidateFingerprint(bad); err == nil {
			t.Fatalf("非法指纹 %q 应被拒绝", bad)
		}
	}
}

// TestVerifyChainPinnedCA_FullVerification 覆盖完整 pinned-root 校验的正/负路径：
//   - 正确链（leaf+CA）+ 正确 SAN → 通过；
//   - 空链 / 非法指纹 → 拒绝；
//   - 错误 SAN → 拒绝；
//   - “把正确 CA 作为无关附加证书塞进伪造链”（evil-leaf + 正确 CA）→ 拒绝。
func TestVerifyChainPinnedCA_FullVerification(t *testing.T) {
	caPEM, _, caCert, caKey := buildCA(t)
	fp, _ := CAFingerprint(caPEM)
	leaf := serverLeaf(t, caCert, caKey) // Certificate = [leafDER, caDER]，SAN=ac.local

	// 正确链 + 正确 SAN
	if err := VerifyChainPinnedCA(leaf.Certificate, fp, "ac.local"); err != nil {
		t.Fatalf("正确链应通过: %v", err)
	}
	// 空链
	if err := VerifyChainPinnedCA(nil, fp, "ac.local"); err == nil {
		t.Fatal("空链应拒绝")
	}
	// 非法指纹
	if err := VerifyChainPinnedCA(leaf.Certificate, "deadbeef", "ac.local"); err == nil {
		t.Fatal("非法指纹应拒绝")
	}
	// 错误 SAN
	if err := VerifyChainPinnedCA(leaf.Certificate, fp, "evil.example"); err == nil {
		t.Fatal("SAN 不符应拒绝")
	}
	// 攻击：evil-leaf 由 evilCA 签发，但把“正确 CA”作为无关附加证书塞进链尾。
	// 指纹匹配到正确 CA，但 evil-leaf 无法由它验签 → 必须拒绝。
	_, _, evilCA, evilKey := buildCA(t)
	evilLeaf := serverLeaf(t, evilCA, evilKey)
	forged := [][]byte{evilLeaf.Certificate[0], caCert.Raw}
	if err := VerifyChainPinnedCA(forged, fp, "ac.local"); err == nil {
		t.Fatal("把正确 CA 作为无关附加证书的伪造链应被拒绝")
	}
}
