package sdclient

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"go.uber.org/zap"
)

func generateTestCert(t *testing.T, dir string) (caPath, certPath, keyPath string) {
	t.Helper()

	// CA 自签
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "mxcwpp-test-ca"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)

	// 客户端证书 (由 CA 签)
	clientKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	clientTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "mxcwpp-ac-client"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientDER, _ := x509.CreateCertificate(rand.Reader, clientTmpl, caTmpl, &clientKey.PublicKey, caKey)

	caPath = filepath.Join(dir, "ca.pem")
	certPath = filepath.Join(dir, "client.pem")
	keyPath = filepath.Join(dir, "client.key")

	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0644); err != nil {
		t.Fatalf("write ca: %v", err)
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientDER}), 0644); err != nil {
		t.Fatalf("write client cert: %v", err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(clientKey)
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		t.Fatalf("write client key: %v", err)
	}
	return
}

func TestBuildHTTPClient_DisabledReturnsPlain(t *testing.T) {
	t.Parallel()
	c, err := buildHTTPClient(MTLSConfig{}, 5*time.Second)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if c == nil {
		t.Fatalf("nil client")
	}
	if c.Transport != nil {
		t.Fatalf("plain client should not have custom transport, got %T", c.Transport)
	}
}

func TestBuildHTTPClient_EnabledRequiresCA(t *testing.T) {
	t.Parallel()
	_, err := buildHTTPClient(MTLSConfig{Enabled: true}, time.Second)
	if err == nil {
		t.Fatalf("expected error for missing ca")
	}
}

func TestBuildHTTPClient_EnabledWithCert(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	caPath, certPath, keyPath := generateTestCert(t, dir)
	c, err := buildHTTPClient(MTLSConfig{
		Enabled:    true,
		CACertPath: caPath,
		ClientCert: certPath,
		ClientKey:  keyPath,
	}, 5*time.Second)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if c.Transport == nil {
		t.Fatalf("expected custom transport with TLS")
	}
}

func TestBuildHTTPClient_InvalidCert(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	bogus := filepath.Join(dir, "bogus.pem")
	_ = os.WriteFile(bogus, []byte("not a cert"), 0644)
	_, err := buildHTTPClient(MTLSConfig{
		Enabled:    true,
		CACertPath: bogus,
		ClientCert: bogus,
		ClientKey:  bogus,
	}, time.Second)
	if err == nil {
		t.Fatalf("expected error for invalid cert")
	}
}

func TestNewClientWithTLS_DisabledKeepsV1Behavior(t *testing.T) {
	t.Parallel()
	// 启动一个简单 HTTP 测试服务器
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Internal-Secret") != "secret-x" {
			t.Errorf("missing or wrong X-Internal-Secret header")
		}
		hits++
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c, err := NewClientWithTLS(srv.URL, "ac-1", "ac:6751", "ac:7071", "secret-x",
		MTLSConfig{}, // mtls 禁用
		func() int { return 0 }, zap.NewNop())
	if err != nil {
		t.Fatalf("NewClientWithTLS: %v", err)
	}
	if err := c.register(); err != nil {
		t.Fatalf("register: %v", err)
	}
	if hits != 1 {
		t.Fatalf("expected 1 hit, got %d", hits)
	}
}
