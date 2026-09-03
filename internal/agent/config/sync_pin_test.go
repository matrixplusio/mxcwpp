package config

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/matrixplusio/mxcwpp/api/proto/grpc"
	"github.com/matrixplusio/mxcwpp/internal/common/certissue"
)

func makeCAPEM(t *testing.T, cn string) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// 下发证书包的 CA 与 pin 不符时，必须拒绝且不落盘（防中间人换 CA 永久劫持）。
func TestSyncCertificatesRejectsCAFingerprintMismatch(t *testing.T) {
	caA := makeCAPEM(t, "ca-A")
	caB := makeCAPEM(t, "ca-B")
	fpA, err := certissue.CAFingerprint(caA)
	if err != nil {
		t.Fatalf("fingerprint: %v", err)
	}

	certDir := t.TempDir()
	c := &Config{}
	c.Local.TLS.CAFingerprint = fpA // pin 住 CA-A

	bundle := &grpc.CertificateBundle{
		CaCert:     caB, // 攻击者换成 CA-B
		ClientCert: []byte("x"),
		ClientKey:  []byte("y"),
	}
	err = c.SyncCertificatesFromServer(bundle, certDir)
	if err == nil {
		t.Fatal("CA 指纹不符应报错")
	}
	if !strings.Contains(err.Error(), "指纹") {
		t.Fatalf("错误应提示指纹不符，得: %v", err)
	}
	// 不应写入任何证书文件
	if _, statErr := os.Stat(filepath.Join(certDir, "ca.crt")); !os.IsNotExist(statErr) {
		t.Fatal("拒绝时不应落盘 ca.crt")
	}
}
