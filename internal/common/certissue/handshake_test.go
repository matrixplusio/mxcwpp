package certissue

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"testing"
	"time"
)

// buildCA 生成 CA（cert PEM/key PEM + 解析对象）供握手测试。
func buildCA(t *testing.T) (certPEM, keyPEM []byte, caCert *x509.Certificate, caKey *rsa.PrivateKey) {
	t.Helper()
	caKey, _ = rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "hs-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &caKey.PublicKey, caKey)
	caCert, _ = x509.ParseCertificate(der)
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(caKey)})
	return
}

// serverLeaf 生成由 CA 签发的服务端证书。
func serverLeaf(t *testing.T, caCert *x509.Certificate, caKey *rsa.PrivateKey) tls.Certificate {
	t.Helper()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "hs-server"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"ac.local"},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	// 服务端 presented chain 含 leaf + CA（模拟 server.go 的附带 CA 行为），pin 才能看到 CA
	return tls.Certificate{Certificate: [][]byte{der, caCert.Raw}, PrivateKey: key}
}

// doHandshake 用 loopback TCP 跑一次 TLS 握手，返回客户端侧握手错误。
func doHandshake(t *testing.T, serverCfg, clientCfg *tls.Config) error {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		defer conn.Close()
		sc := tls.Server(conn, serverCfg)
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if sc.HandshakeContext(ctx) == nil {
			// 握手成功才回写一字节，供客户端确认连接真正可用（区分 TLS1.3 延后告警）。
			_, _ = sc.Write([]byte{1})
		}
	}()

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	cc := tls.Client(c, clientCfg)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := cc.HandshakeContext(ctx); err != nil {
		return err
	}
	// TLS 1.3 下服务端对客户端证书的拒绝以握手后告警形式到达，需读一次才暴露。
	_ = cc.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	if _, rerr := cc.Read(buf); rerr != nil {
		return rerr
	}
	return nil
}

// 场景：agent 首连用 CA 指纹 pin，能识破换了 CA 的伪造 AC（防中间人）。
func TestHandshakeCAPinning(t *testing.T) {
	caPEM, _, caCert, caKey := buildCA(t)
	fp, _ := CAFingerprint(caPEM)

	serverCfg := &tls.Config{Certificates: []tls.Certificate{serverLeaf(t, caCert, caKey)}}

	pinClient := func(wantFP string) *tls.Config {
		return &tls.Config{
			ServerName:         "ac.local",
			InsecureSkipVerify: true,
			VerifyConnection: func(cs tls.ConnectionState) error {
				raw := make([][]byte, 0, len(cs.PeerCertificates))
				for _, c := range cs.PeerCertificates {
					raw = append(raw, c.Raw)
				}
				return VerifyChainPinnedCA(raw, wantFP)
			},
		}
	}

	// 正确指纹 → 握手成功
	if err := doHandshake(t, serverCfg, pinClient(fp)); err != nil {
		t.Fatalf("正确 CA 指纹应握手成功: %v", err)
	}

	// 攻击者换了另一套 CA+server（冒充 AC）→ pin 不符，客户端拒绝
	_, _, evilCA, evilKey := buildCA(t)
	evilServer := &tls.Config{Certificates: []tls.Certificate{serverLeaf(t, evilCA, evilKey)}}
	if err := doHandshake(t, evilServer, pinClient(fp)); err == nil {
		t.Fatal("伪造 AC（CA 不符）应被 pin 拒绝")
	}
}

// 场景：AC 握手期吊销序列号，已吊销的单机证书无法连入。
func TestHandshakeRevocation(t *testing.T) {
	caPEM, caKeyPEM, caCert, caKey := buildCA(t)

	// 给两个 agent 各签一张单机证书
	goodCertPEM, goodKeyPEM, _ := SignAgentCert(caPEM, caKeyPEM, "agent-good", time.Hour)
	badCertPEM, badKeyPEM, _ := SignAgentCert(caPEM, caKeyPEM, "agent-bad", time.Hour)

	badSerial := func() string {
		b, _ := pem.Decode(badCertPEM)
		c, _ := x509.ParseCertificate(b.Bytes)
		return c.SerialNumber.String()
	}()

	caPool := x509.NewCertPool()
	caPool.AddCert(caCert)
	revoked := map[string]bool{badSerial: true}
	serverCfg := &tls.Config{
		Certificates: []tls.Certificate{serverLeaf(t, caCert, caKey)},
		ClientCAs:    caPool,
		ClientAuth:   tls.VerifyClientCertIfGiven,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			for _, raw := range rawCerts {
				c, err := x509.ParseCertificate(raw)
				if err != nil {
					continue
				}
				if c.SerialNumber != nil && revoked[c.SerialNumber.String()] {
					return fmt.Errorf("revoked: %s", c.SerialNumber.String())
				}
			}
			return nil
		},
	}

	clientWith := func(certPEM, keyPEM []byte) *tls.Config {
		cert, _ := tls.X509KeyPair(certPEM, keyPEM)
		return &tls.Config{ServerName: "ac.local", RootCAs: caPool, Certificates: []tls.Certificate{cert}}
	}

	// 未吊销 → 成功
	if err := doHandshake(t, serverCfg, clientWith(goodCertPEM, goodKeyPEM)); err != nil {
		t.Fatalf("未吊销证书应握手成功: %v", err)
	}
	// 已吊销 → 拒绝
	if err := doHandshake(t, serverCfg, clientWith(badCertPEM, badKeyPEM)); err == nil {
		t.Fatal("已吊销证书应被握手拒绝")
	}
}
