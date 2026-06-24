package transfer

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"

	grpcProto "github.com/matrixplusio/mxcwpp/api/proto/grpc"
	"github.com/matrixplusio/mxcwpp/internal/common/certissue"
	"github.com/matrixplusio/mxcwpp/internal/deploy/cluster"
	acserver "github.com/matrixplusio/mxcwpp/internal/server/agentcenter/server"
	"github.com/matrixplusio/mxcwpp/internal/server/config"
)

// enrollStub 用真实的 peerLeafCert / enrollTokenFromCtx / enrollTokenValid / certissue.SignAgentCert
// 复现 enroll 流程，验证生产代码在真实 gRPC over TLS 上的端到端行为（不依赖 DB/Kafka）。
type enrollStub struct {
	grpcProto.UnimplementedTransferServer
	svc       *Service
	caCertPEM []byte
	caKeyPEM  []byte
	seenCN    chan string // 带客户端证书连接时，server 侧读到的 CN
}

func (e *enrollStub) Transfer(stream grpc.BidiStreamingServer[grpcProto.PackagedData, grpcProto.Command]) error {
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	agentID := first.AgentId
	leaf, hasCert := peerLeafCert(stream.Context())
	if hasCert {
		select {
		case e.seenCN <- leaf.Subject.CommonName:
		default:
		}
	}
	alreadyEnrolled := hasCert && leaf.Subject.CommonName == agentID
	if e.svc.cfg.MTLS.PerAgentCert && !alreadyEnrolled {
		if !e.svc.enrollTokenValid(enrollTokenFromCtx(stream.Context())) {
			return context.Canceled
		}
		certPEM, keyPEM, serr := certissue.SignAgentCert(e.caCertPEM, e.caKeyPEM, agentID, time.Hour)
		if serr != nil {
			return serr
		}
		_ = stream.Send(&grpcProto.Command{CertificateBundle: &grpcProto.CertificateBundle{
			CaCert: e.caCertPEM, ClientCert: certPEM, ClientKey: keyPEM,
		}})
	}
	return nil
}

// 真实 gRPC + 生产 server.CreateGRPCServer：首连 pin CA + 令牌 enroll → 拿到 CN=AgentID 单机证书；带证书重连 → server 读到正确 CN。
func TestGRPCEnrollmentOverTLS(t *testing.T) {
	dir := t.TempDir()
	ccfg := &cluster.Config{}
	ccfg.Network.AdditionalSANs.IPs = []string{"127.0.0.1"}
	bundle, err := cluster.GenerateCertificates(ccfg)
	if err != nil {
		t.Fatalf("生成证书: %v", err)
	}
	write := func(name string, data []byte) string {
		p := filepath.Join(dir, name)
		if werr := os.WriteFile(p, data, 0o600); werr != nil {
			t.Fatalf("写 %s: %v", name, werr)
		}
		return p
	}
	caCertPath := write("ca.crt", bundle.CACert)
	caKeyPath := write("ca.key", bundle.CAKey)
	serverCrtPath := write("server.crt", bundle.ServerCert)
	serverKeyPath := write("server.key", bundle.ServerKey)

	cfg := &config.Config{}
	cfg.MTLS = config.MTLSConfig{
		CACert:       caCertPath,
		ServerCert:   serverCrtPath,
		ServerKey:    serverKeyPath,
		CAKey:        caKeyPath,
		EnrollToken:  "tok-secret",
		PerAgentCert: true,
	}

	gs, err := acserver.CreateGRPCServer(cfg, zap.NewNop())
	if err != nil {
		t.Fatalf("CreateGRPCServer: %v", err)
	}
	stub := &enrollStub{svc: &Service{cfg: cfg}, caCertPEM: bundle.CACert, caKeyPEM: bundle.CAKey, seenCN: make(chan string, 4)}
	grpcProto.RegisterTransferServer(gs, stub)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = gs.Serve(ln) }()
	defer gs.Stop()
	addr := ln.Addr().String()

	caFP, _ := certissue.CAFingerprint(bundle.CACert)

	// --- 首连：pin CA、无客户端证书、metadata 带 enroll 令牌 ---
	pinTLS := &tls.Config{
		ServerName:         "127.0.0.1",
		InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			raw := make([][]byte, 0, len(cs.PeerCertificates))
			for _, c := range cs.PeerCertificates {
				raw = append(raw, c.Raw)
			}
			return certissue.VerifyChainPinnedCA(raw, caFP)
		},
	}
	conn1, err := grpc.NewClient(addr, grpc.WithTransportCredentials(credentials.NewTLS(pinTLS)))
	if err != nil {
		t.Fatalf("dial1: %v", err)
	}
	defer conn1.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ctx = metadata.AppendToOutgoingContext(ctx, certissue.EnrollTokenMetaKey, "tok-secret")
	stream1, err := grpcProto.NewTransferClient(conn1).Transfer(ctx)
	if err != nil {
		t.Fatalf("stream1: %v", err)
	}
	if err := stream1.Send(&grpcProto.PackagedData{AgentId: "agent-e2e"}); err != nil {
		t.Fatalf("send1: %v", err)
	}
	cmd, err := stream1.Recv()
	if err != nil {
		t.Fatalf("recv1（应收到单机证书）: %v", err)
	}
	if cmd.CertificateBundle == nil {
		t.Fatal("未下发证书包")
	}

	// 校验下发的是 CN=agent-e2e 且由 CA 签发的单机证书
	block, _ := pem.Decode(cmd.CertificateBundle.ClientCert)
	issued, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("解析下发证书: %v", err)
	}
	if issued.Subject.CommonName != "agent-e2e" {
		t.Fatalf("单机证书 CN=%q，应为 agent-e2e", issued.Subject.CommonName)
	}
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(bundle.CACert)
	if _, err := issued.Verify(x509.VerifyOptions{Roots: caPool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatalf("下发证书应由 CA 签发: %v", err)
	}

	// --- 重连：用拿到的单机证书做完整 mTLS，server 应读到 CN=agent-e2e ---
	clientCert, err := tls.X509KeyPair(cmd.CertificateBundle.ClientCert, cmd.CertificateBundle.ClientKey)
	if err != nil {
		t.Fatalf("加载单机证书: %v", err)
	}
	mtlsCfg := &tls.Config{
		ServerName:   "127.0.0.1",
		RootCAs:      caPool,
		Certificates: []tls.Certificate{clientCert},
	}
	conn2, err := grpc.NewClient(addr, grpc.WithTransportCredentials(credentials.NewTLS(mtlsCfg)))
	if err != nil {
		t.Fatalf("dial2: %v", err)
	}
	defer conn2.Close()

	ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()
	stream2, err := grpcProto.NewTransferClient(conn2).Transfer(ctx2)
	if err != nil {
		t.Fatalf("stream2: %v", err)
	}
	if err := stream2.Send(&grpcProto.PackagedData{AgentId: "agent-e2e"}); err != nil {
		t.Fatalf("send2: %v", err)
	}
	_, _ = stream2.Recv() // 已 enroll，server 不再下发，正常返回 EOF

	select {
	case cn := <-stub.seenCN:
		if cn != "agent-e2e" {
			t.Fatalf("server 侧读到 CN=%q，应为 agent-e2e", cn)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("server 未读到客户端证书 CN（mTLS 重连失败）")
	}
}
