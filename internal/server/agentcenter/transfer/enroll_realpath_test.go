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
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	grpcProto "github.com/matrixplusio/mxcwpp/api/proto/grpc"
	"github.com/matrixplusio/mxcwpp/internal/common/certissue"
	"github.com/matrixplusio/mxcwpp/internal/deploy/cluster"
	acserver "github.com/matrixplusio/mxcwpp/internal/server/agentcenter/server"
	"github.com/matrixplusio/mxcwpp/internal/server/config"
)

// realEnrollEnv 起一个注册了**真实** transfer.Service 的 gRPC over TLS 服务端，
// 用于验证生产 Transfer 代码路径（enrollOnly / 身份绑定）的端到端行为。
type realEnrollEnv struct {
	svc    *Service
	addr   string
	caCert []byte
	caKey  []byte
	caFP   string
	stop   func()
}

func newRealEnrollEnv(t *testing.T, mtls config.MTLSConfig) *realEnrollEnv {
	t.Helper()
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
	mtls.CACert = write("ca.crt", bundle.CACert)
	mtls.CAKey = write("ca.key", bundle.CAKey)
	mtls.ServerCert = write("server.crt", bundle.ServerCert)
	mtls.ServerKey = write("server.key", bundle.ServerKey)

	cfg := &config.Config{}
	cfg.MTLS = mtls

	gs, err := acserver.CreateGRPCServer(cfg, zap.NewNop())
	if err != nil {
		t.Fatalf("CreateGRPCServer: %v", err)
	}
	// 真实 Service（不注入 DB/Kafka）：enrollOnly 与身份绑定拒绝路径均在注册/DB 之前返回。
	svc := &Service{cfg: cfg, logger: zap.NewNop(), connections: make(map[string]*Connection)}
	grpcProto.RegisterTransferServer(gs, svc)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = gs.Serve(ln) }()

	fp, _ := certissue.CAFingerprint(bundle.CACert)
	return &realEnrollEnv{
		svc:    svc,
		addr:   ln.Addr().String(),
		caCert: bundle.CACert,
		caKey:  bundle.CAKey,
		caFP:   fp,
		stop:   func() { gs.Stop() },
	}
}

func (e *realEnrollEnv) pinTLS() *tls.Config {
	return &tls.Config{
		ServerName:         "127.0.0.1",
		InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			raw := make([][]byte, 0, len(cs.PeerCertificates))
			for _, c := range cs.PeerCertificates {
				raw = append(raw, c.Raw)
			}
			return certissue.VerifyChainPinnedCA(raw, e.caFP, "127.0.0.1")
		},
	}
}

func (e *realEnrollEnv) mtlsWithCert(t *testing.T, certPEM, keyPEM []byte) *tls.Config {
	t.Helper()
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("加载客户端证书: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(e.caCert)
	return &tls.Config{ServerName: "127.0.0.1", RootCAs: pool, Certificates: []tls.Certificate{pair}}
}

// TestTransferEnrollOnly_NoBusinessPlane 无证书 + 正确令牌：真实 Transfer 只下发单机证书、
// 结束流，且**绝不注册在线连接**（connections 为空）。
func TestTransferEnrollOnly_NoBusinessPlane(t *testing.T) {
	env := newRealEnrollEnv(t, config.MTLSConfig{EnrollToken: "enroll-token-strong-value-32bytes!", PerAgentCert: true, EnforceAgentID: true})
	defer env.stop()

	conn, err := grpc.NewClient(env.addr, grpc.WithTransportCredentials(credentials.NewTLS(env.pinTLS())))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ctx = metadata.AppendToOutgoingContext(ctx, certissue.EnrollTokenMetaKey, "enroll-token-strong-value-32bytes!")
	stream, err := grpcProto.NewTransferClient(conn).Transfer(ctx)
	if err != nil {
		t.Fatalf("stream: %v", err)
	}
	if err := stream.Send(&grpcProto.PackagedData{AgentId: "host-real-1"}); err != nil {
		t.Fatalf("send: %v", err)
	}
	cmd, err := stream.Recv()
	if err != nil {
		t.Fatalf("recv 应收到单机证书: %v", err)
	}
	if cmd.CertificateBundle == nil {
		t.Fatal("未下发单机证书")
	}
	block, _ := pem.Decode(cmd.CertificateBundle.ClientCert)
	issued, _ := x509.ParseCertificate(block.Bytes)
	if issued.Subject.CommonName != "host-real-1" {
		t.Fatalf("单机证书 CN=%q，应为 host-real-1", issued.Subject.CommonName)
	}
	// 流应随后结束（EOF），且连接从未进入连接表。
	_, _ = stream.Recv()
	env.svc.connMu.RLock()
	n := len(env.svc.connections)
	env.svc.connMu.RUnlock()
	if n != 0 {
		t.Fatalf("enroll 首连不得注册在线连接，connections=%d", n)
	}
}

// TestTransferEnrollOnly_BadToken 无证书 + 空/错误令牌：拒绝，不下发证书、不注册。
func TestTransferEnrollOnly_BadToken(t *testing.T) {
	env := newRealEnrollEnv(t, config.MTLSConfig{EnrollToken: "enroll-token-strong-value-32bytes!", PerAgentCert: true, EnforceAgentID: true})
	defer env.stop()

	try := func(token string, useToken bool) error {
		conn, err := grpc.NewClient(env.addr, grpc.WithTransportCredentials(credentials.NewTLS(env.pinTLS())))
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer conn.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if useToken {
			ctx = metadata.AppendToOutgoingContext(ctx, certissue.EnrollTokenMetaKey, token)
		}
		stream, err := grpcProto.NewTransferClient(conn).Transfer(ctx)
		if err != nil {
			return err
		}
		if err := stream.Send(&grpcProto.PackagedData{AgentId: "host-bad"}); err != nil {
			return err
		}
		_, rerr := stream.Recv()
		return rerr
	}

	for _, tc := range []struct {
		name  string
		token string
		use   bool
	}{
		{"no token", "", false},
		{"empty token", "", true},
		{"wrong token", "wrong-token", true},
	} {
		err := try(tc.token, tc.use)
		if status.Code(err) != codes.Unauthenticated {
			t.Fatalf("%s: 期望 Unauthenticated，得 %v", tc.name, err)
		}
	}
	env.svc.connMu.RLock()
	n := len(env.svc.connections)
	env.svc.connMu.RUnlock()
	if n != 0 {
		t.Fatalf("拒绝的 enroll 不得注册连接，connections=%d", n)
	}
}

// TestTransfer_ForgedAgentID 合法客户端证书 + 伪造 AgentID（CN != AgentID），
// EnforceAgentID 下拒绝，且发生在注册/DB 之前。
func TestTransfer_ForgedAgentID(t *testing.T) {
	env := newRealEnrollEnv(t, config.MTLSConfig{EnrollToken: "enroll-token-strong-value-32bytes!", PerAgentCert: true, EnforceAgentID: true})
	defer env.stop()

	// 给 attacker 签一张合法单机证书（CN=attacker），却冒充上报 victim。
	certPEM, keyPEM, err := certissue.SignAgentCert(env.caCert, env.caKey, "attacker", time.Hour)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	conn, err := grpc.NewClient(env.addr, grpc.WithTransportCredentials(credentials.NewTLS(env.mtlsWithCert(t, certPEM, keyPEM))))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stream, err := grpcProto.NewTransferClient(conn).Transfer(ctx)
	if err != nil {
		t.Fatalf("stream: %v", err)
	}
	if err := stream.Send(&grpcProto.PackagedData{AgentId: "victim"}); err != nil {
		t.Fatalf("send: %v", err)
	}
	_, rerr := stream.Recv()
	if status.Code(rerr) != codes.PermissionDenied {
		t.Fatalf("伪造 AgentID 期望 PermissionDenied，得 %v", rerr)
	}
	env.svc.connMu.RLock()
	n := len(env.svc.connections)
	env.svc.connMu.RUnlock()
	if n != 0 {
		t.Fatalf("伪造 AgentID 不得注册连接，connections=%d", n)
	}
}
