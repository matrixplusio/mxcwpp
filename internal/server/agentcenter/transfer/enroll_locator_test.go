package transfer

import (
	"context"
	"net"
	"strings"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
	"google.golang.org/grpc/peer"

	grpcProto "github.com/matrixplusio/mxcwpp/api/proto/grpc"
)

// 被拒的 agent 要能定位到机器：带上自报主机名、内网 IP 与对端地址，且都有长度上限。
func TestRejectLocatorFields(t *testing.T) {
	ctx := peer.NewContext(context.Background(), &peer.Peer{Addr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 40001}})
	first := &grpcProto.PackagedData{
		Hostname:     strings.Repeat("h", 200),
		IntranetIpv4: []string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5", strings.Repeat("9", 100)},
	}
	core, logs := observer.New(zapcore.InfoLevel)
	zap.New(core).Info("x", rejectLocator(ctx, first)...)

	f := logs.All()[0].ContextMap()
	if h := f["reported_hostname"].(string); len(h) != 64 {
		t.Fatalf("主机名应截到 64 字节，得 %d", len(h))
	}
	ips := f["reported_ipv4"].([]any)
	if len(ips) != 4 || ips[0] != "10.0.0.1" {
		t.Fatalf("IP 列表应只留前 4 个，得 %v", ips)
	}
	if f["remote_addr"] != "127.0.0.1:40001" {
		t.Fatalf("remote_addr = %v", f["remote_addr"])
	}

	// 首包为空、上下文里没有对端也不能出错。
	if n := len(rejectLocator(context.Background(), nil)); n != 2 {
		t.Fatalf("无对端时应只有两个字段，得 %d", n)
	}
}
