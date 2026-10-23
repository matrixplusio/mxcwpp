package transfer

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	grpcProto "github.com/matrixplusio/mxcwpp/api/proto/grpc"
	"github.com/matrixplusio/mxcwpp/internal/server/common/internalauth"
	"github.com/matrixplusio/mxcwpp/internal/server/config"
)

func newRouteService(t *testing.T, peerAddr string, peerFresh bool) *Service {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: gormlogger.Default.LogMode(gormlogger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	if sqlDB, e := db.DB(); e == nil {
		sqlDB.SetMaxOpenConns(1)
	}
	for _, ddl := range []string{
		`CREATE TABLE hosts (id INTEGER PRIMARY KEY, host_id TEXT, ac_instance TEXT)`,
		`CREATE TABLE ac_instances (tenant_id TEXT DEFAULT 't-default', instance_id TEXT PRIMARY KEY, http_addr TEXT, updated_at DATETIME)`,
	} {
		if err := db.Exec(ddl).Error; err != nil {
			t.Fatal(err)
		}
	}
	db.Exec(`INSERT INTO hosts (host_id, ac_instance) VALUES ('remote-agent', 'ac-b'), ('lost-agent', 'ac-a')`)
	ts := time.Now()
	if !peerFresh {
		ts = ts.Add(-time.Hour)
	}
	db.Exec(`INSERT INTO ac_instances (instance_id, http_addr, updated_at) VALUES ('ac-b', ?, ?)`, peerAddr, ts)

	cfg := &config.Config{}
	cfg.Server.InstanceID = "ac-a"
	cfg.Server.InternalSecret = "internal-only"
	cfg.Server.ACAdminSecret = "s3cret" // 转发必须带 ac_admin_secret 而不是 internal_secret
	return &Service{db: db, cfg: cfg, logger: zap.NewNop(), connections: map[string]*Connection{},
		forwardClient: &http.Client{Timeout: time.Second}}
}

// TestRouteCommand_ForwardsToOwningInstance 本机没有连接时转给持有连接的实例，带内部认证与完整命令。
func TestRouteCommand_ForwardsToOwningInstance(t *testing.T) {
	var got ForwardRequest
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/command/raw" || r.Header.Get(internalauth.HeaderName) != "s3cret" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(http.StatusOK)
	}))
	defer peer.Close()
	s := newRouteService(t, strings.TrimPrefix(peer.URL, "http://"), true)

	if err := s.RouteCommand("remote-agent", &grpcProto.Command{AgentRestart: true}); err != nil {
		t.Fatalf("应转发成功: %v", err)
	}
	cmd, err := DecodeForward(got)
	if err != nil || got.AgentID != "remote-agent" || !cmd.AgentRestart {
		t.Fatalf("对端收到的命令不完整: agent=%q restart=%v err=%v", got.AgentID, cmd.GetAgentRestart(), err)
	}
}

// TestRouteCommand_NoForwardWhenOwnedHereOrPeerStale 归属本机（已断开）或对端地址过期时不转发，返回未连接。
func TestRouteCommand_NoForwardWhenOwnedHereOrPeerStale(t *testing.T) {
	called := false
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))
	defer peer.Close()

	s := newRouteService(t, strings.TrimPrefix(peer.URL, "http://"), false)
	if err := s.RouteCommand("lost-agent", &grpcProto.Command{}); err == nil {
		t.Fatal("归属本机但已断开应返回错误")
	}
	if err := s.RouteCommand("remote-agent", &grpcProto.Command{}); !errors.Is(err, ErrAgentNotConnected) {
		t.Fatalf("对端地址过期应返回未连接，实际 %v", err)
	}
	if called {
		t.Fatal("不应发起转发")
	}
}

// TestRouteCommand_PeerSaysNotConnected 对端也没有这条连接（503）按未连接处理。
func TestRouteCommand_PeerSaysNotConnected(t *testing.T) {
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer peer.Close()
	s := newRouteService(t, strings.TrimPrefix(peer.URL, "http://"), true)
	if err := s.RouteCommand("remote-agent", &grpcProto.Command{}); !errors.Is(err, ErrAgentNotConnected) {
		t.Fatalf("应返回未连接，实际 %v", err)
	}
}

// TestRouteCommand_NoAdminSecretFailsBeforeCalling 没配 ac_admin_secret 时不去调对端：
// 带空密钥只会换来一个 401，日志里看不出是本机没配。
func TestRouteCommand_NoAdminSecretFailsBeforeCalling(t *testing.T) {
	called := false
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer peer.Close()
	s := newRouteService(t, strings.TrimPrefix(peer.URL, "http://"), true)
	s.cfg.Server.ACAdminSecret = ""

	err := s.RouteCommand("remote-agent", &grpcProto.Command{AgentRestart: true})
	if err == nil || !strings.Contains(err.Error(), "ac_admin_secret") {
		t.Fatalf("应明确报未配置 ac_admin_secret，实际 %v", err)
	}
	if called {
		t.Fatal("未配置密钥时不应向对端发请求")
	}
}
