package sd

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"go.uber.org/zap"

	grpcProto "github.com/matrixplusio/mxcwpp/api/proto/grpc"
	"github.com/matrixplusio/mxcwpp/internal/server/common/internalauth"
)

// captureAC 是一个记录收到的内部认证头的假 AC HTTP 端。
type captureAC struct {
	mu     sync.Mutex
	secret string
	paths  []string
}

func (c *captureAC) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c.mu.Lock()
		c.secret = r.Header.Get(internalauth.HeaderName)
		c.paths = append(c.paths, r.URL.Path)
		c.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}
}

func newDispatcherWithFakeAC(t *testing.T, secret string) (*ACDispatcher, *captureAC) {
	t.Helper()
	cap := &captureAC{}
	srv := httptest.NewServer(cap.handler())
	t.Cleanup(srv.Close)
	reg := NewRegistry(zap.NewNop())
	reg.Register("ac1", "grpc:6751", strings.TrimPrefix(srv.URL, "http://"))
	// redis 传 nil → 走广播到健康实例路径。
	d := NewACDispatcher(reg, nil, zap.NewNop(), secret)
	return d, cap
}

func TestSendCommand_CarriesInternalSecret(t *testing.T) {
	d, cap := newDispatcherWithFakeAC(t, "dispatch-secret-123456")
	cmd := &grpcProto.Command{Tasks: []*grpcProto.Task{{DataType: 1}}}
	if err := d.SendCommand("agent-1", cmd); err != nil {
		t.Fatalf("SendCommand: %v", err)
	}
	cap.mu.Lock()
	defer cap.mu.Unlock()
	if cap.secret != "dispatch-secret-123456" {
		t.Errorf("command missing internal secret header: got %q", cap.secret)
	}
}

func TestSendDependencyInstall_CarriesInternalSecret(t *testing.T) {
	d, cap := newDispatcherWithFakeAC(t, "dispatch-secret-123456")
	if err := d.SendDependencyInstall("agent-1", "curl", "install", "", "req-1", ""); err != nil {
		t.Fatalf("SendDependencyInstall: %v", err)
	}
	cap.mu.Lock()
	defer cap.mu.Unlock()
	if cap.secret != "dispatch-secret-123456" {
		t.Errorf("dependency install missing internal secret header: got %q", cap.secret)
	}
}
