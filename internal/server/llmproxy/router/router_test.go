package router

import (
	"context"
	"errors"
	"testing"

	"go.uber.org/zap"

	"github.com/imkerbos/mxsec-platform/internal/server/llmproxy/provider"
)

type stubProvider struct {
	name   string
	resp   string
	failN  int
	called int
}

func (s *stubProvider) Name() string              { return s.name }
func (s *stubProvider) Type() string              { return "stub" }
func (s *stubProvider) SupportedModels() []string { return []string{"any"} }

func (s *stubProvider) Complete(_ context.Context, _ provider.CompletionRequest) (*provider.CompletionResponse, error) {
	s.called++
	if s.called <= s.failN {
		return nil, errors.New("stub failure")
	}
	return &provider.CompletionResponse{Content: s.resp, Provider: s.name}, nil
}

func (s *stubProvider) Embed(_ context.Context, _ string, _ string) ([]float32, error) {
	return nil, provider.ErrEmbedNotSupported
}

func (s *stubProvider) HealthCheck(_ context.Context) error { return nil }

func TestRouter_PrimarySucceeds(t *testing.T) {
	t.Parallel()
	reg := provider.NewRegistry()
	_ = reg.Register(&stubProvider{name: "p1", resp: "ok"})
	r := NewRouter(reg, []SceneRoute{{Scene: SceneAlertExplain, Providers: []string{"p1"}}}, Config{AllowDataEgress: true}, zap.NewNop())
	resp, err := r.Complete(context.Background(), SceneAlertExplain, provider.CompletionRequest{Model: "any"})
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	if resp.Content != "ok" {
		t.Errorf("expected ok, got %s", resp.Content)
	}
}

func TestRouter_FallbackToBackup(t *testing.T) {
	t.Parallel()
	reg := provider.NewRegistry()
	_ = reg.Register(&stubProvider{name: "p1", failN: 100, resp: "primary"})
	_ = reg.Register(&stubProvider{name: "p2", resp: "backup"})
	r := NewRouter(reg, []SceneRoute{{Scene: SceneAlertExplain, Providers: []string{"p1", "p2"}}}, Config{FailureThreshold: 10, AllowDataEgress: true}, zap.NewNop())
	resp, err := r.Complete(context.Background(), SceneAlertExplain, provider.CompletionRequest{Model: "any"})
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	if resp.Content != "backup" {
		t.Errorf("expected backup, got %s", resp.Content)
	}
}

func TestRouter_AllFail(t *testing.T) {
	t.Parallel()
	reg := provider.NewRegistry()
	_ = reg.Register(&stubProvider{name: "p1", failN: 100})
	r := NewRouter(reg, []SceneRoute{{Scene: SceneAlertExplain, Providers: []string{"p1"}}}, Config{FailureThreshold: 10, AllowDataEgress: true}, zap.NewNop())
	_, err := r.Complete(context.Background(), SceneAlertExplain, provider.CompletionRequest{Model: "any"})
	if !errors.Is(err, ErrNoAvailableProvider) {
		t.Fatalf("expected ErrNoAvailableProvider, got %v", err)
	}
}

func TestRouter_BlacklistAfterFailures(t *testing.T) {
	t.Parallel()
	reg := provider.NewRegistry()
	p1 := &stubProvider{name: "p1", failN: 100}
	_ = reg.Register(p1)
	_ = reg.Register(&stubProvider{name: "p2", resp: "backup"})
	r := NewRouter(reg, []SceneRoute{{Scene: SceneAlertExplain, Providers: []string{"p1", "p2"}}}, Config{FailureThreshold: 2, AllowDataEgress: true}, zap.NewNop())

	// 触发 3 次让 p1 进黑名单
	for i := 0; i < 3; i++ {
		_, _ = r.Complete(context.Background(), SceneAlertExplain, provider.CompletionRequest{Model: "any"})
	}
	// 黑名单期间 p1 不会被调
	hits := p1.called
	_, _ = r.Complete(context.Background(), SceneAlertExplain, provider.CompletionRequest{Model: "any"})
	if p1.called != hits {
		t.Fatalf("blacklisted provider should not be called, calls before=%d after=%d", hits, p1.called)
	}
}

func TestRouter_SceneNotConfigured(t *testing.T) {
	t.Parallel()
	r := NewRouter(provider.NewRegistry(), nil, Config{}, zap.NewNop())
	_, err := r.Complete(context.Background(), SceneAlertExplain, provider.CompletionRequest{Model: "x"})
	if err == nil {
		t.Fatal("expected error for unconfigured scene")
	}
}
