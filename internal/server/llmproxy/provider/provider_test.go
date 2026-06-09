package provider

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRegistry_RegisterLookup(t *testing.T) {
	t.Parallel()
	r := NewRegistry()
	p := NewOpenAI(OpenAIConfig{
		Name:     "openai-test",
		BaseURL:  "http://example.com",
		Models:   []string{"gpt-4o-mini"},
		Provider: "openai",
	})
	if err := r.Register(p); err != nil {
		t.Fatalf("register: %v", err)
	}
	got, ok := r.Get("openai-test")
	if !ok {
		t.Fatal("expected to find openai-test")
	}
	if got.Type() != "openai" {
		t.Errorf("expected openai type, got %s", got.Type())
	}
}

func TestRegistry_RejectNil(t *testing.T) {
	t.Parallel()
	r := NewRegistry()
	if err := r.Register(nil); err == nil {
		t.Fatal("expected error for nil provider")
	}
}

func TestRegistry_RejectDuplicate(t *testing.T) {
	t.Parallel()
	r := NewRegistry()
	p := NewOpenAI(OpenAIConfig{Name: "p1", BaseURL: "http://x", Models: []string{"m"}})
	_ = r.Register(p)
	if err := r.Register(p); err == nil {
		t.Fatal("expected duplicate error")
	}
}

func TestRegistry_Names(t *testing.T) {
	t.Parallel()
	r := NewRegistry()
	_ = r.Register(NewOpenAI(OpenAIConfig{Name: "p1", BaseURL: "http://x", Models: []string{"m"}}))
	_ = r.Register(NewOpenAI(OpenAIConfig{Name: "p2", BaseURL: "http://y", Models: []string{"m"}}))
	if len(r.Names()) != 2 {
		t.Fatalf("expected 2 names, got %d", len(r.Names()))
	}
}

func TestOpenAI_Complete_MockServer(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/chat/completions" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer fake-key" {
			t.Errorf("missing auth header")
		}
		resp := map[string]any{
			"model": "gpt-4o-mini",
			"choices": []map[string]any{
				{
					"message":       map[string]string{"content": "hello"},
					"finish_reason": "stop",
				},
			},
			"usage": map[string]int{
				"prompt_tokens":     10,
				"completion_tokens": 5,
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	p := NewOpenAI(OpenAIConfig{
		Name:    "test",
		BaseURL: srv.URL,
		APIKey:  "fake-key",
		Models:  []string{"gpt-4o-mini"},
	})
	resp, err := p.Complete(context.Background(), CompletionRequest{
		Model:    "gpt-4o-mini",
		Messages: []Message{{Role: "user", Content: "hi"}},
	})
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	if resp.Content != "hello" {
		t.Errorf("expected 'hello', got %s", resp.Content)
	}
	if resp.TokensIn != 10 || resp.TokensOut != 5 {
		t.Errorf("expected tokens 10/5, got %d/%d", resp.TokensIn, resp.TokensOut)
	}
}

func TestOpenAI_Complete_ModelNotSupported(t *testing.T) {
	t.Parallel()
	p := NewOpenAI(OpenAIConfig{
		Name:    "test",
		BaseURL: "http://x",
		Models:  []string{"gpt-4o-mini"},
	})
	_, err := p.Complete(context.Background(), CompletionRequest{
		Model:    "gpt-9999",
		Messages: []Message{{Role: "user", Content: "hi"}},
	})
	if err == nil {
		t.Fatal("expected error for unsupported model")
	}
}

func TestOpenAI_HealthCheck_OK(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	p := NewOpenAI(OpenAIConfig{Name: "x", BaseURL: srv.URL, APIKey: "k", Models: []string{"m"}})
	if err := p.HealthCheck(context.Background()); err != nil {
		t.Fatalf("healthcheck: %v", err)
	}
}
