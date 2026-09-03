package engine

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.uber.org/zap"
)

func TestNewHTTPHandler_Health(t *testing.T) {
	t.Parallel()
	h := NewHTTPHandler(zap.NewNop())

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/health", nil)
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), `"service":"engine"`) {
		t.Fatalf("body missing service identifier: %s", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), Version) {
		t.Fatalf("body missing version: %s", w.Body.String())
	}
}

func TestNewHTTPHandler_Metrics(t *testing.T) {
	t.Parallel()
	h := NewHTTPHandler(zap.NewNop())

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/metrics", nil)
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	// /metrics 现暴露真实 Prometheus 默认 registry（含 Go runtime 指标），非占位桩。
	if !strings.Contains(w.Body.String(), "# HELP") {
		t.Fatalf("body not prometheus exposition format")
	}
}

func TestNewHTTPHandler_NotImplemented(t *testing.T) {
	t.Parallel()
	h := NewHTTPHandler(zap.NewNop())

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/rules", nil)
	h.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "not implemented") {
		t.Fatalf("body missing not-implemented hint: %s", w.Body.String())
	}
}
