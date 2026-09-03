package llmproxy

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
	h.ServeHTTP(w, httptest.NewRequest("GET", "/health", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), `"service":"llmproxy"`) {
		t.Fatalf("body missing service identifier: %s", w.Body.String())
	}
}

func TestNewHTTPHandler_NotImplemented(t *testing.T) {
	t.Parallel()
	h := NewHTTPHandler(zap.NewNop())
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("POST", "/complete", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}
