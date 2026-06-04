package advisory

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestDoWithBackoff_2xxPassThrough(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	resp, err := DoWithBackoff(context.Background(), srv.Client(), req, 3)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Errorf("expected 1 hit, got %d", got)
	}
	if ua := resp.Request.Header.Get("User-Agent"); ua == "" {
		t.Error("missing UA")
	}
}

func TestDoWithBackoff_404NotRetried(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	resp, err := DoWithBackoff(context.Background(), srv.Client(), req, 3)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Errorf("404 should NOT retry, got %d hits", got)
	}
}

func TestDoWithBackoff_429RetriedThenSucceeds(t *testing.T) {
	// 用极短退避避免单测拖慢
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&hits, 1)
		if n == 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// 用 ctx timeout 控总等待避免吃 backoff 全 60s+
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
	resp, err := DoWithBackoff(ctx, srv.Client(), req, 3)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if got := atomic.LoadInt32(&hits); got < 2 {
		t.Errorf("expected at least 2 hits (1 fail + 1 retry), got %d", got)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("final code: %d", resp.StatusCode)
	}
}

func TestDoWithBackoff_503Retried(t *testing.T) {
	if !shouldRetryStatus(http.StatusServiceUnavailable) {
		t.Error("503 should be retried")
	}
	if !shouldRetryStatus(http.StatusBadGateway) {
		t.Error("502 should be retried")
	}
	if !shouldRetryStatus(http.StatusForbidden) {
		t.Error("403 should be retried (CDN throttle)")
	}
	if shouldRetryStatus(http.StatusNotFound) {
		t.Error("404 should NOT be retried")
	}
	if shouldRetryStatus(http.StatusBadRequest) {
		t.Error("400 should NOT be retried")
	}
}

func TestDoWithBackoff_CtxCancelStops(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
	_, err := DoWithBackoff(ctx, srv.Client(), req, 5)
	if err == nil {
		t.Fatal("expected ctx error")
	}
}
