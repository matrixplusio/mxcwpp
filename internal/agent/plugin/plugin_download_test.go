package plugin

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"go.uber.org/zap"
)

// newTestManager 创建测试用的 Manager（只需 logger）
func newTestManager(t *testing.T) *Manager {
	t.Helper()
	return &Manager{
		logger: zap.NewNop(),
	}
}

// TestDownloadFromURL_Success 正常下载，文件内容完整
func TestDownloadFromURL_Success(t *testing.T) {
	payload := []byte("hello virus-database content for testing")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(payload)))
		w.Write(payload)
	}))
	defer srv.Close()

	m := newTestManager(t)
	dest := filepath.Join(t.TempDir(), "plugin.tar.gz")

	err := m.downloadFromURL(srv.URL, dest)
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}

	data, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("failed to read downloaded file: %v", err)
	}
	if string(data) != string(payload) {
		t.Fatalf("content mismatch: got %q, want %q", string(data), string(payload))
	}
}

// TestDownloadFromURL_RetryOnEOF 服务端前两次中途断连返回不完整响应，第三次成功
func TestDownloadFromURL_RetryOnEOF(t *testing.T) {
	payload := []byte("complete-payload-data-1234567890")
	var attempt atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := attempt.Add(1)
		if n <= 2 {
			// 声明较大的 Content-Length，但只发送部分数据后关闭连接
			w.Header().Set("Content-Length", "10000")
			w.Write([]byte("partial"))
			// httptest handler 返回后连接会被关闭，客户端收到 unexpected EOF
			return
		}
		// 第三次：正常响应
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(payload)))
		w.Write(payload)
	}))
	defer srv.Close()

	m := newTestManager(t)
	dest := filepath.Join(t.TempDir(), "plugin.tar.gz")

	err := m.downloadFromURL(srv.URL, dest)
	if err != nil {
		t.Fatalf("expected success after retry, got error: %v", err)
	}

	// 验证最终文件内容是完整的第三次响应
	data, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("failed to read file: %v", err)
	}
	if string(data) != string(payload) {
		t.Fatalf("content mismatch: got %q, want %q", string(data), string(payload))
	}

	// 验证总共请求了 3 次
	if got := attempt.Load(); got != 3 {
		t.Fatalf("expected 3 attempts, got %d", got)
	}
}

// TestDownloadFromURL_NoRetryOn404 服务端返回 404，不应重试
func TestDownloadFromURL_NoRetryOn404(t *testing.T) {
	var attempt atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempt.Add(1)
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"code":404,"message":"not found"}`))
	}))
	defer srv.Close()

	m := newTestManager(t)
	dest := filepath.Join(t.TempDir(), "plugin.tar.gz")

	err := m.downloadFromURL(srv.URL, dest)
	if err == nil {
		t.Fatal("expected error for 404, got nil")
	}

	// 只应请求 1 次，不重试
	if got := attempt.Load(); got != 1 {
		t.Fatalf("expected 1 attempt for 404, got %d", got)
	}
}

// TestDownloadFromURL_RetryOn429 服务端返回 429 限流，应重试
func TestDownloadFromURL_RetryOn429(t *testing.T) {
	payload := []byte("rate-limit-then-success")
	var attempt atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := attempt.Add(1)
		if n == 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte("rate limited"))
			return
		}
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(payload)))
		w.Write(payload)
	}))
	defer srv.Close()

	m := newTestManager(t)
	dest := filepath.Join(t.TempDir(), "plugin.tar.gz")

	err := m.downloadFromURL(srv.URL, dest)
	if err != nil {
		t.Fatalf("expected success after 429 retry, got error: %v", err)
	}

	data, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("failed to read file: %v", err)
	}
	if string(data) != string(payload) {
		t.Fatalf("content mismatch: got %q, want %q", string(data), string(payload))
	}

	if got := attempt.Load(); got != 2 {
		t.Fatalf("expected 2 attempts, got %d", got)
	}
}

// TestDownloadFromURL_NoRetryOnCreateFailure 目标路径不可写时不应重试
func TestDownloadFromURL_NoRetryOnCreateFailure(t *testing.T) {
	var attempt atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempt.Add(1)
		w.Write([]byte("data"))
	}))
	defer srv.Close()

	m := newTestManager(t)
	// 写入不存在的目录，os.Create 必然失败
	dest := filepath.Join(t.TempDir(), "no-such-dir", "sub", "plugin.tar.gz")

	err := m.downloadFromURL(srv.URL, dest)
	if err == nil {
		t.Fatal("expected error for invalid path, got nil")
	}

	// 文件创建失败是 nonRetryableError，只应请求 1 次
	if got := attempt.Load(); got != 1 {
		t.Fatalf("expected 1 attempt for create failure, got %d", got)
	}
}

// TestDownloadFromURL_FileProtocol 验证 file:// 协议仍然正常工作
func TestDownloadFromURL_FileProtocol(t *testing.T) {
	srcDir := t.TempDir()
	srcPath := filepath.Join(srcDir, "source-plugin")
	content := []byte("file-protocol-content")
	if err := os.WriteFile(srcPath, content, 0644); err != nil {
		t.Fatal(err)
	}

	m := newTestManager(t)
	dest := filepath.Join(t.TempDir(), "plugin-copy")

	err := m.downloadFromURL("file://"+srcPath, dest)
	if err != nil {
		t.Fatalf("file:// download failed: %v", err)
	}

	data, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != string(content) {
		t.Fatalf("content mismatch: got %q, want %q", string(data), string(content))
	}
}

// TestIsRetryableError 验证错误分类逻辑
func TestIsRetryableError(t *testing.T) {
	tests := []struct {
		name      string
		err       error
		retryable bool
	}{
		{"plain error is retryable", fmt.Errorf("connection reset"), true},
		{"unexpected EOF is retryable", fmt.Errorf("failed to write file: %w", io.ErrUnexpectedEOF), true},
		{"nonRetryableError is not retryable", &nonRetryableError{fmt.Errorf("status 404")}, false},
		{"wrapped retryable", fmt.Errorf("outer: %w", fmt.Errorf("inner EOF")), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isRetryableError(tt.err)
			if got != tt.retryable {
				t.Errorf("isRetryableError(%v) = %v, want %v", tt.err, got, tt.retryable)
			}
		})
	}
}
