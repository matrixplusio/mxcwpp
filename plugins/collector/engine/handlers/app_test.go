package handlers

import (
	"testing"

	"go.uber.org/zap"
)

func TestExtractPortFromProcess(t *testing.T) {
	h := &AppHandler{Logger: zap.NewNop()}

	tests := []struct {
		name     string
		cmdline  string
		wantPort int
	}{
		{"--port= 参数", "mysqld --port=3306 --datadir=/var/lib/mysql", 3306},
		{"--port 空格参数", "redis-server --port 6379 --bind 0.0.0.0", 6379},
		{"-p 参数", "nginx -p 8080 -c /etc/nginx.conf", 8080},
		{"--listen= 参数", "server --listen=9090", 9090},
		{"无端口参数", "nginx -g daemon off", 0},
		{"空命令行", "", 0},
		{"参数在末尾无值 --port=", "server --port=", 0},
		{"--port 在末尾无值", "server --port ", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proc := map[string]string{"cmdline": tt.cmdline}
			got := h.extractPortFromProcess(proc)
			if got != tt.wantPort {
				t.Errorf("extractPortFromProcess(%q) = %d, want %d", tt.cmdline, got, tt.wantPort)
			}
		})
	}
}

func TestFindProcessByName_Empty(t *testing.T) {
	h := &AppHandler{Logger: zap.NewNop()}

	// 查找不存在的进程名
	processes, err := h.findProcessByName("nonexistent-process-xyz-12345")
	if err != nil {
		// /proc 在非 Linux 系统不存在，跳过
		t.Skipf("skipping on non-Linux: %v", err)
	}
	if len(processes) != 0 {
		t.Errorf("expected 0 processes for nonexistent name, got %d", len(processes))
	}
}
