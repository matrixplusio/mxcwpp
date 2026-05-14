package handlers

import (
	"testing"

	"go.uber.org/zap"
)

func TestParsePortLine_ValidTCP(t *testing.T) {
	h := &PortHandler{Logger: zap.NewNop()}

	// 标准 /proc/net/tcp 行：sl local_addr:port rem_addr:port st tx rx tr tm ret uid timeout inode
	line := "   0: 0100007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0"
	port, err := h.parsePortLine(line, "tcp")
	if err != nil {
		t.Fatalf("parsePortLine failed: %v", err)
	}
	if port == nil {
		t.Fatal("port should not be nil")
	}
	if port.Port != 53 { // 0x0035 = 53
		t.Errorf("expected port 53, got %d", port.Port)
	}
	if port.Protocol != "tcp" {
		t.Errorf("expected protocol tcp, got %s", port.Protocol)
	}
}

func TestParsePortLine_InvalidFormat(t *testing.T) {
	h := &PortHandler{Logger: zap.NewNop()}

	tests := []struct {
		name string
		line string
	}{
		{"字段不足", "0: 0100007F:0035 00000000:0000"},
		{"空行", ""},
		{"无冒号的地址", "0: 0100007F 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 12345"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := h.parsePortLine(tt.line, "tcp")
			if err == nil {
				t.Error("expected error for invalid line format")
			}
		})
	}
}

func TestParsePortLine_UDPNoState(t *testing.T) {
	h := &PortHandler{Logger: zap.NewNop()}

	line := "   0: 00000000:14E9 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 54321 1 0000000000000000 100 0 0 10 0"
	port, err := h.parsePortLine(line, "udp")
	if err != nil {
		t.Fatalf("parsePortLine failed: %v", err)
	}
	if port.Port != 5353 { // 0x14E9 = 5353
		t.Errorf("expected port 5353, got %d", port.Port)
	}
	if port.State != "" {
		t.Errorf("UDP should have empty state, got %s", port.State)
	}
}

func TestTcpStateToString(t *testing.T) {
	h := &PortHandler{Logger: zap.NewNop()}
	tests := []struct {
		code int
		want string
	}{
		{0x0A, "LISTEN"},
		{0x01, "ESTABLISHED"},
		{0x06, "TIME_WAIT"},
		{0xFF, "UNKNOWN(255)"},
	}
	for _, tt := range tests {
		got := h.tcpStateToString(tt.code)
		if got != tt.want {
			t.Errorf("tcpStateToString(%d) = %q, want %q", tt.code, got, tt.want)
		}
	}
}

func TestExtractProcessName(t *testing.T) {
	h := &PortHandler{Logger: zap.NewNop()}
	tests := []struct {
		name    string
		cmdline string
		want    string
	}{
		{"标准命令", "/usr/bin/nginx\x00-g\x00daemon off;", "nginx"},
		{"无路径", "redis-server\x00--port\x006379", "redis-server"},
		{"空命令行", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := h.extractProcessName(tt.cmdline)
			if got != tt.want {
				t.Errorf("extractProcessName(%q) = %q, want %q", tt.cmdline, got, tt.want)
			}
		})
	}
}
