package engine

import (
	"context"
	"testing"
)

// TestShouldCheckScan 校验 1b：仅入站连接(direction=inbound 或 event_type=tcp_accept)走扫描检测。
func TestShouldCheckScan(t *testing.T) {
	cases := []struct {
		name   string
		fields map[string]string
		want   bool
	}{
		{"inbound 方向", map[string]string{"direction": "inbound"}, true},
		{"tcp_accept 兜底(方向缺失)", map[string]string{"event_type": "tcp_accept"}, true},
		{"outbound 不检测", map[string]string{"direction": "outbound", "event_type": "tcp_connect"}, false},
		{"tcp_connect 不检测", map[string]string{"event_type": "tcp_connect"}, false},
		{"空事件不检测", map[string]string{}, false},
	}
	for _, c := range cases {
		if got := shouldCheckScan(c.fields); got != c.want {
			t.Errorf("%s: shouldCheckScan=%v 期望 %v", c.name, got, c.want)
		}
	}
}

// TestScanStage_NilDetectorSafe 校验 detector 为 nil(未配 Redis)时 stage 安全 no-op。
func TestScanStage_NilDetectorSafe(t *testing.T) {
	s := NewScanStage(nil, nil)
	if s.Name() != "scan" {
		t.Errorf("Name=%q", s.Name())
	}
	alerts, err := s.Process(context.Background(), PipelineEvent{HostID: "h1"})
	if err != nil || alerts != nil {
		t.Errorf("nil detector 应安全 no-op, got alerts=%v err=%v", alerts, err)
	}
}
