package consumer

import (
	"testing"

	"github.com/IBM/sarama"
)

// TestParseInitialOffset 验证冷启动初始位点解析：
// 仅显式 "oldest"（大小写/空白不敏感）解析为 OffsetOldest，其余一律默认 OffsetNewest（不破坏现状）。
func TestParseInitialOffset(t *testing.T) {
	cases := []struct {
		in   string
		want int64
	}{
		{"oldest", sarama.OffsetOldest},
		{"OLDEST", sarama.OffsetOldest},
		{"  oldest  ", sarama.OffsetOldest},
		{"newest", sarama.OffsetNewest},
		{"", sarama.OffsetNewest},
		{"garbage", sarama.OffsetNewest},
	}
	for _, tc := range cases {
		if got := parseInitialOffset(tc.in); got != tc.want {
			t.Errorf("parseInitialOffset(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}
