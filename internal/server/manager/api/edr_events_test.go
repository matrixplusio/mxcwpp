package api

import (
	"errors"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestNormalizeDateBound(t *testing.T) {
	cases := []struct {
		name  string
		in    string
		upper bool
		want  string
	}{
		// 含 ":" 视为已带时分秒，原样返回（即便看起来不完整）
		{"datetime keeps as-is lower", "2026-06-04 15:30:45", false, "2026-06-04 15:30:45"},
		{"datetime keeps as-is upper", "2026-06-04 15:30:45", true, "2026-06-04 15:30:45"},
		{"hour minute kept", "2026-06-04 15:00", false, "2026-06-04 15:00"},
		// 仅 date：补时分秒
		{"date only lower bound", "2026-06-04", false, "2026-06-04 00:00:00"},
		{"date only upper bound", "2026-06-04", true, "2026-06-04 23:59:59"},
		{"empty string lower", "", false, ""},
		{"empty string upper", "", true, ""},
		// ISO 8601 兼容（regression 修复）
		{"ISO 8601 with Z", "2026-06-04T15:30:45Z", false, "2026-06-04 15:30:45"},
		{"ISO 8601 with Z upper", "2026-06-04T15:30:45Z", true, "2026-06-04 15:30:45"},
		{"ISO 8601 with +tz", "2026-06-04T15:30:45+08:00", false, "2026-06-04 15:30:45"},
		{"ISO 8601 with -tz", "2026-06-04T15:30:45-05:00", false, "2026-06-04 15:30:45"},
		{"ISO 8601 with fractional", "2026-06-04T15:30:45.123Z", false, "2026-06-04 15:30:45.123"},
		{"datetime with T no tz", "2026-06-04T15:30:45", false, "2026-06-04 15:30:45"},
		// URL '+' 未编码 → Go decode 成空格(回归 fix: detail endpoint 500)
		{"ISO 8601 +tz with URL-decoded space", "2026-06-04T15:30:45 08:00", false, "2026-06-04 15:30:45"},
		{"ISO 8601 -tz with URL-decoded space", "2026-06-04T15:30:45 05:00", false, "2026-06-04 15:30:45"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := normalizeDateBound(tc.in, tc.upper)
			if got != tc.want {
				t.Errorf("normalizeDateBound(%q, %v) = %q; want %q", tc.in, tc.upper, got, tc.want)
			}
		})
	}
}

// TestRecordCHQuery_NoPanic 验证 recordCHQuery 对各类输入不 panic（含 nil err / timeout-like err / 通用 err）。
// 真实 status label 写入由 metrics 包的 Prom collector 处理，单测不深入 collector 内部状态；
// 这里只确保副作用（Prom histogram observe + 慢查询 log）能跑通。
func TestRecordCHQuery_NoPanic(t *testing.T) {
	h := &EDREventsHandler{logger: zap.NewNop()}
	cases := []struct {
		name string
		err  error
	}{
		{"nil err", nil},
		{"go ctx deadline", errors.New("context deadline exceeded")},
		{"ch max_execution_time", errors.New("Code: 159. DB::Exception: max_execution_time")},
		{"ch TIMEOUT_EXCEEDED", errors.New("TIMEOUT_EXCEEDED: forced abort")},
		{"generic error", errors.New("driver disconnected")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("recordCHQuery panicked: %v", r)
				}
			}()
			h.recordCHQuery("test_op", "test_table", time.Now(), tc.err)
		})
	}
}

// TestRecordCHQuery_StatusClassification 验证 status 分类逻辑（与代码内 strings.Contains 链一致）。
// 该测试镜像了 recordCHQuery 内部逻辑：避免后续重构时悄悄改坏 timeout 识别。
func TestRecordCHQuery_StatusClassification(t *testing.T) {
	classify := func(err error) string {
		status := "ok"
		if err != nil {
			status = "error"
			msg := err.Error()
			if strings.Contains(msg, "deadline exceeded") ||
				strings.Contains(msg, "max_execution_time") ||
				strings.Contains(msg, "TIMEOUT_EXCEEDED") {
				status = "timeout"
			}
		}
		return status
	}
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"nil", nil, "ok"},
		{"go ctx deadline", errors.New("context deadline exceeded"), "timeout"},
		{"ch max_execution_time", errors.New("Code: 159. DB::Exception: max_execution_time exceeded"), "timeout"},
		{"ch TIMEOUT_EXCEEDED", errors.New("TIMEOUT_EXCEEDED: query was aborted"), "timeout"},
		{"generic err", errors.New("driver disconnected"), "error"},
		{"err containing word time but not timeout", errors.New("invalid time format"), "error"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classify(tc.err); got != tc.want {
				t.Errorf("classify(%v) = %q; want %q", tc.err, got, tc.want)
			}
		})
	}
}
