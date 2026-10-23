package api

import "testing"

// TestEvaluateReadiness 验证 readiness 状态聚合：
//   - 全 ok → ok，不 503
//   - 硬依赖(database)不可用 → degraded 且应 503
//   - 仅可选依赖(clickhouse/redis)不可用 → degraded 但不 503（降级仍可服务）
func TestEvaluateReadiness(t *testing.T) {
	cases := []struct {
		name            string
		checks          map[string]string
		wantStatus      string
		wantUnavailable bool
	}{
		{
			name:            "all ok",
			checks:          map[string]string{"database": "ok", "clickhouse": "ok", "redis": "ok"},
			wantStatus:      "ok",
			wantUnavailable: false,
		},
		{
			name:            "database down is hard failure",
			checks:          map[string]string{"database": "error", "clickhouse": "ok"},
			wantStatus:      "degraded",
			wantUnavailable: true,
		},
		{
			name:            "database timeout is hard failure",
			checks:          map[string]string{"database": "timeout"},
			wantStatus:      "degraded",
			wantUnavailable: true,
		},
		{
			name:            "clickhouse down only degrades",
			checks:          map[string]string{"database": "ok", "clickhouse": "error"},
			wantStatus:      "degraded",
			wantUnavailable: false,
		},
		{
			name:            "redis down only degrades",
			checks:          map[string]string{"database": "ok", "redis": "error"},
			wantStatus:      "degraded",
			wantUnavailable: false,
		},
		{
			name:            "optional deps absent, db ok",
			checks:          map[string]string{"database": "ok"},
			wantStatus:      "ok",
			wantUnavailable: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status, unavailable := evaluateReadiness(tc.checks)
			if status != tc.wantStatus {
				t.Errorf("status = %q, want %q", status, tc.wantStatus)
			}
			if unavailable != tc.wantUnavailable {
				t.Errorf("unavailable = %v, want %v", unavailable, tc.wantUnavailable)
			}
		})
	}
}
