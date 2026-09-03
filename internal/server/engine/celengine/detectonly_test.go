package celengine

import (
	"testing"
	"time"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

func TestGraceDecision(t *testing.T) {
	now := time.Now()
	lt := func(d time.Duration) *model.LocalTime {
		v := model.ToLocalTime(now.Add(d))
		return &v
	}

	cases := []struct {
		name      string
		rule      model.DetectionRule
		hostGrace bool
		wantGrace bool
		wantDim   string
	}{
		{
			name:      "critical 规则豁免观察期(真威胁不等)",
			rule:      model.DetectionRule{Severity: "critical", Builtin: false, EffectiveAt: lt(-time.Hour)},
			hostGrace: true,
			wantGrace: false,
		},
		{
			name:      "内置规则不受规则观察期约束",
			rule:      model.DetectionRule{Severity: "high", Builtin: true, EffectiveAt: lt(-time.Hour)},
			hostGrace: false,
			wantGrace: false,
		},
		{
			name:      "用户新增规则窗口内降级",
			rule:      model.DetectionRule{Severity: "high", Builtin: false, EffectiveAt: lt(-time.Hour)},
			hostGrace: false,
			wantGrace: true,
			wantDim:   "rule",
		},
		{
			name:      "用户新增规则已过窗口正常告警",
			rule:      model.DetectionRule{Severity: "high", Builtin: false, EffectiveAt: lt(-ruleGraceWindow - time.Hour)},
			hostGrace: false,
			wantGrace: false,
		},
		{
			name:      "EffectiveAt 为 nil 不进规则观察期",
			rule:      model.DetectionRule{Severity: "high", Builtin: false, EffectiveAt: nil},
			hostGrace: false,
			wantGrace: false,
		},
		{
			name:      "新主机观察期对非 critical 规则降级",
			rule:      model.DetectionRule{Severity: "medium", Builtin: true, EffectiveAt: nil},
			hostGrace: true,
			wantGrace: true,
			wantDim:   "host",
		},
		{
			name:      "规则窗口优先于主机窗口标注 rule",
			rule:      model.DetectionRule{Severity: "high", Builtin: false, EffectiveAt: lt(-time.Hour)},
			hostGrace: true,
			wantGrace: true,
			wantDim:   "rule",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gotGrace, gotDim := graceDecision(&c.rule, c.hostGrace, now)
			if gotGrace != c.wantGrace {
				t.Fatalf("grace = %v, want %v", gotGrace, c.wantGrace)
			}
			if c.wantGrace && gotDim != c.wantDim {
				t.Fatalf("dim = %q, want %q", gotDim, c.wantDim)
			}
		})
	}
}
