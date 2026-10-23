package celengine

import (
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/matrixplusio/mxcwpp/internal/server/engine/celengine/replay"
	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// logClearRule 与内置「防御规避 - 日志清除」同一个表达式。
var logClearRule = model.DetectionRule{
	ID: 10, Name: "防御规避 - 日志清除", Severity: "high", Category: "defense_evasion",
	Expression: `(cmdline.contains(">/dev/null") || cmdline.contains("history -c") || cmdline.contains("rm -rf /var/log")) && exe.contains("bash")`,
	DataTypes:  model.StringArray{"3000"}, Enabled: true, Stage: model.RuleStageAlert, Fidelity: model.RuleFidelityHigh,
}

func newTestGuard(t *testing.T) WhitelistGuard {
	t.Helper()
	e, err := NewInMemory(zap.NewNop(), []model.DetectionRule{logClearRule})
	if err != nil {
		t.Fatal(err)
	}
	corpus, err := replay.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	return NewWhitelistGuard(e, corpus.Attacks(), zap.NewNop())
}

func TestWhitelistGuard(t *testing.T) {
	guard := newTestGuard(t)
	cases := []struct {
		name   string
		wl     model.AlertWhitelist
		reject bool
	}{
		// 规则要求进程是 bash，豁免又对全部主机写 bash。
		{"豁免抵消规则条件", model.AlertWhitelist{RuleID: "cel-10", Exe: "bash"}, true},
		{"豁免会压掉清除历史的攻击样本", model.AlertWhitelist{RuleID: "cel-10", Cmdline: "history -c"}, true},
		{"限定主机也一样：攻击就可能发生在那台主机上", model.AlertWhitelist{RuleID: "cel-10", HostID: "h1", Cmdline: "history"}, true},
		{"只豁免某个脚本，攻击样本不受影响", model.AlertWhitelist{RuleID: "cel-10", Exe: "/usr/bin/bash", Cmdline: "/opt/scripts/backup.sh"}, false},
		{"别的规则的豁免不受影响", model.AlertWhitelist{RuleID: "cel-99", Cmdline: "history -c"}, false},
		// 对所有规则生效的豁免：只要有一条规则点名的正是这个进程，就是在停用那条规则。
		{"不指定规则的豁免逐条核对", model.AlertWhitelist{Exe: "/usr/bin/bash", HostID: "h1"}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			reason := guard(&c.wl)
			if (reason != "") != c.reject {
				t.Fatalf("拒绝=%v（%q），期望 %v", reason != "", reason, c.reject)
			}
		})
	}
}

// 被检查出问题的白名单不再生效，并开一条告警；同一批冲突只开一次，不随每次加载重复。
func TestGuardWhitelistDropsAndRaisesOnce(t *testing.T) {
	db := setupStageDB(t)
	g := newStageGenerator(db)
	g.whitelistGuard = func() WhitelistGuard { return newTestGuard(t) }
	expires := model.ToLocalTime(time.Now().Add(time.Hour))
	rows := func() []model.AlertWhitelist {
		return []model.AlertWhitelist{
			{ID: 1, RuleID: "cel-10", Exe: "bash", Enabled: true, ExpiresAt: &expires},
			{ID: 2, RuleID: "cel-10", Exe: "/usr/bin/bash", Cmdline: "/opt/scripts/backup.sh", Enabled: true, ExpiresAt: &expires},
		}
	}

	kept := g.guardWhitelist(rows())
	if len(kept) != 1 || kept[0].ID != 2 {
		t.Fatalf("应只保留第 2 条，实际 %+v", kept)
	}
	g.guardWhitelist(rows())

	var alerts []model.Alert
	db.Where("rule_id = ?", "whitelist-guard").Find(&alerts)
	if len(alerts) != 1 {
		t.Fatalf("应开一条告警，实际 %d", len(alerts))
	}
	if !strings.Contains(alerts[0].Title, "#1") || alerts[0].Status != model.AlertStatusActive {
		t.Fatalf("告警应指向白名单 #1 且处于待处理: %+v", alerts[0])
	}
}

// 影子阶段的规则在判白名单之前就跳过了，它的白名单不起作用，不必报冲突。
func TestWhitelistGuardIgnoresShadowRules(t *testing.T) {
	shadow := logClearRule
	shadow.Stage = model.RuleStageShadow
	e, err := NewInMemory(zap.NewNop(), []model.DetectionRule{shadow})
	if err != nil {
		t.Fatal(err)
	}
	guard := NewWhitelistGuard(e, nil, zap.NewNop())
	if reason := guard(&model.AlertWhitelist{RuleID: "cel-10", Exe: "bash"}); reason != "" {
		t.Fatalf("影子规则的白名单不应报冲突: %q", reason)
	}
}
