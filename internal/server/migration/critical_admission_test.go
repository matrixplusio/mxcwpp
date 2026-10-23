package migration

import (
	"strconv"
	"testing"

	"go.uber.org/zap"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

func TestSeedCriticalAdmissions(t *testing.T) {
	db := setupRuleDB(t)
	if err := db.AutoMigrate(&model.SequenceRule{}, &model.RuleCriticalAdmission{}); err != nil {
		t.Fatalf("automigrate: %v", err)
	}
	createSystemConfigs(t, db)
	rules := []model.DetectionRule{
		{Name: "动态链接劫持 - ld.so.preload", Expression: "true", Severity: "critical"},
		{Name: "sudoers 文件修改", Expression: "true", Severity: "critical"},
		{Name: "信息收集 - 网络枚举", Expression: "true", Severity: "low"},
	}
	if err := db.Create(&rules).Error; err != nil {
		t.Fatalf("seed rules: %v", err)
	}
	seqs := []model.SequenceRule{
		{Name: "内存执行-外联 攻击链", Severity: "critical", Steps: model.SequenceSteps{}},
		{Name: "Web服务派生Shell-侦察 攻击链", Severity: "critical", Steps: model.SequenceSteps{}},
	}
	if err := db.Create(&seqs).Error; err != nil {
		t.Fatalf("seed sequence rules: %v", err)
	}

	if err := seedCriticalAdmissions(db, zap.NewNop()); err != nil {
		t.Fatalf("seed: %v", err)
	}

	var rows []model.RuleCriticalAdmission
	if err := db.Find(&rows).Error; err != nil {
		t.Fatalf("load: %v", err)
	}
	got := make(map[string]model.RuleCriticalAdmission, len(rows))
	for _, r := range rows {
		got[r.RuleID] = r
	}
	celID := func(i int) string { return "cel-" + strconv.FormatUint(uint64(rules[i].ID), 10) }
	seqID := func(i int) string { return "seq-" + strconv.FormatUint(uint64(seqs[i].ID), 10) }

	if r, ok := got[celID(0)]; !ok || !r.Allowed {
		t.Errorf("未被点名的 critical 规则应沿用准入：%+v", r)
	}
	if r, ok := got[celID(1)]; !ok || r.Allowed || r.Reason == "" {
		t.Errorf("被点名的规则应登记为不准入并写明原因：%+v", r)
	}
	if _, ok := got[celID(2)]; ok {
		t.Errorf("非 critical 规则不该出现在清单里")
	}
	if r, ok := got[seqID(0)]; !ok || r.Allowed {
		t.Errorf("被点名的攻击链应登记为不准入：%+v", r)
	}
	if r, ok := got[seqID(1)]; !ok || !r.Allowed {
		t.Errorf("未被点名的攻击链应沿用准入：%+v", r)
	}
	for _, id := range criticalStageRules {
		if r, ok := got[id]; !ok || !r.Allowed {
			t.Errorf("硬编码规则 %s 应在初始清单里且准入", id)
		}
	}

	// 只执行一次：之后人或自动降级改过的记录不能被启动时的种子覆盖回去。
	if err := db.Model(&model.RuleCriticalAdmission{}).Where("rule_id = ?", celID(0)).
		Updates(map[string]any{"allowed": false, "changed_by": "auto"}).Error; err != nil {
		t.Fatalf("update: %v", err)
	}
	if err := seedCriticalAdmissions(db, zap.NewNop()); err != nil {
		t.Fatalf("reseed: %v", err)
	}
	var again model.RuleCriticalAdmission
	if err := db.Where("rule_id = ?", celID(0)).First(&again).Error; err != nil {
		t.Fatalf("reload: %v", err)
	}
	if again.Allowed {
		t.Fatal("再次启动把已降级的规则恢复成了准入")
	}
	var n int64
	db.Model(&model.RuleCriticalAdmission{}).Count(&n)
	if int(n) != len(rows) {
		t.Fatalf("再次启动后行数从 %d 变成 %d", len(rows), n)
	}
}

// 点名的规则名必须真实存在于内置规则里：改了规则名而没同步这里，那条规则会悄悄恢复 critical。
func TestCriticalDeniedRulesExistInBuiltins(t *testing.T) {
	db := setupRuleDB(t)
	if err := initBuiltinDetectionRules(db, zap.NewNop()); err != nil {
		t.Fatalf("init builtin rules: %v", err)
	}
	for name := range criticalDeniedRules {
		var r model.DetectionRule
		if err := db.Where("name = ?", name).First(&r).Error; err != nil {
			t.Errorf("内置规则里找不到 %q：%v", name, err)
			continue
		}
		if r.Severity != "critical" {
			t.Errorf("%q 声明的级别是 %s，已不需要点名", name, r.Severity)
		}
	}
	seq := make(map[string]string)
	for _, r := range builtinSequenceRules() {
		seq[r.Name] = r.Severity
	}
	for name := range criticalDeniedSequenceRules {
		if seq[name] != "critical" {
			t.Errorf("内置攻击链里找不到声明为 critical 的 %q", name)
		}
	}
}

// 内置规则还没进库时什么都不写。表只要非空，引擎就认为清单已就绪、把清单外的 critical
// 规则全部压到 high；这时候只写硬编码规则那几条，等于把还没导入的内置规则全判了不准入。
func TestSeedCriticalAdmissionsWaitsForRules(t *testing.T) {
	db := setupRuleDB(t)
	if err := db.AutoMigrate(&model.SequenceRule{}, &model.RuleCriticalAdmission{}); err != nil {
		t.Fatalf("automigrate: %v", err)
	}
	createSystemConfigs(t, db)

	// 第一次启动：规则表是空的（导入失败）。
	if err := seedCriticalAdmissions(db, zap.NewNop()); err != nil {
		t.Fatalf("seed: %v", err)
	}
	var n int64
	db.Model(&model.RuleCriticalAdmission{}).Count(&n)
	if n != 0 {
		t.Fatalf("规则没导入时不该写任何准入记录，得 %d", n)
	}

	// 第二次启动：规则进来了，整份清单一次写齐。
	rule := model.DetectionRule{Name: "动态链接劫持 - ld.so.preload", Expression: "true", Severity: "critical"}
	if err := db.Create(&rule).Error; err != nil {
		t.Fatalf("create rule: %v", err)
	}
	if err := seedCriticalAdmissions(db, zap.NewNop()); err != nil {
		t.Fatalf("reseed: %v", err)
	}
	var got model.RuleCriticalAdmission
	if err := db.Where("rule_id = ?", "cel-"+strconv.FormatUint(uint64(rule.ID), 10)).First(&got).Error; err != nil || !got.Allowed {
		t.Fatalf("补进来的 critical 规则应被登记为准入：%+v err=%v", got, err)
	}
	db.Model(&model.RuleCriticalAdmission{}).Count(&n)
	if int(n) != len(criticalStageRules)+1 {
		t.Fatalf("应写入硬编码规则 %d 条 + 1 条，得 %d", len(criticalStageRules), n)
	}

	// 写完之后新建的 critical 规则不再自动准入。
	later := model.DetectionRule{Name: "之后新建的规则", Expression: "true", Severity: "critical"}
	if err := db.Create(&later).Error; err != nil {
		t.Fatalf("create later rule: %v", err)
	}
	if err := seedCriticalAdmissions(db, zap.NewNop()); err != nil {
		t.Fatalf("third run: %v", err)
	}
	var cnt int64
	db.Model(&model.RuleCriticalAdmission{}).Where("rule_id = ?", "cel-"+strconv.FormatUint(uint64(later.ID), 10)).Count(&cnt)
	if cnt != 0 {
		t.Fatal("初始清单写完之后新建的规则不该自动获得准入")
	}
}

// 从没有标记的上一版升上来：表里已有清单，只补标记。
// 重新写一遍的话，上次写入之后新建、还没人决定过的 critical 规则会被自动准入。
func TestSeedCriticalAdmissionsUpgradeOnlyMarks(t *testing.T) {
	db := setupRuleDB(t)
	if err := db.AutoMigrate(&model.SequenceRule{}, &model.RuleCriticalAdmission{}); err != nil {
		t.Fatalf("automigrate: %v", err)
	}
	createSystemConfigs(t, db)

	newer := model.DetectionRule{Name: "上次写入之后新建的规则", Expression: "true", Severity: "critical"}
	if err := db.Create(&newer).Error; err != nil {
		t.Fatalf("create rule: %v", err)
	}
	seeded := model.DetectionRule{Name: "上次已登记的规则", Expression: "true", Severity: "critical"}
	if err := db.Create(&seeded).Error; err != nil {
		t.Fatalf("create rule: %v", err)
	}
	for _, a := range []model.RuleCriticalAdmission{
		{RuleID: "REVERSE_SHELL", Allowed: false, ChangedBy: "alice", DecidedAt: model.Now()},
		{RuleID: "cel-" + strconv.FormatUint(uint64(seeded.ID), 10), Allowed: true, ChangedBy: model.AdmissionChangedBySeed, DecidedAt: model.Now()},
	} {
		if err := db.Create(&a).Error; err != nil {
			t.Fatalf("create admission: %v", err)
		}
	}

	for i := 0; i < 2; i++ {
		if err := seedCriticalAdmissions(db, zap.NewNop()); err != nil {
			t.Fatalf("seed #%d: %v", i, err)
		}
	}
	var n int64
	db.Model(&model.RuleCriticalAdmission{}).Count(&n)
	if n != 2 {
		t.Fatalf("已有清单时不该再插入，得 %d 条", n)
	}
	var kept model.RuleCriticalAdmission
	db.Where("rule_id = ?", "REVERSE_SHELL").First(&kept)
	if kept.Allowed || kept.ChangedBy != "alice" {
		t.Fatalf("人改过的记录被动了：%+v", kept)
	}
	db.Model(&model.SystemConfig{}).Where("`key` = ?", criticalSeedMarkerKey).Count(&n)
	if n != 1 {
		t.Fatalf("应补上且只补一次标记，得 %d", n)
	}
}

// 上一版在规则导入失败的库上只写得进硬编码检测那几条，且此后不会再补。
// 这是一份残缺的清单：升级后要补齐，不能只盖个「已完成」。人改过的保持原样。
func TestSeedCriticalAdmissionsCompletesPartialList(t *testing.T) {
	db := setupRuleDB(t)
	if err := db.AutoMigrate(&model.SequenceRule{}, &model.RuleCriticalAdmission{}); err != nil {
		t.Fatalf("automigrate: %v", err)
	}
	createSystemConfigs(t, db)

	for _, id := range criticalStageRules {
		a := model.RuleCriticalAdmission{RuleID: id, Allowed: true, ChangedBy: model.AdmissionChangedBySeed, DecidedAt: model.Now()}
		if id == "REVERSE_SHELL" {
			a.Allowed, a.ChangedBy = false, "alice"
		}
		if err := db.Create(&a).Error; err != nil {
			t.Fatalf("create admission: %v", err)
		}
	}
	// 残缺清单上有人手工准入过一条：这不代表其余规则都登记过了。
	manual := model.DetectionRule{Name: "手工准入过的规则", Expression: "true", Severity: "critical"}
	if err := db.Create(&manual).Error; err != nil {
		t.Fatalf("create rule: %v", err)
	}
	if err := db.Create(&model.RuleCriticalAdmission{RuleID: "cel-" + strconv.FormatUint(uint64(manual.ID), 10),
		Allowed: true, ChangedBy: "alice", DecidedAt: model.Now()}).Error; err != nil {
		t.Fatalf("create admission: %v", err)
	}
	rule := model.DetectionRule{Name: "动态链接劫持 - ld.so.preload", Expression: "true", Severity: "critical"}
	if err := db.Create(&rule).Error; err != nil {
		t.Fatalf("create rule: %v", err)
	}
	if err := seedCriticalAdmissions(db, zap.NewNop()); err != nil {
		t.Fatalf("seed: %v", err)
	}
	var got model.RuleCriticalAdmission
	if err := db.Where("rule_id = ?", "cel-"+strconv.FormatUint(uint64(rule.ID), 10)).First(&got).Error; err != nil || !got.Allowed {
		t.Fatalf("残缺清单应被补齐：%+v err=%v", got, err)
	}
	var kept model.RuleCriticalAdmission
	db.Where("rule_id = ?", "REVERSE_SHELL").First(&kept)
	if kept.Allowed || kept.ChangedBy != "alice" {
		t.Fatalf("人改过的记录被覆盖了：%+v", kept)
	}
}
