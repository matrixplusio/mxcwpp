package detquality

import (
	"testing"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// reviewed 写入若干条带研判结论的检测告警。
func reviewed(t *testing.T, db *gorm.DB, ruleID string, verdicts []string, at time.Time) {
	t.Helper()
	created := model.ToLocalTime(at)
	for _, v := range verdicts {
		a := testAlert{HostID: "h1", RuleID: ruleID, Verdict: v, VerdictBasis: model.VerdictBasisIndividual, Source: model.AlertSourceDetection, CreatedAt: &created}
		if err := db.Create(&a).Error; err != nil {
			t.Fatalf("create alert: %v", err)
		}
	}
}

func admit(t *testing.T, db *gorm.DB, ruleID string, decidedAt time.Time) {
	t.Helper()
	row := model.RuleCriticalAdmission{
		RuleID: ruleID, Allowed: true, Reason: "seed",
		ChangedBy: model.AdmissionChangedBySeed, DecidedAt: model.ToLocalTime(decidedAt),
	}
	if err := db.Create(&row).Error; err != nil {
		t.Fatalf("create admission: %v", err)
	}
}

func admissionOf(t *testing.T, db *gorm.DB, ruleID string) model.RuleCriticalAdmission {
	t.Helper()
	var r model.RuleCriticalAdmission
	if err := db.Where("rule_id = ?", ruleID).First(&r).Error; err != nil {
		t.Fatalf("load admission %s: %v", ruleID, err)
	}
	return r
}

// 误报够多且没有真实威胁：只提建议，准入不变；由人确认后才生效。
func TestSuggestCriticalDemotions(t *testing.T) {
	db := newTestDB(t)
	svc := NewService(db, zap.NewNop())
	now := time.Now()
	long := now.Add(-60 * 24 * time.Hour)
	recent := now.Add(-24 * time.Hour)

	admit(t, db, "cel-noisy", long)
	reviewed(t, db, "cel-noisy", rep(model.VerdictFalsePositive, 25), recent)

	// 良性真阳性不算数：检测对了，只是这次无害（演练、自测）。把它算成不可信，
	// 会让工作正常的高特异规则被调松。
	admit(t, db, "cel-drill", long)
	reviewed(t, db, "cel-drill", rep(model.VerdictBenignTruePositive, 60), recent)
	admit(t, db, "cel-mixed", long)
	reviewed(t, db, "cel-mixed", append(rep(model.VerdictFalsePositive, 12), rep(model.VerdictBenignTruePositive, 30)...), recent)

	// 有一条真实威胁就不提。
	admit(t, db, "cel-real", long)
	reviewed(t, db, "cel-real", append(rep(model.VerdictFalsePositive, 30), model.VerdictTruePositive), recent)

	// 样本不够、没研判过、窗口之外、人工确认保留之前的，都不算。
	admit(t, db, "cel-few", long)
	reviewed(t, db, "cel-few", rep(model.VerdictFalsePositive, AdmissionMinReviewed-1), recent)
	admit(t, db, "cel-unreviewed", long)
	reviewed(t, db, "cel-unreviewed", rep("", 50), recent)
	admit(t, db, "cel-old", long)
	reviewed(t, db, "cel-old", rep(model.VerdictFalsePositive, 40), now.Add(-AdmissionReviewWindow-24*time.Hour))
	admit(t, db, "cel-confirmed", now.Add(-time.Hour))
	reviewed(t, db, "cel-confirmed", rep(model.VerdictFalsePositive, 40), recent)

	got, err := svc.SuggestCriticalDemotions(now)
	if err != nil {
		t.Fatalf("suggest: %v", err)
	}
	if len(got) != 1 || got[0].RuleID != "cel-noisy" || got[0].FalsePositives != 25 {
		t.Fatalf("应只对 cel-noisy 提建议（25 条误报），得 %+v", got)
	}
	r := admissionOf(t, db, "cel-noisy")
	if !r.Allowed {
		t.Fatal("提建议不该改变准入：仍应是准入状态")
	}
	if r.DemotionSuggestedAt == nil || r.DemotionSuggestion == "" {
		t.Fatalf("建议应记在准入记录上：%+v", r)
	}
	for _, id := range []string{"cel-drill", "cel-mixed", "cel-real", "cel-few", "cel-unreviewed", "cel-old", "cel-confirmed"} {
		if a := admissionOf(t, db, id); !a.Allowed || a.DemotionSuggestedAt != nil {
			t.Errorf("%s 不该被提建议", id)
		}
	}

	// 已有待确认建议的不重复提（也就不会重复通知）。
	again, err := svc.SuggestCriticalDemotions(now.Add(24 * time.Hour))
	if err != nil || len(again) != 0 {
		t.Fatalf("第二轮应无新建议，得 %+v err=%v", again, err)
	}

	// 人确认保留：建议了结，准入不变；确认之前的误报不会让它立刻被再提一次。
	if _, err := svc.SetCriticalAdmission("cel-noisy", true, "已收窄条件，保留", "alice"); err != nil {
		t.Fatalf("confirm keep: %v", err)
	}
	r = admissionOf(t, db, "cel-noisy")
	if !r.Allowed || r.DemotionSuggestedAt != nil || r.DemotionSuggestion != "" || r.ChangedBy != "alice" {
		t.Fatalf("确认保留后建议应清空：%+v", r)
	}
	if again, _ := svc.SuggestCriticalDemotions(now.Add(48 * time.Hour)); len(again) != 0 {
		t.Fatalf("确认保留之前的误报不该再触发建议：%+v", again)
	}
}

func TestSetCriticalAdmission(t *testing.T) {
	db := newTestDB(t)
	svc := NewService(db, zap.NewNop())

	for _, bad := range []string{"", "cel 1", "cel-1;drop", "../x"} {
		if _, err := svc.SetCriticalAdmission(bad, true, "原因", "alice"); err == nil {
			t.Errorf("规则 ID %q 应被拒绝", bad)
		}
	}
	if _, err := svc.SetCriticalAdmission("cel-1", true, "   ", "alice"); err == nil {
		t.Error("不写原因应被拒绝")
	}

	// 清单里没有的规则：直接登记。
	before, err := svc.SetCriticalAdmission("cel-1", true, "收窄了条件，复核通过", "alice")
	if err != nil || before {
		t.Fatalf("首次登记：before=%v err=%v", before, err)
	}
	r := admissionOf(t, db, "cel-1")
	if !r.Allowed || r.ChangedBy != "alice" {
		t.Fatalf("登记结果不符：%+v", r)
	}

	// 已有记录：改写，并返回改之前的状态。
	before, err = svc.SetCriticalAdmission("cel-1", false, "又吵起来了", "bob")
	if err != nil || !before {
		t.Fatalf("改写：before=%v err=%v", before, err)
	}
	r = admissionOf(t, db, "cel-1")
	if r.Allowed || r.ChangedBy != "bob" || r.Reason != "又吵起来了" {
		t.Fatalf("改写结果不符：%+v", r)
	}

	items, err := svc.ListCriticalAdmissions()
	if err != nil || len(items) != 1 {
		t.Fatalf("list：%+v err=%v", items, err)
	}
}
