package casework

import (
	"errors"
	"testing"
	"time"

	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

func withOncallTable(t *testing.T, db *gorm.DB) {
	t.Helper()
	if err := db.Exec(`CREATE TABLE oncall_shifts (
		tenant_id TEXT DEFAULT 't-default', id INTEGER PRIMARY KEY AUTOINCREMENT,
		tier TEXT NOT NULL, username TEXT NOT NULL,
		starts_at DATETIME NOT NULL, ends_at DATETIME NOT NULL,
		created_at DATETIME, updated_at DATETIME
	)`).Error; err != nil {
		t.Fatal(err)
	}
}

func addShift(t *testing.T, db *gorm.DB, tier, user string, from, to time.Time) {
	t.Helper()
	if err := db.Exec(
		`INSERT INTO oncall_shifts (tier, username, starts_at, ends_at) VALUES (?,?,?,?)`,
		tier, user, from, to).Error; err != nil {
		t.Fatal(err)
	}
}

// TestCurrentOncall_PicksActiveShift 只取当前时间窗内的值班人。
func TestCurrentOncall_PicksActiveShift(t *testing.T) {
	s, db := newTestService(t)
	withOncallTable(t, db)
	now := time.Now()

	addShift(t, db, model.OncallTierL1, "past", now.Add(-4*time.Hour), now.Add(-2*time.Hour))
	addShift(t, db, model.OncallTierL1, "current", now.Add(-1*time.Hour), now.Add(time.Hour))
	addShift(t, db, model.OncallTierL1, "future", now.Add(2*time.Hour), now.Add(4*time.Hour))

	got, err := s.CurrentOncall(model.OncallTierL1)
	if err != nil {
		t.Fatal(err)
	}
	if got != "current" {
		t.Errorf("值班人 = %q, want current", got)
	}
}

// TestCurrentOncall_ReportsGap 无人值班要明确报错而不是返回空字符串。
//
// 返回空会让调用方把"没人值班"当成"指派给了空用户"，事件看起来有主实际无人管。
func TestCurrentOncall_ReportsGap(t *testing.T) {
	s, db := newTestService(t)
	withOncallTable(t, db)

	if _, err := s.CurrentOncall(model.OncallTierL2); !errors.Is(err, ErrNoOncall) {
		t.Errorf("无人值班应返回 ErrNoOncall，实际 %v", err)
	}
}

// TestAutoAssign_AssignsToOncall 新事件自动派给当班的一线值班人。
func TestAutoAssign_AssignsToOncall(t *testing.T) {
	s, db := newTestService(t)
	withOncallTable(t, db)
	seedIncident(t, db, "inc-1", "high")
	now := time.Now()
	addShift(t, db, model.OncallTierL1, "alice", now.Add(-time.Hour), now.Add(time.Hour))

	if err := s.AutoAssign("inc-1"); err != nil {
		t.Fatal(err)
	}
	if got := loadIncident(t, db, "inc-1").Owner; got != "alice" {
		t.Errorf("owner = %q, want alice", got)
	}
}

// TestAutoAssign_RecordsGapInsteadOfSilentSkip 排班有缺口时留下时间线记录。
//
// 静默跳过会让事件一直无主而无人知道原因；排班缺口本身就是运维要处理的问题。
func TestAutoAssign_RecordsGapInsteadOfSilentSkip(t *testing.T) {
	s, db := newTestService(t)
	withOncallTable(t, db)
	seedIncident(t, db, "inc-1", "critical")

	if err := s.AutoAssign("inc-1"); err != nil {
		t.Fatalf("无人值班不应报错中断: %v", err)
	}
	if got := loadIncident(t, db, "inc-1").Owner; got != "" {
		t.Errorf("无人值班时不应指派，owner = %q", got)
	}
	events, err := s.Timeline("inc-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("应留下 1 条派单失败记录，实际 %d 条", len(events))
	}
}

// TestEscalateToNextTier_ResolvesTargetFromRoster 升级对象由值班表算出。
// 让人在半夜三点自己填"升级给谁"是行不通的。
func TestEscalateToNextTier_ResolvesTargetFromRoster(t *testing.T) {
	s, db := newTestService(t)
	withOncallTable(t, db)
	seedIncident(t, db, "inc-1", "critical")
	now := time.Now()
	addShift(t, db, model.OncallTierL2, "bob", now.Add(-time.Hour), now.Add(time.Hour))

	if err := s.EscalateToNextTier("inc-1", model.OncallTierL1, "疑似横向移动", "alice"); err != nil {
		t.Fatal(err)
	}
	inc := loadIncident(t, db, "inc-1")
	if !inc.Escalated || inc.EscalatedTo != "bob" {
		t.Errorf("升级目标 = %q, want bob (L2 当班)", inc.EscalatedTo)
	}
}

// TestEscalateToNextTier_FailsAtTopTier 已在最高层要明确报错，不假装升级成功。
func TestEscalateToNextTier_FailsAtTopTier(t *testing.T) {
	s, db := newTestService(t)
	withOncallTable(t, db)
	seedIncident(t, db, "inc-1", "critical")

	if err := s.EscalateToNextTier("inc-1", model.OncallTierSecurity, "原因", "alice"); err == nil {
		t.Error("最高层级继续升级应报错")
	}
	if loadIncident(t, db, "inc-1").Escalated {
		t.Error("失败的升级不应改变事件状态")
	}
}

// TestSaveShift_RejectsInvalidWindow 结束早于开始的排班永远匹配不到人，
// 等于这段时间没人值班却看起来排了。
func TestSaveShift_RejectsInvalidWindow(t *testing.T) {
	s, db := newTestService(t)
	withOncallTable(t, db)
	now := time.Now()

	err := s.SaveShift(&model.OncallShift{
		Tier: model.OncallTierL1, Username: "alice",
		StartsAt: model.ToLocalTime(now.Add(time.Hour)),
		EndsAt:   model.ToLocalTime(now),
	})
	if err == nil {
		t.Error("结束早于开始的排班应被拒绝")
	}
}

// TestNextTier 升级链必须有确定的下一站，最高层返回空。
func TestNextTier(t *testing.T) {
	if got := model.NextTier(model.OncallTierL1); got != model.OncallTierL2 {
		t.Errorf("L1 的下一层 = %q", got)
	}
	if got := model.NextTier(model.OncallTierL2); got != model.OncallTierSecurity {
		t.Errorf("L2 的下一层 = %q", got)
	}
	if got := model.NextTier(model.OncallTierSecurity); got != "" {
		t.Errorf("最高层不应有下一层，实际 %q", got)
	}
}
