package storyline

import (
	"testing"
	"time"

	"go.uber.org/zap"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

func lifecycleEngine(t *testing.T) *Engine {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: gormlogger.Default.LogMode(gormlogger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	if err := db.AutoMigrate(&model.Storyline{}, &model.StorylineEvent{}); err != nil {
		t.Fatal(err)
	}
	return NewEngine(db, zap.NewNop())
}

func seedStory(t *testing.T, e *Engine, id, status string, lastSeen time.Time) {
	t.Helper()
	if err := e.db.Create(&model.Storyline{StoryID: id, Status: status, LastSeenAt: model.LocalTime(lastSeen)}).Error; err != nil {
		t.Fatal(err)
	}
}

func storyStatus(t *testing.T, e *Engine, id string) string {
	t.Helper()
	var s model.Storyline
	if err := e.db.Where("story_id = ?", id).First(&s).Error; err != nil {
		t.Fatal(err)
	}
	return s.Status
}

// 长时间无新事件的 active 故事线要在库里关闭；近期活跃的、人工处置过的不动。
// 不关闭，active 只增不减，计数和事件关联都会越来越慢。
func TestCloseInactive(t *testing.T) {
	e := lifecycleEngine(t)
	now := time.Now()
	seedStory(t, e, "old", model.StorylineStatusActive, now.Add(-3*time.Hour))
	seedStory(t, e, "recent", model.StorylineStatusActive, now.Add(-10*time.Minute))
	seedStory(t, e, "handled", model.StorylineStatusResolved, now.Add(-3*time.Hour))

	e.closeInactive(now.Add(-closeAfter))

	if got := storyStatus(t, e, "old"); got != model.StorylineStatusClosed {
		t.Errorf("old: %s，期望 closed", got)
	}
	if got := storyStatus(t, e, "recent"); got != model.StorylineStatusActive {
		t.Errorf("recent: %s，期望仍为 active", got)
	}
	if got := storyStatus(t, e, "handled"); got != model.StorylineStatusResolved {
		t.Errorf("handled: %s，人工处置的不应被改", got)
	}
}

// 已关闭的故事线又来新事件：重新打开，而不是在 closed 状态下继续累积。
// 人工 resolved 的不自动改回。
func TestPersistReopensClosedStory(t *testing.T) {
	e := lifecycleEngine(t)
	old := time.Now().Add(-3 * time.Hour)
	seedStory(t, e, "s1", model.StorylineStatusClosed, old)
	seedStory(t, e, "s2", model.StorylineStatusResolved, old)

	e.Ingest("s1", "h1", "web-01", 3001, netFields("c2-beacon"))
	e.Ingest("s2", "h1", "web-01", 3001, netFields("c2-beacon"))
	e.flush()

	if got := storyStatus(t, e, "s1"); got != model.StorylineStatusActive {
		t.Errorf("s1: %s，有新事件应重新打开", got)
	}
	if got := storyStatus(t, e, "s2"); got != model.StorylineStatusResolved {
		t.Errorf("s2: %s，人工处置的不应被自动改回", got)
	}
}
