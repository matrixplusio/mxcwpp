package anomaly

import (
	"testing"

	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

func newVersionDB(t *testing.T) *gorm.DB {
	t.Helper()
	db := newStateDB(t)
	if err := db.AutoMigrate(&model.AnomalyModelVersion{}); err != nil {
		t.Fatalf("migrate versions: %v", err)
	}
	return db
}

// trainDetector 造一个训练好的 detector。
func trainDetector(t *testing.T, db *gorm.DB, center float64) *Detector {
	t.Helper()
	d := newStateDetector(db)
	d.forest.Train(makeWindow(512, center, 8))
	if !d.forest.Trained() {
		t.Fatal("训练失败")
	}
	return d
}

// 每次训练留下一个版本，版本号单调递增，且只有一个生效。
func TestEachTrainCreatesRollbackPoint(t *testing.T) {
	db := newVersionDB(t)
	d := trainDetector(t, db, 50)

	d.saveModelVersion(512, 0.5)
	d.forest.Train(makeWindow(512, 60, 8))
	d.saveModelVersion(512, 1.2)

	var vs []model.AnomalyModelVersion
	if err := db.Where("model_name = ?", modelStateName).Order("version").Find(&vs).Error; err != nil {
		t.Fatalf("read versions: %v", err)
	}
	if len(vs) != 2 {
		t.Fatalf("应有 2 个版本，实际 %d", len(vs))
	}
	if vs[0].Version != 1 || vs[1].Version != 2 {
		t.Fatalf("版本号应为 1,2，实际 %d,%d", vs[0].Version, vs[1].Version)
	}
	// 任一时刻只应有一个生效版本，否则重启后加载哪个是不确定的。
	active := 0
	for _, v := range vs {
		if v.Active {
			active++
		}
	}
	if active != 1 {
		t.Fatalf("生效版本应恰好 1 个，实际 %d", active)
	}
	if !vs[1].Active {
		t.Fatal("最新版本应为生效版本")
	}
}

// 回滚后模型真的换了：分数必须变回旧版本的分数。
//
// 只改数据库标记而内存模型没换，等于"回滚成功"却仍在用坏模型打分——
// 这正是回滚必须防住的失败方式。
func TestRollbackActuallySwapsModel(t *testing.T) {
	db := newVersionDB(t)
	d := trainDetector(t, db, 50)

	sample := makeWindow(1, 50, 8)[0]
	v1Score := d.forest.Score(sample)
	d.saveModelVersion(512, 0)

	// 换一个明显不同的模型作为 v2。
	d.forest.Train(makeWindow(512, 500, 40))
	d.saveModelVersion(512, 3.0)
	v2Score := d.forest.Score(sample)
	if v1Score == v2Score {
		t.Skip("两个模型对该样本打分相同，换个样本再测")
	}

	if err := d.RollbackModel(1, "tester"); err != nil {
		t.Fatalf("回滚失败: %v", err)
	}
	if got := d.forest.Score(sample); got != v1Score {
		t.Fatalf("回滚后分数应回到 v1 的 %.17g，实际 %.17g", v1Score, got)
	}
	if d.activeVersion() != 1 {
		t.Fatalf("生效版本应为 1，实际 %d", d.activeVersion())
	}
}

// 回滚到装不上的版本必须失败，且不改数据库。
//
// 顺序反了的话，一个装不上的模型会被标成生效，重启后同样装不上——
// 一次失败的回滚会变成持续故障。
func TestRollbackToCorruptVersionChangesNothing(t *testing.T) {
	db := newVersionDB(t)
	d := trainDetector(t, db, 50)
	d.saveModelVersion(512, 0)

	// 塞一个损坏的 v2 并置为生效。
	bad := model.AnomalyModelVersion{
		ModelName: modelStateName, ModelNameIdx: modelStateName,
		Version: 2, Payload: "{not json", Active: false,
	}
	if err := db.Create(&bad).Error; err != nil {
		t.Fatalf("create bad version: %v", err)
	}

	sample := makeWindow(1, 50, 8)[0]
	before := d.forest.Score(sample)
	activeBefore := d.activeVersion()

	if err := d.RollbackModel(2, "tester"); err == nil {
		t.Fatal("回滚到损坏版本必须失败")
	}
	if got := d.forest.Score(sample); got != before {
		t.Fatal("回滚失败后当前模型不该改变")
	}
	if d.activeVersion() != activeBefore {
		t.Fatalf("回滚失败后生效版本不该改变，%d → %d", activeBefore, d.activeVersion())
	}
}

// 回滚到不存在的版本给出明确错误。
func TestRollbackToMissingVersion(t *testing.T) {
	db := newVersionDB(t)
	d := trainDetector(t, db, 50)
	d.saveModelVersion(512, 0)
	if err := d.RollbackModel(99, "tester"); err == nil {
		t.Fatal("不存在的版本必须报错")
	}
}

// 重启后能恢复生效版本的模型，且分数一致。
func TestActiveModelSurvivesRestart(t *testing.T) {
	db := newVersionDB(t)
	first := trainDetector(t, db, 50)
	first.saveModelVersion(512, 0)
	sample := makeWindow(1, 50, 8)[0]
	want := first.forest.Score(sample)

	// 模拟重启：全新 detector，只共享数据库。
	second := newStateDetector(db)
	if second.forest.Trained() {
		t.Fatal("新实例在加载前不该是已训练状态")
	}
	second.LoadActiveModel()
	if !second.forest.Trained() {
		t.Fatal("重启后应恢复模型，否则要等一个完整重训周期才能评分")
	}
	if got := second.forest.Score(sample); got != want {
		t.Fatalf("恢复后分数应一致: want=%.17g got=%.17g", want, got)
	}
}

// 只保留最近若干版本，且生效版本永不被清掉。
//
// 删掉正在用的版本会让重启后无模型可加载，而这种失败要到下次重启才暴露。
func TestPruneKeepsRecentAndActive(t *testing.T) {
	db := newVersionDB(t)
	d := trainDetector(t, db, 50)
	for i := range model.MaxRetainedModelVersions + 3 {
		d.forest.Train(makeWindow(512, 50+float64(i), 8))
		d.saveModelVersion(512, 0)
	}

	var vs []model.AnomalyModelVersion
	if err := db.Where("model_name = ?", modelStateName).Find(&vs).Error; err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(vs) > model.MaxRetainedModelVersions {
		t.Fatalf("应最多保留 %d 个版本，实际 %d", model.MaxRetainedModelVersions, len(vs))
	}
	found := false
	for _, v := range vs {
		if v.Active {
			found = true
		}
	}
	if !found {
		t.Fatal("生效版本被清理掉了：重启后将无模型可加载")
	}
}

// 未训练时不产生版本：空模型加载回去会让 Trained() 为真却给不出有意义的分数。
func TestUntrainedProducesNoVersion(t *testing.T) {
	db := newVersionDB(t)
	d := newStateDetector(db)
	d.saveModelVersion(0, 0)

	var n int64
	db.Model(&model.AnomalyModelVersion{}).Count(&n)
	if n != 0 {
		t.Fatalf("未训练不该产生版本，实际 %d", n)
	}
}
