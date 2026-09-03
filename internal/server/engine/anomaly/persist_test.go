package anomaly

import (
	"testing"

	"go.uber.org/zap"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

func newStateDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if sqlDB, e := db.DB(); e == nil {
		sqlDB.SetMaxOpenConns(1)
	}
	if err := db.AutoMigrate(&model.AnomalyModelState{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

func newStateDetector(db *gorm.DB) *Detector {
	return &Detector{
		db:         db,
		logger:     zap.NewNop(),
		forest:     NewIForest(),
		hostMeans:  map[string][]float64{},
		hostCounts: map[string]int{},
	}
}

// 参照基线必须能跨重启保留。
//
// 参照必须来自一段未被污染的历史，丢了就再也长不回来。若每次重启都从零开始，
// 投毒防护在每次发布、扩容、崩溃恢复后都会静默失效一段时间。
func TestReferenceSurvivesRestart(t *testing.T) {
	db := newStateDB(t)

	first := newStateDetector(db)
	first.reference = newReferenceBaseline(makeWindow(minReferenceSamples, 50, 5))
	if first.reference == nil {
		t.Fatal("参照基线未建立")
	}
	first.SaveState()

	// 模拟进程重启：全新 Detector，只共享数据库。
	second := newStateDetector(db)
	if second.HasReference() {
		t.Fatal("新实例在 LoadState 之前不该有参照")
	}
	second.LoadState()
	if !second.HasReference() {
		t.Fatal("重启后未恢复参照基线：投毒防护会静默失效")
	}
	if second.reference.samples != first.reference.samples {
		t.Fatalf("恢复的样本数不符：got %d want %d",
			second.reference.samples, first.reference.samples)
	}
	for i := range first.reference.mean {
		if second.reference.mean[i] != first.reference.mean[i] {
			t.Fatalf("第 %d 维均值恢复不符: got %v want %v",
				i, second.reference.mean[i], first.reference.mean[i])
		}
	}
}

// 恢复后的参照必须仍能拦下投毒——只恢复数字但判断失效等于没恢复。
func TestRestoredReferenceStillBlocksPoisoning(t *testing.T) {
	db := newStateDB(t)
	first := newStateDetector(db)
	first.reference = newReferenceBaseline(makeWindow(minReferenceSamples, 50, 5))
	first.SaveState()

	second := newStateDetector(db)
	second.LoadState()
	if !second.HasReference() {
		t.Fatal("未恢复参照基线")
	}
	if rep := second.reference.evaluateDrift(makeWindow(200, 80, 5)); !rep.Poisoned {
		t.Fatalf("恢复后的参照未能拦下明显偏移，最大偏移 %.2fσ", rep.MaxDrift)
	}
}

// 存量参照的维度与当前特征数不符时必须丢弃重建。
//
// 特征维度变过之后，旧参照的第 i 维已经不是当前的第 i 维。拿它做漂移判断
// 会给出一个看起来精确、实际错位的结论——比没有结论更糟。
func TestDimensionMismatchDiscardsReference(t *testing.T) {
	db := newStateDB(t)
	st := model.AnomalyModelState{
		ModelName:        modelStateName,
		ReferenceMean:    model.FloatArray{1, 2, 3},
		ReferenceStdev:   model.FloatArray{1, 1, 1},
		ReferenceSamples: 999,
	}
	if err := db.Create(&st).Error; err != nil {
		t.Fatalf("create state: %v", err)
	}

	d := newStateDetector(db)
	d.LoadState()
	if d.HasReference() {
		t.Fatal("维度不符的参照必须被丢弃，不能错位比较")
	}
}

// 没有状态记录时正常启动，不能因此把检测器卡住。
func TestMissingStateStartsClean(t *testing.T) {
	d := newStateDetector(newStateDB(t))
	d.LoadState()
	if d.HasReference() {
		t.Fatal("空库不该产生参照")
	}
}

// 拒绝重训要累加计数：连续拒绝意味着模型长期学不进新数据，
// 而这在指标上只表现为一个计数器，不记录就无从复盘。
func TestRejectedRetrainIsCounted(t *testing.T) {
	db := newStateDB(t)
	d := newStateDetector(db)
	d.reference = newReferenceBaseline(makeWindow(minReferenceSamples, 50, 5))
	d.SaveState()

	d.recordRejectedRetrain()
	d.recordRejectedRetrain()

	var st model.AnomalyModelState
	if err := db.Where("model_name = ?", modelStateName).First(&st).Error; err != nil {
		t.Fatalf("read state: %v", err)
	}
	if st.RejectedRetrains != 2 {
		t.Fatalf("拒绝重训计数应为 2，实际 %d", st.RejectedRetrains)
	}
}

// 从未训练过不算陈旧：那是冷启动。
//
// 把两者混为一谈会让刚启动的实例一直报陈旧告警，最后没人再看它。
func TestNeverTrainedIsNotStale(t *testing.T) {
	d := newStateDetector(newStateDB(t))
	if d.ModelStale() {
		t.Fatal("从未训练过应视为冷启动，不是陈旧")
	}
}

// 数据库不可用时不能让检测器崩掉。
//
// 模型状态是决策辅助，不是检测链路的一环；因为它挂掉整个异常检测是本末倒置。
func TestNilDBIsSafe(t *testing.T) {
	d := newStateDetector(nil)
	d.LoadState()
	d.SaveState()
	d.recordRejectedRetrain()
	if d.HasReference() {
		t.Fatal("无数据库时不该凭空产生参照")
	}
}
