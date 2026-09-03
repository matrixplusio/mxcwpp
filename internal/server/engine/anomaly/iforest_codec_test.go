package anomaly

import (
	"testing"
)

// 序列化往返后，同一样本的分数必须逐位一致。
//
// 这是模型持久化唯一有意义的正确性标准：如果加载回来的模型给出不同的分数，
// 那它就不是同一个模型了——重启后阈值的含义会悄悄改变，而没有任何东西会提示。
func TestForestRoundTripPreservesScores(t *testing.T) {
	f := NewIForest()
	f.Train(makeWindow(512, 50, 8))
	if !f.Trained() {
		t.Fatal("训练失败")
	}

	samples := [][]float64{
		makeWindow(1, 50, 8)[0],
		makeWindow(1, 200, 8)[0], // 明显异常
		makeWindow(1, 0, 1)[0],
	}
	before := make([]float64, len(samples))
	for i, s := range samples {
		before[i] = f.Score(s)
	}

	data, err := f.MarshalForest()
	if err != nil {
		t.Fatalf("序列化失败: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("已训练的森林不该序列化为空")
	}

	restored := NewIForest()
	if err := restored.UnmarshalForest(data); err != nil {
		t.Fatalf("反序列化失败: %v", err)
	}
	if !restored.Trained() {
		t.Fatal("恢复后的森林应为已训练状态")
	}

	for i, s := range samples {
		after := restored.Score(s)
		if after != before[i] {
			t.Fatalf("样本 %d 往返后分数不一致: before=%.17g after=%.17g", i, before[i], after)
		}
	}
}

// 未训练的森林序列化为空，而不是产出一个"空模型"。
//
// 空模型加载回去会让 Trained() 为真却给不出有意义的分数——
// 那是最糟的状态：看起来在工作，实际在乱打分。
func TestUntrainedForestMarshalsEmpty(t *testing.T) {
	f := NewIForest()
	data, err := f.MarshalForest()
	if err != nil {
		t.Fatalf("不该报错: %v", err)
	}
	if len(data) != 0 {
		t.Fatalf("未训练森林应序列化为空，实际 %d 字节", len(data))
	}
}

// 特征维数不符必须拒绝加载，并保留原模型。
//
// 维数变过之后，旧模型的第 i 维已经不是当前的第 i 维。用它打分会给出
// 看似正常实则错位的结果——比没有模型更糟。
func TestDimensionMismatchRejected(t *testing.T) {
	f := NewIForest()
	f.Train(makeWindow(512, 50, 8))
	snap := f.Snapshot()
	snap.Features = featureCount + 1

	restored := NewIForest()
	restored.Train(makeWindow(512, 30, 5))
	sample := makeWindow(1, 30, 5)[0]
	before := restored.Score(sample)

	if err := restored.LoadSnapshot(snap); err == nil {
		t.Fatal("维数不符必须拒绝加载")
	}
	if after := restored.Score(sample); after != before {
		t.Fatal("加载被拒后必须保留原模型，分数不该变化")
	}
}

// 结构可疑的快照一律拒绝：半个森林照样给分，只是分数不再有意义。
func TestMalformedSnapshotsRejected(t *testing.T) {
	good := func() *forestSnapshot {
		f := NewIForest()
		f.Train(makeWindow(512, 50, 8))
		return f.Snapshot()
	}

	cases := map[string]func(*forestSnapshot){
		"无树":     func(s *forestSnapshot) { s.Trees = nil },
		"psi 非法": func(s *forestSnapshot) { s.Psi = 0 },
		"c 非法":   func(s *forestSnapshot) { s.C = 0 },
		"空树":     func(s *forestSnapshot) { s.Trees[0] = nil },
	}
	for name, mutate := range cases {
		snap := good()
		mutate(snap)
		if err := NewIForest().LoadSnapshot(snap); err == nil {
			t.Fatalf("%s 的快照必须被拒绝", name)
		}
	}
	if err := NewIForest().LoadSnapshot(nil); err == nil {
		t.Fatal("nil 快照必须被拒绝")
	}
}

// 损坏的 JSON 不能让检测器崩掉。
func TestCorruptDataRejected(t *testing.T) {
	for _, data := range [][]byte{nil, {}, []byte("not json"), []byte(`{"trees":`)} {
		if err := NewIForest().UnmarshalForest(data); err == nil {
			t.Fatalf("损坏数据必须被拒绝: %q", string(data))
		}
	}
}
