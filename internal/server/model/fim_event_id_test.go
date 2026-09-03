package model

import "testing"

const (
	sameTS   = int64(1700000000)
	otherTS  = int64(1700003600)
	rawFirst = "evt-000001"
)

// TestDeriveFIMEventID_DistinctAcrossHosts 不同主机的同序号事件必须得到不同主键。
//
// 这是本函数存在的理由：插件的 event_id 每轮扫描从 evt-000001 重新开始，而 event_id
// 是 fim_events 的全局主键。原实现下两台主机的首个事件同 ID，Kafka 路径 DoNothing
// 静默丢掉后来那条，AC 路径则报冲突错——两种都是文件被改而平台没记下。
func TestDeriveFIMEventID_DistinctAcrossHosts(t *testing.T) {
	a := DeriveFIMEventID("host-a", "task-1", "/etc/passwd", "changed", rawFirst, sameTS)
	b := DeriveFIMEventID("host-b", "task-1", "/etc/passwd", "changed", rawFirst, sameTS)
	if a == b {
		t.Fatalf("不同主机的同序号事件不得同主键: %s", a)
	}
}

// TestDeriveFIMEventID_DistinctAcrossScans 同一主机不同扫描的同序号事件也必须区分。
// 计数器每轮重置，所以第二次扫描的首个事件同样是 evt-000001。
func TestDeriveFIMEventID_DistinctAcrossScans(t *testing.T) {
	first := DeriveFIMEventID("host-a", "task-1", "/etc/passwd", "changed", rawFirst, sameTS)
	second := DeriveFIMEventID("host-a", "task-2", "/etc/passwd", "changed", rawFirst, otherTS)
	if first == second {
		t.Fatalf("同主机不同扫描的同序号事件不得同主键: %s", first)
	}
}

// TestDeriveFIMEventID_DistinctPerDimension 每个参与维度都必须真正影响结果，
// 否则某个维度形同虚设，冲突会从那个方向重新出现。
func TestDeriveFIMEventID_DistinctPerDimension(t *testing.T) {
	base := DeriveFIMEventID("h", "t", "/p", "changed", rawFirst, sameTS)
	cases := map[string]string{
		"host":        DeriveFIMEventID("h2", "t", "/p", "changed", rawFirst, sameTS),
		"task":        DeriveFIMEventID("h", "t2", "/p", "changed", rawFirst, sameTS),
		"path":        DeriveFIMEventID("h", "t", "/p2", "changed", rawFirst, sameTS),
		"change_type": DeriveFIMEventID("h", "t", "/p", "removed", rawFirst, sameTS),
		"raw_event":   DeriveFIMEventID("h", "t", "/p", "changed", "evt-000002", sameTS),
		"detected_at": DeriveFIMEventID("h", "t", "/p", "changed", rawFirst, otherTS),
	}
	for dim, got := range cases {
		if got == base {
			t.Errorf("维度 %s 未参与主键推导", dim)
		}
	}
}

// TestDeriveFIMEventID_NoFieldBoundaryAmbiguity 相邻字段的拼接不得产生歧义，
// 否则 host="ab",task="c" 与 host="a",task="bc" 会撞主键。
func TestDeriveFIMEventID_NoFieldBoundaryAmbiguity(t *testing.T) {
	x := DeriveFIMEventID("ab", "c", "/p", "changed", rawFirst, sameTS)
	y := DeriveFIMEventID("a", "bc", "/p", "changed", rawFirst, sameTS)
	if x == y {
		t.Fatal("字段边界歧义：拼接后相同的不同输入得到了同一主键")
	}
}

// TestDeriveFIMEventID_StableForReplay 同一条消息重放必得同一主键，
// Kafka 路径的 OnConflict DoNothing 去重语义依赖这一点。
func TestDeriveFIMEventID_StableForReplay(t *testing.T) {
	a := DeriveFIMEventID("host-a", "task-1", "/etc/passwd", "changed", rawFirst, sameTS)
	b := DeriveFIMEventID("host-a", "task-1", "/etc/passwd", "changed", rawFirst, sameTS)
	if a != b {
		t.Fatalf("同一事件两次推导结果不一致: %s vs %s", a, b)
	}
}

// TestDeriveFIMEventID_FitsColumn 结果必须放得进 varchar(64)。
func TestDeriveFIMEventID_FitsColumn(t *testing.T) {
	id := DeriveFIMEventID("host-a", "task-1", "/etc/passwd", "changed", rawFirst, sameTS)
	if len(id) > 64 {
		t.Errorf("主键长度 %d 超过 varchar(64)", len(id))
	}
	if len(id) < 16 {
		t.Errorf("主键过短，碰撞风险: %s", id)
	}
}
