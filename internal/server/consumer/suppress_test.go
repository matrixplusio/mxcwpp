package consumer

import "testing"

// TestIsBehaviorSuppressed 验证运维抑制窗查询:窗内 host 命中、其它不命中、缓存空时不抑制。
func TestIsBehaviorSuppressed(t *testing.T) {
	r := &Router{}
	if r.isBehaviorSuppressed("h1") {
		t.Fatal("空缓存不应抑制")
	}
	set := map[string]struct{}{"h1": {}}
	r.suppressed.Store(&set)
	if !r.isBehaviorSuppressed("h1") {
		t.Fatal("h1 在抑制窗内应抑制")
	}
	if r.isBehaviorSuppressed("h2") {
		t.Fatal("h2 不在窗内不应抑制")
	}
}
