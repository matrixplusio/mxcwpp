package scheduler

import "testing"

func TestShouldBroadcastPlugins(t *testing.T) {
	cases := []struct {
		name    string
		changed int
		manual  int64
		auto    bool
		want    bool
	}{
		{"版本变化但自动广播关闭：不广播，等重连拉取或控制台推送", 1, 0, false, false},
		{"版本变化且开启自动广播", 1, 0, true, true},
		{"控制台显式推送：版本没变也广播", 0, 1, false, true},
		{"无变化无推送", 0, 0, true, false},
	}
	for _, c := range cases {
		if got := shouldBroadcastPlugins(c.changed, c.manual, c.auto); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}
