package consumer

import "testing"

func TestShouldPersistBehaviorAlert(t *testing.T) {
	cases := []struct {
		name      string
		coldStart bool
		risk      float64
		want      bool
	}{
		{"毕业后全量保留-低分", false, 10, true},
		{"毕业后全量保留-高分", false, 95, true},
		{"学习期冷启动-低分抑制", true, 40, false},
		{"学习期冷启动-临界下抑制", true, coldStartBehaviorAlertMinScore - 0.1, false},
		{"学习期冷启动-达阈值保留", true, coldStartBehaviorAlertMinScore, true},
		{"学习期冷启动-高分保留", true, 99, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := shouldPersistBehaviorAlert(c.coldStart, c.risk); got != c.want {
				t.Fatalf("shouldPersistBehaviorAlert(%v,%v)=%v want %v", c.coldStart, c.risk, got, c.want)
			}
		})
	}
}
