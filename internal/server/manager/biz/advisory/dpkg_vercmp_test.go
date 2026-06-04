package advisory

import "testing"

func TestCompareDpkgVersion(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		// 数字段按数值
		{"1.10", "1.9", 1},
		{"1.9", "1.10", -1},
		{"2.0", "2.0", 0},

		// epoch 优先
		{"1:1.0", "2:0.1", -1},
		{"2:0.1", "1:9.9", 1},

		// debian_revision
		{"1.2.3-1", "1.2.3-2", -1},
		{"1.2.3-2", "1.2.3-1", 1},
		{"1.2.3-1ubuntu2", "1.2.3-1ubuntu3", -1},

		// '~' 是 pre-release 标记，小于一切（含空）
		{"1.0~rc1", "1.0", -1},
		{"1.0~rc1", "1.0~rc2", -1},
		{"1.0", "1.0~rc1", 1},

		// 字母 < 数字
		{"1.0a", "1.0", 1},   // 1.0a 比 1.0 大(因 1.0 末尾空字符的 char order 是 0 < 字母)
		{"1.0a", "1.0b", -1}, // a < b

		// 真实 Debian 案例
		{"2.34-211.0.4.el9_4", "2.34-211.0.4.el9_4", 0},
		{"2.31-13+deb11u11", "2.31-13+deb11u12", -1},

		// upstream 不变只看 revision
		{"3.0.5-4ubuntu0.1", "3.0.5-4ubuntu0.2", -1},
	}
	for _, tc := range cases {
		got, err := CompareDpkgVersion(tc.a, tc.b)
		if err != nil {
			t.Errorf("CompareDpkgVersion(%q,%q) err: %v", tc.a, tc.b, err)
			continue
		}
		if got != tc.want {
			t.Errorf("CompareDpkgVersion(%q,%q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}
