package advisory

import "testing"

// TestCompareVersionByOS 校验 3c：按 OS family 选权威比较器，正确处理 release 后缀
// （旧弱比较器忽略 el9_4 会把安全 bump 判为相等 → 误标已修）。
func TestCompareVersionByOS(t *testing.T) {
	cases := []struct {
		name     string
		osFamily string
		a, b     string
		wantSign int // <0 / 0 / >0
	}{
		{"rpm el9 < el9_4 安全bump", "rocky", "2.34-100.el9", "2.34-100.el9_4", -1},
		{"rpm 相等", "centos", "1.2.3-4.el8", "1.2.3-4.el8", 0},
		{"rpm 已达修复", "rhel", "1.2.3-5.el8", "1.2.3-4.el8", 1},
		{"dpkg ubuntu 安全bump", "ubuntu", "1.0-1ubuntu0.1", "1.0-1ubuntu0.2", -1},
		{"默认按 rpm(未知 OS)", "", "1.0-1.el9", "1.0-1.el9_2", -1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := CompareVersionByOS(c.osFamily, c.a, c.b)
			if err != nil {
				t.Fatalf("CompareVersionByOS(%q,%q,%q) err: %v", c.osFamily, c.a, c.b, err)
			}
			if sign(got) != c.wantSign {
				t.Errorf("CompareVersionByOS(%q,%q,%q) = %d, 期望符号 %d", c.osFamily, c.a, c.b, got, c.wantSign)
			}
		})
	}
}

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	default:
		return 0
	}
}
