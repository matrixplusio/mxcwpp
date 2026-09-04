package biz

import "testing"

// TestJoinNEVRA 采集侧分开存的三段，比较前必须拼回通告使用的形态。
//
// 通告写作 epoch:version-release。只拿 version 去比，release 段恒缺，
// 比较器会判定「装的比修复版旧」——大部分已修复的漏洞会因此被判成回潮。
func TestJoinNEVRA(t *testing.T) {
	cases := []struct {
		name                    string
		epoch, version, release string
		want                    string
	}{
		{"典型 RPM", "0", "0.10.4", "18.el9", "0.10.4-18.el9"},
		{"带非零 epoch", "1", "3.5.5", "4.el9_8", "1:3.5.5-4.el9_8"},
		{"epoch 为 (none)", "(none)", "2.4.6", "1.el9", "2.4.6-1.el9"},
		{"语言生态无 epoch/release", "", "v0.23.2", "", "v0.23.2"},
		{"只有 release", "", "1.2.3", "5.el9", "1.2.3-5.el9"},
		{"版本为空", "0", "", "1.el9", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := joinNEVRA(c.epoch, c.version, c.release); got != c.want {
				t.Errorf("joinNEVRA(%q,%q,%q) = %q，应为 %q",
					c.epoch, c.version, c.release, got, c.want)
			}
		})
	}
}

// TestNEVRAComparisonSucceedsWhereBareVersionFails 拼回 NEVRA 之后，
// 「已装版本是否达到修复版」这个判断才成立。
//
// 这是两种数据形态的直接对照：左边是修复前送进比较器的串，右边是修复后的。
func TestNEVRAComparisonSucceedsWhereBareVersionFails(t *testing.T) {
	const osFamily = "rocky"
	const purl = "pkg:rpm/rocky/libssh"
	const fixed = "0.10.4-18.el9"

	// 修复前：只有 version，release 段缺失
	bare := joinNEVRA("", "0.10.4", "")
	if cmp, err := compareInstalledVsFix(osFamily, purl, bare, fixed); err == nil && cmp >= 0 {
		t.Errorf("残缺版本串 %q 竟被判为已达修复版——那说明这个用例失去了意义", bare)
	}

	// 修复后：三段齐全，且已装的 release 高于修复版
	full := joinNEVRA("0", "0.10.4", "20.el9")
	cmp, err := compareInstalledVsFix(osFamily, purl, full, fixed)
	if err != nil {
		t.Fatalf("完整 NEVRA %q 比较失败: %v", full, err)
	}
	if cmp < 0 {
		t.Errorf("已装 %q 高于修复版 %q，却被判为仍需修复", full, fixed)
	}
}

// TestBackportedFixIsRecognised 发行版回合补丁必须能被识别。
//
// RHEL 系把上游修复回合进同一个上游版本号，只推进 release。
// 上游版本号完全相同，只有 release 不同——丢掉 release 就等于丢掉了
// 「这个洞到底修没修」的唯一凭据，这正是红队与成熟扫描器都盯着 NEVRA 的原因。
func TestBackportedFixIsRecognised(t *testing.T) {
	const osFamily = "rocky"
	const purl = "pkg:rpm/rocky/openssl"

	fixed := joinNEVRA("1", "3.0.7", "27.el9")     // 通告：回合修复在 -27
	installed := joinNEVRA("1", "3.0.7", "28.el9") // 主机：比它更新

	cmp, err := compareInstalledVsFix(osFamily, purl, installed, fixed)
	if err != nil {
		t.Fatalf("比较失败: %v", err)
	}
	if cmp < 0 {
		t.Errorf("已装 %q 的 release 高于修复版 %q，回合补丁应判为已修复", installed, fixed)
	}
}
