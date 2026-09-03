package advisory

import (
	"fmt"
	"strings"
	"unicode"
)

// CompareDpkgVersion 按 Debian dpkg 版本比较语义比对 a 和 b。
// 返回 -1 (a<b) / 0 (a==b) / 1 (a>b)。
//
// 格式: [epoch:]upstream_version[-debian_revision]
//
//	"1.2.3-1ubuntu2" → epoch=0, upstream="1.2.3", revision="1ubuntu2"
//	"2:1.0.0-3"     → epoch=2, upstream="1.0.0", revision="3"
//	"1.0"           → epoch=0, upstream="1.0", revision=""
//
// 算法：
//  1. epoch 整数比较
//  2. upstream_version 用 dpkg 段比对（'~' < (end) < letters < digits < other）
//  3. debian_revision 用 dpkg 段比对
//
// 参考 dpkg/lib/dpkg/version.c verrevcmp()。
func CompareDpkgVersion(a, b string) (int, error) {
	aEpoch, aVer, aRev, err := dpkgVerEpoch(a)
	if err != nil {
		return 0, err
	}
	bEpoch, bVer, bRev, err := dpkgVerEpoch(b)
	if err != nil {
		return 0, err
	}
	if aEpoch != bEpoch {
		if aEpoch < bEpoch {
			return -1, nil
		}
		return 1, nil
	}
	if c := dpkgSegmentCompare(aVer, bVer); c != 0 {
		return c, nil
	}
	if aRev == "" && bRev == "" {
		return 0, nil
	}
	return dpkgSegmentCompare(aRev, bRev), nil
}

// dpkgVerEpoch 拆分 dpkg 版本号。
func dpkgVerEpoch(s string) (epoch int, ver, rev string, err error) {
	rest := s
	if colon := strings.Index(rest, ":"); colon > 0 && allDigits(rest[:colon]) {
		for _, c := range rest[:colon] {
			epoch = epoch*10 + int(c-'0')
		}
		rest = rest[colon+1:]
	}
	// 最后一个 '-' 分割 upstream 与 debian_revision
	if dash := strings.LastIndex(rest, "-"); dash > 0 {
		ver = rest[:dash]
		rev = rest[dash+1:]
	} else {
		ver = rest
	}
	if ver == "" {
		err = fmt.Errorf("invalid dpkg version: %q", s)
	}
	return
}

// dpkgSegmentCompare 实现 dpkg verrevcmp 算法。
//
// 关键差异（与 RPM 不同）：
//   - '~' < empty < letter < digit < other_punct
//   - 数字段按数值比较
//   - 非数字段逐字符比较，但使用 dpkgCharOrder 自定义序
func dpkgSegmentCompare(a, b string) int {
	ai, bi := 0, 0
	for ai < len(a) || bi < len(b) {
		// 非数字段比较
		for (ai < len(a) && !unicode.IsDigit(rune(a[ai]))) ||
			(bi < len(b) && !unicode.IsDigit(rune(b[bi]))) {
			var ac, bc int
			if ai < len(a) && !unicode.IsDigit(rune(a[ai])) {
				ac = dpkgCharOrder(a[ai])
			}
			if bi < len(b) && !unicode.IsDigit(rune(b[bi])) {
				bc = dpkgCharOrder(b[bi])
			}
			if ac != bc {
				if ac < bc {
					return -1
				}
				return 1
			}
			if ai < len(a) && !unicode.IsDigit(rune(a[ai])) {
				ai++
			}
			if bi < len(b) && !unicode.IsDigit(rune(b[bi])) {
				bi++
			}
		}
		// 数字段比较（先剥 leading zero 然后比长度再比值）
		for ai < len(a) && a[ai] == '0' {
			ai++
		}
		for bi < len(b) && b[bi] == '0' {
			bi++
		}
		var aNumStart, bNumStart = ai, bi
		for ai < len(a) && unicode.IsDigit(rune(a[ai])) {
			ai++
		}
		for bi < len(b) && unicode.IsDigit(rune(b[bi])) {
			bi++
		}
		aNum := a[aNumStart:ai]
		bNum := b[bNumStart:bi]
		if len(aNum) != len(bNum) {
			if len(aNum) < len(bNum) {
				return -1
			}
			return 1
		}
		if aNum != bNum {
			if aNum < bNum {
				return -1
			}
			return 1
		}
	}
	return 0
}

// dpkgCharOrder 实现 dpkg 字符序：'~' < empty < letter < digit < other_punct
//
// 返回值用于比较，按以下规则映射:
//
//	'~'      → -1（最小，"pre-release" 标记）
//	(empty)  →  0
//	letter   →  ASCII 值
//	digit    →  在外层 numeric branch 处理，这里不应出现
//	其他     →  ASCII + 256（确保大于 letter）
func dpkgCharOrder(c byte) int {
	switch {
	case c == '~':
		return -1
	case c >= 'A' && c <= 'Z':
		return int(c)
	case c >= 'a' && c <= 'z':
		return int(c)
	default:
		return int(c) + 256
	}
}
