// Package strutil 给项目集中字符串助手 (A10 审计修复).
//
// 历史: 同名 truncate / intToStr / itoa 等在多处独立实现 (5+ 处),
// 此包提供单一可靠实现, 调用方迁移过来.
package strutil

import (
	"strconv"
	"strings"
)

// Truncate 截断字符串到 maxLen, 超长追加 "..." 后缀.
//
// 用于安全敏感日志 / RASP 上报 / cmdline 截断, 避免内存爆.
func Truncate(s string, maxLen int) string {
	if maxLen <= 0 {
		return ""
	}
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}

// TruncateRaw 截断到 maxLen, 不加后缀.
//
// 用在 BPF / 协议帧场景 (不能加 "..." 改变长度).
func TruncateRaw(s string, maxLen int) string {
	if maxLen <= 0 {
		return ""
	}
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}

// IntToStr 包装 strconv.Itoa, 用于零依赖场景 (RASP / BPF userspace 解析).
func IntToStr(n int) string { return strconv.Itoa(n) }

// Int64ToStr 包装 strconv.FormatInt.
func Int64ToStr(n int64) string { return strconv.FormatInt(n, 10) }

// BoolToStr "true" / "false".
func BoolToStr(b bool) string { return strconv.FormatBool(b) }

// MaskMiddle 把 s 中间 mask 成 ***, 保留头 head + 尾 tail 字符.
//
//	MaskMiddle("ak_abcdef1234", 2, 2) = "ak***34"
//
// 用于 KMS / API key 日志展示.
func MaskMiddle(s string, head, tail int) string {
	if head < 0 {
		head = 0
	}
	if tail < 0 {
		tail = 0
	}
	if len(s) <= head+tail {
		return "***"
	}
	return s[:head] + "***" + s[len(s)-tail:]
}

// ContainsAny s 含 needles 中任意一项.
func ContainsAny(s string, needles ...string) bool {
	for _, n := range needles {
		if strings.Contains(s, n) {
			return true
		}
	}
	return false
}

// HasPrefixAny s 以 prefixes 中任意一项打头.
func HasPrefixAny(s string, prefixes ...string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}
