// Package osfamily 统一 OS 系列名称的比较。
//
// 主机上报的 os_family 取自 /etc/os-release 的 ID（Oracle Linux 是 "ol"），
// 策略里写的是人读的名字（"oracle"）。逐字比较会让整类主机被静默跳过，所以比较前先归一。
package osfamily

import "strings"

var aliases = map[string]string{
	"ol":           "oracle",
	"oraclelinux":  "oracle",
	"oracle linux": "oracle",
	"alma":         "almalinux",
	"redhat":       "rhel",
	"red hat":      "rhel",
}

// Normalize 返回规范名：小写、去空白、别名折叠。
func Normalize(family string) string {
	f := strings.ToLower(strings.TrimSpace(family))
	if canon, ok := aliases[f]; ok {
		return canon
	}
	return f
}

// Contains 判断 families 中是否有与 family 同属一个系列的项。
func Contains(families []string, family string) bool {
	want := Normalize(family)
	if want == "" {
		return false
	}
	for _, f := range families {
		if Normalize(f) == want {
			return true
		}
	}
	return false
}
