// Package osfamily 统一 OS 系列名称的比较。
//
// 主机上报的 os_family 取自 /etc/os-release 的 ID（Oracle Linux 是 "ol"），
// 策略里写的是人读的名字（"oracle"）。逐字比较会让整类主机被静默跳过，所以比较前先归一。
package osfamily

import (
	"sort"
	"strings"
)

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

// rhelCompatible 是与 RHEL 二进制兼容、共用 RHSA 修复版本的系列（规范名）。
var rhelCompatible = map[string]bool{
	"rhel":          true,
	"rocky":         true,
	"centos":        true,
	"centos-stream": true,
	"almalinux":     true,
	"oracle":        true,
}

// RHELCompatible 判断 family 是否属于 RHEL 兼容系列（任意拼写）。
func RHELCompatible(family string) bool {
	return rhelCompatible[Normalize(family)]
}

// RHELCompatibleSQLList 返回 RHEL 兼容系列的全部拼写（规范名 + 别名），
// 形如 'almalinux','alma',...，供 SQL 的 LOWER(os_family) IN (...) 使用。
// SQL 侧没法调用 Normalize，库里存的又是主机上报的原值（如 "ol"），只列规范名会漏。
func RHELCompatibleSQLList() string {
	names := make([]string, 0, len(rhelCompatible)+len(aliases))
	for f := range rhelCompatible {
		names = append(names, f)
	}
	for alias, canon := range aliases {
		if rhelCompatible[canon] {
			names = append(names, alias)
		}
	}
	sort.Strings(names)
	return "'" + strings.Join(names, "','") + "'"
}
