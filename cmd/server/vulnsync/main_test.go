package main

import (
	"sort"
	"testing"

	"go.uber.org/zap"
)

func sourceNames(t *testing.T, enabled, fleet map[string]bool) []string {
	t.Helper()
	srcs := buildAdvisorySources(enabled, fleet, zap.NewNop())
	names := make([]string, 0, len(srcs))
	for n := range srcs {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

func setOf(items ...string) map[string]bool {
	m := make(map[string]bool, len(items))
	for _, i := range items {
		m[i] = true
	}
	return m
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func TestSourceServesFleet(t *testing.T) {
	cases := []struct {
		source string
		fleet  map[string]bool
		want   bool
	}{
		{"rhsa", setOf("centos"), true},         // rhsa 经 rhel-compat 覆盖 centos
		{"rhsa", setOf("rocky"), true},          // 覆盖 rocky
		{"rocky-apollo", setOf("centos"), true}, // rocky-apollo 覆盖 centos
		{"debian-tracker", setOf("centos", "rocky"), false},
		{"usn", setOf("centos"), false},
		{"alpine", setOf("centos"), false},
		{"usn", setOf("ubuntu"), true},
		{"debian-tracker", setOf("debian"), true},
		{"kylin-sa", setOf("kylin"), true},
		{"unknown-future-source", setOf("centos"), true}, // 未登记 → 保守放行
	}
	for _, c := range cases {
		if got := sourceServesFleet(c.source, c.fleet); got != c.want {
			t.Errorf("sourceServesFleet(%q, %v) = %v, want %v", c.source, c.fleet, got, c.want)
		}
	}
}

func TestBuildAdvisorySources_FleetGated(t *testing.T) {
	// 全 RHEL fleet：只应启用 rhsa/rocky-apollo/centos，跳过 debian/ubuntu/alpine/信创
	got := sourceNames(t, nil, setOf("centos", "rocky"))
	for _, want := range []string{"rhsa", "rocky-apollo", "centos"} {
		if !contains(got, want) {
			t.Errorf("RHEL fleet 应启用 %q, got %v", want, got)
		}
	}
	for _, notWant := range []string{"debian-tracker", "usn", "alpine", "kylin-sa", "uos-sa"} {
		if contains(got, notWant) {
			t.Errorf("RHEL fleet 不应启用 %q, got %v", notWant, got)
		}
	}
}

func TestBuildAdvisorySources_EmptyFleetFallback(t *testing.T) {
	// fleet 查询失败(nil) → 不门控，启用全部（安全兜底）
	got := sourceNames(t, nil, nil)
	for _, want := range []string{"rhsa", "rocky-apollo", "centos", "debian-tracker", "usn", "alpine"} {
		if !contains(got, want) {
			t.Errorf("空 fleet 应兜底启用全部, 缺 %q, got %v", want, got)
		}
	}
}

func TestBuildAdvisorySources_ExplicitOverride(t *testing.T) {
	// 显式 -sources 覆盖优先于 fleet 门控
	got := sourceNames(t, setOf("debian-tracker"), setOf("centos"))
	if len(got) != 1 || got[0] != "debian-tracker" {
		t.Errorf("显式 -sources 应只启用 debian-tracker, got %v", got)
	}
}
