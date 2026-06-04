package handlers

import (
	"testing"
)

func TestIsAllDigits(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"", false},
		{"1", true},
		{"12345", true},
		{"123a", false},
		{"a123", false},
		{"abc", false},
		{"0", true},
	}
	for _, c := range cases {
		if got := isAllDigits(c.in); got != c.want {
			t.Errorf("isAllDigits(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestStripProcRootPrefix(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"/proc/1234/root/usr/bin/nginx", "/usr/bin/nginx"},
		{"/proc/9/root/bin/sh", "/bin/sh"},
		{"/usr/bin/nginx", "/usr/bin/nginx"},     // 非 /proc 前缀原样返回
		{"/proc/abc/root/x", "/proc/abc/root/x"}, // pid 非数字原样返回
		{"/proc/123/cwd", "/proc/123/cwd"},       // 非 root/ 子路径原样返回
		{"/proc/1/root", "/proc/1/root"},         // 仅 root 无后缀原样返回（stripped == ""）
		{"/proc/1/root/", "/"},                   // root/ 仅一斜杠尾
	}
	for _, c := range cases {
		if got := stripProcRootPrefix(c.in); got != c.want {
			t.Errorf("stripProcRootPrefix(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestFilterRunningJobs_HitByPath(t *testing.T) {
	jobs := []probeJob{
		{probe: BinaryProbe{Name: "nginx"}, binaryPath: "/usr/local/nginx/sbin/nginx"},
		{probe: BinaryProbe{Name: "redis"}, binaryPath: "/opt/redis/bin/redis-server"},
	}
	paths := map[string]struct{}{
		"/usr/local/nginx/sbin/nginx": {},
	}
	bases := map[string]struct{}{}

	got := filterRunningJobs(jobs, paths, bases)
	if len(got) != 1 || got[0].probe.Name != "nginx" {
		t.Errorf("path-hit gate failed: got %#v", got)
	}
}

func TestFilterRunningJobs_HitByBasename(t *testing.T) {
	// 探针扫 /opt/openresty/bin/nginx，实际进程 exe 是
	// /usr/local/openresty/nginx/sbin/nginx —— 路径不同 basename 相同应命中
	jobs := []probeJob{
		{probe: BinaryProbe{Name: "openresty"}, binaryPath: "/opt/openresty/bin/nginx"},
	}
	paths := map[string]struct{}{
		"/usr/local/openresty/nginx/sbin/nginx": {},
	}
	bases := map[string]struct{}{
		"nginx": {},
	}

	got := filterRunningJobs(jobs, paths, bases)
	if len(got) != 1 {
		t.Errorf("basename gate failed: got %d jobs", len(got))
	}
}

func TestFilterRunningJobs_KafkaBypass(t *testing.T) {
	// Kafka 启动脚本拉起 JVM，/proc 看不到 kafka-server-start.sh 本身在跑
	// 探针对 kafka 应允许通过 running gate，靠 detectKafkaVersion 解析 jar
	jobs := []probeJob{
		{probe: BinaryProbe{Name: "kafka"}, binaryPath: "/opt/kafka/bin/kafka-server-start.sh"},
		{probe: BinaryProbe{Name: "nginx"}, binaryPath: "/opt/nginx/sbin/nginx"},
	}
	// 完全空的运行集
	got := filterRunningJobs(jobs, map[string]struct{}{}, map[string]struct{}{})
	if len(got) != 0 {
		t.Errorf("empty running set should return empty (kafka bypass needs non-empty running set guard): got %#v", got)
	}

	// 至少有一个其他运行进程触发 kafka 特判通路
	bases := map[string]struct{}{"java": {}}
	got = filterRunningJobs(jobs, map[string]struct{}{}, bases)
	if len(got) != 1 || got[0].probe.Name != "kafka" {
		t.Errorf("kafka bypass failed, expected only kafka: got %#v", got)
	}
}

func TestFilterRunningJobs_NoneRunning(t *testing.T) {
	jobs := []probeJob{
		{probe: BinaryProbe{Name: "nginx"}, binaryPath: "/opt/nginx/sbin/nginx"},
	}
	// 完全空的 running set → 整体跳过
	got := filterRunningJobs(jobs, map[string]struct{}{}, map[string]struct{}{})
	if got != nil {
		t.Errorf("empty running set should return nil, got %#v", got)
	}
}
