package scheduler

import "testing"

func TestExtractExeBasename(t *testing.T) {
	cases := []struct {
		name   string
		actual string
		want   string
	}{
		{"exe 全路径取 basename", `{"exe":"/usr/sbin/nginx","dst_ip":"8.8.8.8"}`, "nginx"},
		{"exe 缺失回退 comm", `{"comm":"node_exporter"}`, "node_exporter"},
		{"无 exe/comm", `{"dst_ip":"1.2.3.4"}`, ""},
		{"空串", ``, ""},
		{"非法 JSON", `{not json`, ""},
		{"exe 空白被裁剪", `{"exe":"   "}`, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := extractExeBasename(c.actual); got != c.want {
				t.Fatalf("extractExeBasename(%q) = %q, want %q", c.actual, got, c.want)
			}
		})
	}
}
