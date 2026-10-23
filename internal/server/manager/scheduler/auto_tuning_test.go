package scheduler

import "testing"

func TestExtractExePath(t *testing.T) {
	cases := []struct {
		name   string
		actual string
		want   string
	}{
		{"exe 全路径原样保留", `{"exe":"/usr/sbin/nginx","dst_ip":"8.8.8.8"}`, "/usr/sbin/nginx"},
		{"只有 comm 不提建议", `{"comm":"node_exporter"}`, ""},
		{"exe 不是路径不提建议", `{"exe":"nginx"}`, ""},
		{"无 exe/comm", `{"dst_ip":"1.2.3.4"}`, ""},
		{"空串", ``, ""},
		{"非法 JSON", `{not json`, ""},
		{"exe 空白被裁剪", `{"exe":"   "}`, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := extractExePath(c.actual); got != c.want {
				t.Fatalf("extractExePath(%q) = %q, want %q", c.actual, got, c.want)
			}
		})
	}
}
