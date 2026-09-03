package notify

import "testing"

func TestHostTagsMatch(t *testing.T) {
	cases := []struct {
		name         string
		hostTags     []string
		requiredTags []string
		want         bool
	}{
		{
			name:         "命中任一标签即匹配(OR)",
			hostTags:     []string{"prod", "linux"},
			requiredTags: []string{"windows", "prod"},
			want:         true,
		},
		{
			name:         "无交集不匹配",
			hostTags:     []string{"prod", "linux"},
			requiredTags: []string{"windows", "staging"},
			want:         false,
		},
		{
			name:         "配置标签为空不匹配(避免退化为全量分发)",
			hostTags:     []string{"prod"},
			requiredTags: nil,
			want:         false,
		},
		{
			name:         "主机无标签不匹配",
			hostTags:     nil,
			requiredTags: []string{"prod"},
			want:         false,
		},
		{
			name:         "完全一致",
			hostTags:     []string{"db"},
			requiredTags: []string{"db"},
			want:         true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := hostTagsMatch(c.hostTags, c.requiredTags); got != c.want {
				t.Errorf("hostTagsMatch(%v,%v)=%v want %v", c.hostTags, c.requiredTags, got, c.want)
			}
		})
	}
}
