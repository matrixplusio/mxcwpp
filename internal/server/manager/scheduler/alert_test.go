package scheduler

import "testing"

func TestHostTagsMatchAny(t *testing.T) {
	cases := []struct {
		name         string
		hostTags     []string
		requiredTags []string
		want         bool
	}{
		{"命中任一(OR)", []string{"prod", "linux"}, []string{"db", "prod"}, true},
		{"无交集", []string{"prod"}, []string{"staging"}, false},
		{"配置为空不匹配", []string{"prod"}, nil, false},
		{"主机无标签", nil, []string{"prod"}, false},
		{"完全一致", []string{"db"}, []string{"db"}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := hostTagsMatchAny(c.hostTags, c.requiredTags); got != c.want {
				t.Errorf("hostTagsMatchAny(%v,%v)=%v want %v", c.hostTags, c.requiredTags, got, c.want)
			}
		})
	}
}
