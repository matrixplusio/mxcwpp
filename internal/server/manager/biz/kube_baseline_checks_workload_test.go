package biz

import "testing"

// TestLabelsMatch 验证 PDB selector 子集匹配逻辑
func TestLabelsMatch(t *testing.T) {
	tests := []struct {
		name      string
		pdbLabels map[string]string
		depLabels map[string]string
		want      bool
	}{
		{
			"完全匹配",
			map[string]string{"app": "nginx"},
			map[string]string{"app": "nginx"},
			true,
		},
		{
			"PDB 是子集",
			map[string]string{"app": "nginx"},
			map[string]string{"app": "nginx", "env": "prod"},
			true,
		},
		{
			"PDB 标签值不同",
			map[string]string{"app": "nginx"},
			map[string]string{"app": "redis"},
			false,
		},
		{
			"PDB 标签 key 不在 dep 中",
			map[string]string{"app": "nginx", "tier": "frontend"},
			map[string]string{"app": "nginx"},
			false,
		},
		{
			"空 PDB 标签",
			map[string]string{},
			map[string]string{"app": "nginx"},
			false,
		},
		{
			"nil PDB 标签",
			nil,
			map[string]string{"app": "nginx"},
			false,
		},
		{
			"两者都为空",
			map[string]string{},
			map[string]string{},
			false,
		},
		{
			"dep 标签为空但 PDB 有值",
			map[string]string{"app": "nginx"},
			map[string]string{},
			false,
		},
		{
			"多标签完全匹配",
			map[string]string{"app": "nginx", "env": "prod"},
			map[string]string{"app": "nginx", "env": "prod", "team": "platform"},
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := labelsMatch(tt.pdbLabels, tt.depLabels)
			if got != tt.want {
				t.Fatalf("labelsMatch(%v, %v) = %v, want %v", tt.pdbLabels, tt.depLabels, got, tt.want)
			}
		})
	}
}
