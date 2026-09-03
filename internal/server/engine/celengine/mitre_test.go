package celengine

import (
	"strings"
	"testing"
)

// TestTacticFromTechnique 校验技术→战术映射:base 查表、子技术剥离、逗号取首、未知/空回退空。
func TestTacticFromTechnique(t *testing.T) {
	cases := map[string]string{
		"T1071":       "TA0011", // base 命中
		"T1059.004":   "TA0002", // 子技术剥离到 base
		"T1003.001":   "TA0006", // 子技术
		"T1046":       "TA0007", // 端口扫描
		"T1071,T1090": "TA0011", // 逗号分隔取首个
		" T1548 ":     "TA0004", // 首尾空白
		"T9999":       "",       // 未知技术 → 空(宁缺勿错)
		"":            "",       // 空输入
		"garbage":     "",       // 非技术 ID
	}
	for in, want := range cases {
		if got := tacticFromTechnique(in); got != want {
			t.Errorf("tacticFromTechnique(%q)=%q, want %q", in, got, want)
		}
	}
}

// TestTechniqueTacticValid 校验映射表所有战术值都是合法 TA-id(与 incident_correlation 的
// attckTacticOrder 口径一致),防手滑填错格式。
func TestTechniqueTacticValid(t *testing.T) {
	valid := map[string]bool{
		"TA0001": true, "TA0002": true, "TA0003": true, "TA0004": true,
		"TA0005": true, "TA0006": true, "TA0007": true, "TA0008": true,
		"TA0009": true, "TA0010": true, "TA0011": true, "TA0040": true,
	}
	for tech, tactic := range techniqueTactic {
		if !strings.HasPrefix(tech, "T") {
			t.Errorf("技术 key %q 不是 T 开头", tech)
		}
		if !valid[tactic] {
			t.Errorf("技术 %q 的战术 %q 不是合法 TA-id", tech, tactic)
		}
	}
}
