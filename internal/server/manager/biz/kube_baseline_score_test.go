package biz

import (
	"testing"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

func r(severity, result string) model.KubeBaseline {
	return model.KubeBaseline{Severity: severity, Result: result}
}

func TestWeightedComplianceScore(t *testing.T) {
	cases := []struct {
		name    string
		results []model.KubeBaseline
		want    int
	}{
		{"empty", nil, 100},
		{"all pass", []model.KubeBaseline{r("critical", "pass"), r("low", "pass")}, 100},
		{"all fail", []model.KubeBaseline{r("critical", "fail"), r("low", "fail")}, 0},
		// critical 失败惩罚远重于 low：1 critical(10) fail + 1 low(1) pass => 1/11
		{"critical fail dominates", []model.KubeBaseline{r("critical", "fail"), r("low", "pass")}, 9},
		// 反过来 low fail 影响小：critical(10) pass + low(1) fail => 10/11
		{"low fail minor", []model.KubeBaseline{r("critical", "pass"), r("low", "fail")}, 90},
		// error 计入分母不计分子（视为未通过）
		{"error counts as not-pass", []model.KubeBaseline{r("high", "pass"), r("high", "error")}, 50},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := weightedComplianceScore(tc.results); got != tc.want {
				t.Errorf("weightedComplianceScore = %d, want %d", got, tc.want)
			}
		})
	}
}
