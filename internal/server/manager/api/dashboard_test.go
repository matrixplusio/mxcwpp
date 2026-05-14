package api

import (
	"math"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestSanitizeDashboardValue(t *testing.T) {
	input := gin.H{
		"avgCpuUsage":    math.NaN(),
		"avgMemoryUsage": math.Inf(1),
		"baseline": gin.H{
			"percent": math.Inf(-1),
		},
		"baselineRisks": []gin.H{
			{"score": math.NaN()},
			{"score": 42.5},
		},
	}

	sanitized := sanitizeDashboardValue(input).(gin.H)

	if got := sanitized["avgCpuUsage"].(float64); got != 0 {
		t.Fatalf("avgCpuUsage = %v, want 0", got)
	}
	if got := sanitized["avgMemoryUsage"].(float64); got != 0 {
		t.Fatalf("avgMemoryUsage = %v, want 0", got)
	}

	baseline := sanitized["baseline"].(gin.H)
	if got := baseline["percent"].(float64); got != 0 {
		t.Fatalf("baseline.percent = %v, want 0", got)
	}

	baselineRisks := sanitized["baselineRisks"].([]gin.H)
	if got := baselineRisks[0]["score"].(float64); got != 0 {
		t.Fatalf("baselineRisks[0].score = %v, want 0", got)
	}
	if got := baselineRisks[1]["score"].(float64); got != 42.5 {
		t.Fatalf("baselineRisks[1].score = %v, want 42.5", got)
	}
}
