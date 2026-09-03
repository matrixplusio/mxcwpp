package api

import (
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// KubeStatsHandler 容器安全统计 API Handler
type KubeStatsHandler struct {
	db     *gorm.DB
	logger *zap.Logger
}

// NewKubeStatsHandler 创建统计 Handler
func NewKubeStatsHandler(db *gorm.DB, logger *zap.Logger) *KubeStatsHandler {
	return &KubeStatsHandler{db: db, logger: logger}
}

// GetSummary 容器安全概览统计
func (h *KubeStatsHandler) GetSummary(c *gin.Context) {
	var clusterCount int64
	h.db.Model(&model.KubeCluster{}).Count(&clusterCount)

	var onlineCount int64
	h.db.Model(&model.KubeCluster{}).Where("status != ?", "offline").Count(&onlineCount)

	var pendingAlarms int64
	h.db.Model(&model.KubeAlarm{}).Where("status = ?", "pending").Count(&pendingAlarms)

	var criticalAlarms int64
	h.db.Model(&model.KubeAlarm{}).Where("status = ? AND severity = ?", "pending", "critical").Count(&criticalAlarms)

	var unhandledEvents int64
	h.db.Model(&model.KubeEvent{}).Where("status = ?", "unhandled").Count(&unhandledEvents)

	var baselineTotal, baselinePassed int64
	h.db.Model(&model.KubeBaseline{}).Count(&baselineTotal)
	h.db.Model(&model.KubeBaseline{}).Where("result = ?", "pass").Count(&baselinePassed)

	var passRate int
	if baselineTotal > 0 {
		passRate = int(baselinePassed * 100 / baselineTotal)
	}

	Success(c, gin.H{
		"clusters":         clusterCount,
		"onlineClusters":   onlineCount,
		"pendingAlarms":    pendingAlarms,
		"criticalAlarms":   criticalAlarms,
		"unhandledEvents":  unhandledEvents,
		"baselinePassRate": passRate,
	})
}

// GetAlarmTrend 告警趋势（最近 N 天每天的告警数量）
func (h *KubeStatsHandler) GetAlarmTrend(c *gin.Context) {
	days, _ := strconv.Atoi(c.DefaultQuery("days", "7"))
	if days <= 0 || days > 90 {
		days = 7
	}
	clusterID := c.Query("cluster_id")

	type DayStat struct {
		Date     string `json:"date"`
		Critical int    `json:"critical"`
		High     int    `json:"high"`
		Medium   int    `json:"medium"`
		Low      int    `json:"low"`
	}

	result := make([]DayStat, 0, days)

	for i := 0; i < days; i++ {
		date := time.Now().AddDate(0, 0, -days+1+i)
		dateStr := date.Format("2006-01-02")
		dayStart := dateStr + " 00:00:00"
		dayEnd := dateStr + " 23:59:59"

		stat := DayStat{Date: dateStr}
		baseQ := func() *gorm.DB {
			q := h.db.Model(&model.KubeAlarm{}).Where("created_at BETWEEN ? AND ?", dayStart, dayEnd)
			if clusterID != "" {
				q = q.Where("cluster_id = ?", clusterID)
			}
			return q
		}

		var critical, high, medium, low int64
		baseQ().Where("severity = ?", "critical").Count(&critical)
		baseQ().Where("severity = ?", "high").Count(&high)
		baseQ().Where("severity = ?", "medium").Count(&medium)
		baseQ().Where("severity = ?", "low").Count(&low)
		stat.Critical = int(critical)
		stat.High = int(high)
		stat.Medium = int(medium)
		stat.Low = int(low)

		result = append(result, stat)
	}

	Success(c, gin.H{"items": result, "days": days})
}
