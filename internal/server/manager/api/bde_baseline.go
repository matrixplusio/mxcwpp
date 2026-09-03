package api

import (
	"encoding/json"
	"fmt"
	"math"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// bdeMetricKeys 与 engine/baseline MetricNames 顺序严格一致（MeanJSON/M2JSON 为该顺序的 [13]float64）
var bdeMetricKeys = [13]string{
	"proc_exec_count", "proc_unique_exe", "proc_fork_rate",
	"file_write_count", "file_unique_path", "file_sensitive_hits",
	"net_connect_count", "net_unique_ip", "net_unique_port", "net_external_ratio",
	"dns_query_count", "dns_unique_domain", "dns_nx_ratio",
}

// bdeMetricStat 单维行为画像：基线均值与标准差
type bdeMetricStat struct {
	Key    string  `json:"key"`
	Mean   float64 `json:"mean"`
	Stddev float64 `json:"stddev"`
}

// 学习毕业门槛，与 engine/baseline 引擎常量保持一致：
// 需同时满足 samples>=bdeMinSamples 且 距 first_seen>=bdeLearningPeriod。
const (
	bdeMinSamples     = 100
	bdeLearningPeriod = 7 * 24 * time.Hour
)

// baselineStateResp 在原始状态上附加学习进度，便于前端展示进度条与阻塞原因
type baselineStateResp struct {
	model.HostBaselineState
	RequiredMin    int             `json:"required_min"`
	SamplePct      float64         `json:"sample_pct"`
	TimePct        float64         `json:"time_pct"`
	ProgressPct    float64         `json:"progress_pct"`
	LearningEnds   model.LocalTime `json:"learning_ends"`
	BlockingReason string          `json:"blocking_reason"`
	Metrics        []bdeMetricStat `json:"metrics"` // 13 维学到的行为画像
}

// parseMetrics 从持久化的 MeanJSON/M2JSON 还原 13 维画像（mean ± stddev）
func parseMetrics(s model.HostBaselineState) []bdeMetricStat {
	var mean, m2 [13]float64
	_ = json.Unmarshal([]byte(s.MeanJSON), &mean)
	_ = json.Unmarshal([]byte(s.M2JSON), &m2)
	out := make([]bdeMetricStat, len(bdeMetricKeys))
	for i, key := range bdeMetricKeys {
		sd := 0.0
		if s.Samples >= 2 {
			sd = math.Sqrt(m2[i] / float64(s.Samples-1))
		}
		out[i] = bdeMetricStat{Key: key, Mean: mean[i], Stddev: sd}
	}
	return out
}

func clampPct(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return math.Round(v*10) / 10
}

// buildBaselineProgress 由 samples / first_seen 与门槛常量推导学习进度
func buildBaselineProgress(s model.HostBaselineState) baselineStateResp {
	firstSeen := s.FirstSeen.Time()
	learningEnds := firstSeen.Add(bdeLearningPeriod)
	samplePct := clampPct(float64(s.Samples) / float64(bdeMinSamples) * 100)
	timePct := clampPct(float64(time.Since(firstSeen)) / float64(bdeLearningPeriod) * 100)

	resp := baselineStateResp{
		HostBaselineState: s,
		RequiredMin:       bdeMinSamples,
		SamplePct:         samplePct,
		TimePct:           timePct,
		LearningEnds:      model.ToLocalTime(learningEnds),
		Metrics:           parseMetrics(s),
	}

	if s.Phase == "active" {
		resp.ProgressPct = 100
		return resp
	}

	// 学习中：两个门槛都要满足，进度取较小者
	resp.ProgressPct = math.Min(samplePct, timePct)
	samplesOk := s.Samples >= bdeMinSamples
	timeOk := time.Since(firstSeen) >= bdeLearningPeriod
	remainDays := max(int(math.Ceil(time.Until(learningEnds).Hours()/24)), 0)
	switch {
	case !samplesOk && !timeOk:
		resp.BlockingReason = fmt.Sprintf("样本不足 %d/%d，学习期未满（还需 %d 天）", s.Samples, bdeMinSamples, remainDays)
	case !samplesOk:
		resp.BlockingReason = fmt.Sprintf("样本不足 %d/%d", s.Samples, bdeMinSamples)
	case !timeOk:
		resp.BlockingReason = fmt.Sprintf("学习期未满，还需 %d 天", remainDays)
	}
	return resp
}

// BDEBaselineHandler BDE 基线管理 API 处理器
type BDEBaselineHandler struct {
	db     *gorm.DB
	logger *zap.Logger
}

// NewBDEBaselineHandler 创建 BDE 基线管理 API 处理器
func NewBDEBaselineHandler(db *gorm.DB, logger *zap.Logger) *BDEBaselineHandler {
	return &BDEBaselineHandler{db: db, logger: logger}
}

// ListBaselineStates 查看所有主机基线学习状态
func (h *BDEBaselineHandler) ListBaselineStates(c *gin.Context) {
	phase := c.Query("phase") // learning / active
	hostID := c.Query("host_id")

	var states []model.HostBaselineState
	query := h.db.Model(&model.HostBaselineState{})
	if phase != "" {
		query = query.Where("phase = ?", phase)
	}
	if hostID != "" {
		query = query.Where("host_id = ?", hostID)
	}
	query = query.Order("updated_at DESC")

	var total int64
	if err := query.Count(&total).Error; err != nil {
		InternalError(c, "查询基线状态失败")
		return
	}

	page, pageSize := ParsePagination(c)
	if err := query.Offset((page - 1) * pageSize).Limit(pageSize).Find(&states).Error; err != nil {
		InternalError(c, "查询基线状态失败")
		return
	}

	items := make([]baselineStateResp, 0, len(states))
	for _, s := range states {
		items = append(items, buildBaselineProgress(s))
	}

	SuccessPaginated(c, total, items)
}

// GetBaselineStats 基线引擎统计概览
func (h *BDEBaselineHandler) GetBaselineStats(c *gin.Context) {
	var totalHosts int64
	var learningHosts int64
	var activeHosts int64

	h.db.Model(&model.HostBaselineState{}).Count(&totalHosts)
	h.db.Model(&model.HostBaselineState{}).Where("phase = ?", "learning").Count(&learningHosts)
	h.db.Model(&model.HostBaselineState{}).Where("phase = ?", "active").Count(&activeHosts)

	var alertCount int64
	h.db.Model(&model.BehaviorAlert{}).Where("status = ?", "open").Count(&alertCount)

	Success(c, gin.H{
		"total_hosts":    totalHosts,
		"learning_hosts": learningHosts,
		"active_hosts":   activeHosts,
		"open_alerts":    alertCount,
	})
}

// ListBehaviorAlerts 查看行为异常告警列表
func (h *BDEBaselineHandler) ListBehaviorAlerts(c *gin.Context) {
	hostID := c.Query("host_id")
	status := c.Query("status")
	metric := c.Query("metric")

	query := h.db.Model(&model.BehaviorAlert{})
	if hostID != "" {
		query = query.Where("host_id = ?", hostID)
	}
	if status != "" {
		query = query.Where("status = ?", status)
	}
	if metric != "" {
		query = query.Where("metric = ?", metric)
	}
	query = query.Order("created_at DESC")

	var total int64
	if err := query.Count(&total).Error; err != nil {
		InternalError(c, "查询行为告警失败")
		return
	}

	page, pageSize := ParsePagination(c)
	var alerts []model.BehaviorAlert
	if err := query.Offset((page - 1) * pageSize).Limit(pageSize).Find(&alerts).Error; err != nil {
		InternalError(c, "查询行为告警失败")
		return
	}

	SuccessPaginated(c, total, alerts)
}
