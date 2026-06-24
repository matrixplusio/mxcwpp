// Package api — Prometheus 告警 webhook 接收。
//
// 设计：
//   - Prometheus 触发告警后通过 webhook (alerting.alertmanagers 配置) POST 到此端点
//   - 入 alerts 表（source=prometheus_infra）复用 mxcwpp 现有告警系统
//   - 持久化 / 去重 / 状态机 / UI / notification 全部走现有路径，不重复造轮子
//
// 不部署 Alertmanager 的原因（避免组件重叠）：
//   - alerts 表已有 result_id 唯一索引 + hit_count（去重）
//   - notification 系统已有 Lark/Webhook 配置（路由）
//   - alert_scheduler 已有 30min repeat（重发）
//   - UI 已有列表/确认/趋势（展示）
package api

import (
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// PrometheusAlertsHandler 接收 Prometheus alerting webhook
type PrometheusAlertsHandler struct {
	db     *gorm.DB
	logger *zap.Logger
}

// NewPrometheusAlertsHandler 构造
func NewPrometheusAlertsHandler(db *gorm.DB, logger *zap.Logger) *PrometheusAlertsHandler {
	return &PrometheusAlertsHandler{db: db, logger: logger}
}

// promWebhookPayload 是 Prometheus alerting webhook 的标准 payload（兼容 Alertmanager 格式）。
// 文档：https://prometheus.io/docs/alerting/latest/configuration/#webhook_config
type promWebhookPayload struct {
	Version           string             `json:"version"`
	GroupKey          string             `json:"groupKey"`
	Status            string             `json:"status"` // firing | resolved
	Receiver          string             `json:"receiver"`
	GroupLabels       map[string]string  `json:"groupLabels"`
	CommonLabels      map[string]string  `json:"commonLabels"`
	CommonAnnotations map[string]string  `json:"commonAnnotations"`
	ExternalURL       string             `json:"externalURL"`
	Alerts            []promWebhookAlert `json:"alerts"`
}

type promWebhookAlert struct {
	Status       string            `json:"status"` // firing | resolved
	Labels       map[string]string `json:"labels"`
	Annotations  map[string]string `json:"annotations"`
	StartsAt     time.Time         `json:"startsAt"`
	EndsAt       time.Time         `json:"endsAt"`
	GeneratorURL string            `json:"generatorURL"`
	Fingerprint  string            `json:"fingerprint"`
}

// Ingest 处理 Prometheus 告警 webhook。
//
// POST /api/v1/internal/alerts/prometheus
//
// 行为：
//   - status=firing  → upsert alert 记录（status=active，命中次数+1）
//   - status=resolved → 更新 alert 记录 status=resolved + resolved_at
func (h *PrometheusAlertsHandler) Ingest(c *gin.Context) {
	var payload promWebhookPayload
	if err := c.ShouldBindJSON(&payload); err != nil {
		h.logger.Warn("Prometheus webhook payload 解析失败", zap.Error(err))
		BadRequest(c, "payload 解析失败")
		return
	}

	now := time.Now()
	firing, resolved := 0, 0
	for _, a := range payload.Alerts {
		if err := h.upsertAlert(a, now); err != nil {
			h.logger.Error("Prometheus 告警入库失败",
				zap.String("fingerprint", a.Fingerprint),
				zap.String("alertname", a.Labels["alertname"]),
				zap.Error(err))
			continue
		}
		if a.Status == "firing" {
			firing++
		} else {
			resolved++
		}
	}

	h.logger.Info("Prometheus 告警 webhook 处理完成",
		zap.Int("firing", firing),
		zap.Int("resolved", resolved),
		zap.String("receiver", payload.Receiver))

	Success(c, gin.H{
		"firing":   firing,
		"resolved": resolved,
	})
}

// upsertAlert 将单条 Prometheus 告警入 mxcwpp alerts 表。
//
// result_id 用 Prometheus fingerprint（保证去重 + 同一告警跨多次 webhook 命中累加）。
func (h *PrometheusAlertsHandler) upsertAlert(a promWebhookAlert, now time.Time) error {
	alertname := strings.TrimSpace(a.Labels["alertname"])
	if alertname == "" {
		alertname = "PrometheusAlert"
	}
	service := strings.TrimSpace(a.Labels["service"])
	if service == "" {
		service = strings.TrimSpace(a.Labels["job"])
	}
	severity := mapPromSeverity(a.Labels["severity"])
	title := alertname
	if service != "" {
		title = alertname + " (" + service + ")"
	}
	description := strings.TrimSpace(a.Annotations["description"])
	if description == "" {
		description = strings.TrimSpace(a.Annotations["summary"])
	}

	// fingerprint 作为 result_id（Prometheus 计算的稳定哈希）
	resultID := "prom:" + a.Fingerprint
	if a.Fingerprint == "" {
		resultID = "prom:" + alertname + ":" + service
	}

	// resolved 路径：更新已有记录
	if a.Status == "resolved" {
		nowLocal := model.LocalTime(now)
		return h.db.Model(&model.Alert{}).
			Where("result_id = ?", resultID).
			Updates(map[string]interface{}{
				"status":         model.AlertStatusResolved,
				"resolved_at":    &nowLocal,
				"resolve_reason": "Prometheus 告警已自动恢复",
			}).Error
	}

	// firing 路径：upsert（存在则 hit_count + 1 + last_seen_at 更新；不存在则 insert）
	var existing model.Alert
	err := h.db.Where("result_id = ?", resultID).First(&existing).Error
	if err == nil {
		// 已存在：累加命中
		return h.db.Model(&existing).Updates(map[string]interface{}{
			"hit_count":    existing.HitCount + 1,
			"last_seen_at": model.LocalTime(now),
			"status":       model.AlertStatusActive, // 若之前 resolved 又触发，恢复 active
			"resolved_at":  nil,
		}).Error
	}
	if err != gorm.ErrRecordNotFound {
		return err
	}

	// 新建
	alert := model.Alert{
		ResultID:    resultID,
		HostID:      "", // Prometheus 告警通常无 host 维度（基础设施）
		RuleID:      alertname,
		PolicyID:    "",
		Source:      model.AlertSourcePrometheusInfra,
		Severity:    severity,
		Category:    "infra",
		Title:       title,
		Description: description,
		Status:      model.AlertStatusActive,
		FirstSeenAt: model.LocalTime(a.StartsAt),
		LastSeenAt:  model.LocalTime(now),
		HitCount:    1,
	}
	if alert.FirstSeenAt == (model.LocalTime{}) {
		alert.FirstSeenAt = model.LocalTime(now)
	}
	return h.db.Create(&alert).Error
}

// mapPromSeverity 将 Prometheus severity label 映射到 mxcwpp alerts.severity。
func mapPromSeverity(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical", "fatal", "page":
		return "critical"
	case "warning", "warn":
		return "high" // mxcwpp 没有 warning，映射到 high
	case "info", "":
		return "low"
	default:
		return "low"
	}
}
