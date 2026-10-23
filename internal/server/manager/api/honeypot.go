// Package api — Honeypot 蜜罐 HTTP handler (C1).
//
// 后端架构:
//   - HoneypotPolicy: 诱饵投放策略表
//   - HoneypotDeploymentRecord: Agent 实际投放的诱饵记录
//   - alerts (source=honeypot): 命中告警
//
// UI 概念映射:
//   - sensor   = 一条已部署的诱饵 (聚合自 HoneypotDeploymentRecord)
//   - event    = honeypot 告警 (alerts 表过滤)
package api

import (
	"strconv"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

type HoneypotHandler struct {
	db     *gorm.DB
	logger *zap.Logger
}

func NewHoneypotHandler(db *gorm.DB, logger *zap.Logger) *HoneypotHandler {
	return &HoneypotHandler{db: db, logger: logger}
}

type honeypotSensorView struct {
	ID        string `json:"id"`
	HostID    string `json:"host_id"`
	Hostname  string `json:"hostname"`
	Kind      string `json:"kind"`
	BindAddr  string `json:"bind_addr"`
	Status    string `json:"status"`
	Hits24h   int    `json:"hits_24h"`
	StartedAt string `json:"started_at"`
}

// ListSensors 列出诱饵传感器 (聚合 HoneypotDeploymentRecord).
// GET /api/v1/v2/honeypot/sensors
func (h *HoneypotHandler) ListSensors(c *gin.Context) {
	tid, _ := c.Get("tenant_id")
	tenantID, _ := tid.(string)
	if tenantID == "" {
		tenantID = model.DefaultTenantID
	}

	var rows []model.HoneypotDeploymentRecord
	q := h.db.WithContext(c.Request.Context()).Where("tenant_id = ?", tenantID).Order("deployed_at DESC").Limit(200)
	if err := q.Find(&rows).Error; err != nil {
		h.logger.Error("list honeypot deployments failed", zap.Error(err))
		InternalError(c, "查询失败")
		return
	}

	items := make([]honeypotSensorView, 0, len(rows))
	for _, r := range rows {
		items = append(items, honeypotSensorView{
			ID:        strconv.FormatUint(uint64(r.ID), 10),
			HostID:    r.HostID,
			Hostname:  r.HostID, // hostname 关联另查; 简洁起见暂回 host_id, UI 已在 hosts 接口拿名
			Kind:      r.DecoyKind,
			BindAddr:  r.DecoyPath,
			Status:    "running",
			Hits24h:   r.TriggerCount,
			StartedAt: r.DeployedAt.String(),
		})
	}
	Success(c, gin.H{"items": items, "total": len(items)})
}

type honeypotEventView struct {
	ID        uint64 `json:"id"`
	SensorID  string `json:"sensor_id"`
	Kind      string `json:"kind"`
	SrcIP     string `json:"src_ip"`
	SrcPort   int    `json:"src_port"`
	Username  string `json:"username"`
	Password  string `json:"password"`
	UserAgent string `json:"user_agent"`
	Method    string `json:"method"`
	Path      string `json:"path"`
	Severity  string `json:"severity"`
	Time      string `json:"time"`
}

// ListEvents 列出蜜罐告警 (alerts 表 source=honeypot).
// GET /api/v1/v2/honeypot/events
func (h *HoneypotHandler) ListEvents(c *gin.Context) {
	tid, _ := c.Get("tenant_id")
	tenantID, _ := tid.(string)
	if tenantID == "" {
		tenantID = model.DefaultTenantID
	}

	var rows []model.Alert
	q := h.db.WithContext(c.Request.Context()).
		Where("tenant_id = ?", tenantID).
		Where("source = ? OR category = ?", "honeypot", "honeypot").
		Order("last_seen_at DESC").
		Limit(200)
	if err := q.Find(&rows).Error; err != nil {
		h.logger.Error("list honeypot events failed", zap.Error(err))
		InternalError(c, "查询失败")
		return
	}

	items := make([]honeypotEventView, 0, len(rows))
	for _, r := range rows {
		items = append(items, honeypotEventView{
			ID:       uint64(r.ID),
			SensorID: "",
			Kind:     r.Category,
			SrcIP:    "",
			Severity: r.Severity,
			Time:     r.LastSeenAt.String(),
		})
	}
	Success(c, gin.H{"items": items, "total": len(items)})
}

// CreateSensorReq 部署诱饵请求.
type CreateSensorReq struct {
	HostID   string `json:"host_id" binding:"required"`
	Kind     string `json:"kind" binding:"required"` // ssh | http | file_decoy
	BindAddr string `json:"bind_addr"`
}

// CreateSensor 创建/部署一个诱饵 (写 deployment 记录).
// POST /api/v1/v2/honeypot/sensors
func (h *HoneypotHandler) CreateSensor(c *gin.Context) {
	tid, _ := c.Get("tenant_id")
	tenantID, _ := tid.(string)
	if tenantID == "" {
		tenantID = model.DefaultTenantID
	}

	var req CreateSensorReq
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "请求参数错误")
		return
	}

	row := model.HoneypotDeploymentRecord{
		TenantID:  tenantID,
		HostID:    req.HostID,
		DecoyKind: req.Kind,
		DecoyPath: req.BindAddr,
	}
	if err := h.db.WithContext(c.Request.Context()).Create(&row).Error; err != nil {
		h.logger.Error("create honeypot sensor failed", zap.Error(err))
		InternalError(c, "部署失败")
		return
	}
	Success(c, gin.H{"id": row.ID})
}

// StopSensor 停止一个诱饵 (删除 deployment 记录).
// POST /api/v1/v2/honeypot/sensors/:id/stop
func (h *HoneypotHandler) StopSensor(c *gin.Context) {
	tid, _ := c.Get("tenant_id")
	tenantID, _ := tid.(string)
	if tenantID == "" {
		tenantID = model.DefaultTenantID
	}
	id := c.Param("id")
	if err := h.db.WithContext(c.Request.Context()).
		Where("tenant_id = ? AND id = ?", tenantID, id).
		Delete(&model.HoneypotDeploymentRecord{}).Error; err != nil {
		h.logger.Error("stop honeypot sensor failed", zap.Error(err))
		InternalError(c, "停止失败")
		return
	}
	Success(c, gin.H{"id": id, "status": "stopped"})
}
