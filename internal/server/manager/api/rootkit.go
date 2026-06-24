// Package api — Rootkit / DKOM 检测 HTTP handler (C2).
package api

import (
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

type RootkitHandler struct {
	db     *gorm.DB
	logger *zap.Logger
}

func NewRootkitHandler(db *gorm.DB, logger *zap.Logger) *RootkitHandler {
	return &RootkitHandler{db: db, logger: logger}
}

// ListFindings GET /api/v1/rootkit/findings.
func (h *RootkitHandler) ListFindings(c *gin.Context) {
	tid, _ := c.Get("tenant_id")
	tenantID, _ := tid.(string)
	if tenantID == "" {
		tenantID = model.DefaultTenantID
	}

	hostID := c.Query("host_id")
	status := c.Query("status")

	q := h.db.WithContext(c.Request.Context()).Model(&model.RootkitFinding{}).Where("tenant_id = ?", tenantID)
	if hostID != "" {
		q = q.Where("host_id = ?", hostID)
	}
	if status != "" {
		q = q.Where("status = ?", status)
	}
	var total int64
	if err := q.Count(&total).Error; err != nil {
		h.logger.Error("count rootkit findings failed", zap.Error(err))
		InternalError(c, "查询失败")
		return
	}
	var rows []model.RootkitFinding
	if err := q.Order("detected_at DESC").Limit(200).Find(&rows).Error; err != nil {
		h.logger.Error("list rootkit findings failed", zap.Error(err))
		InternalError(c, "查询失败")
		return
	}
	Success(c, gin.H{"items": rows, "total": total})
}

// TriggerScanReq POST /api/v1/rootkit/scan.
type TriggerScanReq struct {
	HostID string `json:"host_id" binding:"required"`
}

type rootkitScanResult struct {
	HostID           string   `json:"host_id"`
	HiddenPIDs       []int    `json:"hidden_pids"`
	HiddenModules    []string `json:"hidden_modules"`
	HiddenPorts      []int    `json:"hidden_ports"`
	PreloadAnomalies []string `json:"preload_anomalies"`
	ProcDirMismatch  int      `json:"proc_dir_mismatch"`
	Warnings         []string `json:"warnings"`
	ScannedAt        string   `json:"scanned_at"`
}

// TriggerScan 下发一次扫描 (异步, 完成后 Agent 上报落 RootkitFinding 表).
//
// 注: 实际下发通道在 v2.2 接入 ACDispatcher; 当前返回 accepted + 最新一次扫描快照.
// POST /api/v1/rootkit/scan
func (h *RootkitHandler) TriggerScan(c *gin.Context) {
	tid, _ := c.Get("tenant_id")
	tenantID, _ := tid.(string)
	if tenantID == "" {
		tenantID = model.DefaultTenantID
	}

	var req TriggerScanReq
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "请求参数错误")
		return
	}

	var rows []model.RootkitFinding
	if err := h.db.WithContext(c.Request.Context()).
		Where("tenant_id = ? AND host_id = ?", tenantID, req.HostID).
		Order("detected_at DESC").
		Limit(50).
		Find(&rows).Error; err != nil {
		h.logger.Error("query rootkit findings failed", zap.Error(err))
		InternalError(c, "查询失败")
		return
	}

	res := rootkitScanResult{HostID: req.HostID}
	for _, r := range rows {
		switch r.Kind {
		case "hidden_pid":
			if r.PID > 0 {
				res.HiddenPIDs = append(res.HiddenPIDs, r.PID)
			}
		case "hidden_module":
			if r.ModuleName != "" {
				res.HiddenModules = append(res.HiddenModules, r.ModuleName)
			}
		case "preload_anomaly":
			res.PreloadAnomalies = append(res.PreloadAnomalies, r.Detail)
		case "proc_dir_mismatch":
			res.ProcDirMismatch++
		}
	}
	res.ScannedAt = "snapshot"
	if len(rows) == 0 {
		res.Warnings = []string{"暂无扫描数据 (Agent 尚未上报或主机不存在 rootkit 异常)"}
	}
	Success(c, res)
}

// ResolveReq POST /api/v1/rootkit/findings/:id/resolve.
type ResolveReq struct {
	Note string `json:"note"`
}

// Resolve 标记一条 finding 为已处理.
func (h *RootkitHandler) Resolve(c *gin.Context) {
	tid, _ := c.Get("tenant_id")
	tenantID, _ := tid.(string)
	if tenantID == "" {
		tenantID = model.DefaultTenantID
	}
	id := c.Param("id")
	user, _ := c.Get("username")
	username, _ := user.(string)

	var req ResolveReq
	_ = c.ShouldBindJSON(&req)

	if err := h.db.WithContext(c.Request.Context()).
		Model(&model.RootkitFinding{}).
		Where("tenant_id = ? AND id = ?", tenantID, id).
		Updates(map[string]any{
			"status":       "resolved",
			"resolved_by":  username,
			"resolve_note": req.Note,
		}).Error; err != nil {
		h.logger.Error("resolve rootkit finding failed", zap.Error(err))
		InternalError(c, "更新失败")
		return
	}
	Success(c, gin.H{"id": id, "status": "resolved"})
}
