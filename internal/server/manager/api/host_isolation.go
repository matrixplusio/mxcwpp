package api

import (
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/gorm"

	grpcProto "github.com/matrixplusio/mxcwpp/api/proto/grpc"
	"github.com/matrixplusio/mxcwpp/internal/server/manager/sd"
	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// HostIsolationHandler handles host network isolation API requests.
type HostIsolationHandler struct {
	db           *gorm.DB
	logger       *zap.Logger
	acDispatcher *sd.ACDispatcher
}

// NewHostIsolationHandler creates a new host isolation handler.
func NewHostIsolationHandler(db *gorm.DB, logger *zap.Logger, acDispatcher *sd.ACDispatcher) *HostIsolationHandler {
	return &HostIsolationHandler{db: db, logger: logger, acDispatcher: acDispatcher}
}

type isolateHostReq struct {
	HostID  string `json:"host_id" binding:"required"`
	Level   string `json:"level"`   // standard (default) / complete
	Reason  string `json:"reason"`  // isolation reason
	Timeout int    `json:"timeout"` // timeout in seconds (default 14400 = 4h)
}

// IsolateHost enables network isolation on a host.
// POST /api/v1/hosts/isolate
func (h *HostIsolationHandler) IsolateHost(c *gin.Context) {
	var req isolateHostReq
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "参数错误")
		return
	}

	if req.Level == "" {
		req.Level = "standard"
	}
	if req.Level != "standard" && req.Level != "complete" {
		BadRequest(c, "隔离级别必须是 standard 或 complete")
		return
	}
	if req.Timeout <= 0 {
		req.Timeout = 14400 // 4 hours default
	}

	// Check host exists.
	var host model.Host
	if err := h.db.Where("host_id = ?", req.HostID).First(&host).Error; err != nil {
		NotFound(c, "主机不存在")
		return
	}

	// Check for existing active isolation.
	var existing model.HostIsolation
	if err := h.db.Where("host_id = ? AND status = ?", req.HostID, "active").First(&existing).Error; err == nil {
		BadRequest(c, fmt.Sprintf("主机已处于隔离状态 (level=%s)", existing.Level))
		return
	}

	username, _ := c.Get("username")
	now := model.Now()

	record := model.HostIsolation{
		HostID:     req.HostID,
		Hostname:   host.Hostname,
		Level:      req.Level,
		Reason:     req.Reason,
		Timeout:    req.Timeout,
		Status:     "active",
		Source:     "manual",
		CreatedBy:  fmt.Sprintf("%v", username),
		IsolatedAt: &now,
	}

	if err := h.db.Create(&record).Error; err != nil {
		h.logger.Error("创建隔离记录失败", zap.Error(err))
		InternalError(c, "创建隔离记录失败")
		return
	}

	// Dispatch isolation command to Agent via AC.
	if err := h.dispatchIsolateCommand(req.HostID, req.Level, req.Reason, req.Timeout); err != nil {
		h.logger.Error("下发隔离命令失败", zap.Error(err))
		h.db.Model(&record).Update("status", "failed")
		InternalError(c, "下发隔离命令失败: "+err.Error())
		return
	}

	h.logger.Warn("主机隔离命令已下发",
		zap.String("host_id", req.HostID),
		zap.String("level", req.Level),
		zap.String("reason", req.Reason))

	Success(c, record)
}

type releaseHostReq struct {
	HostID string `json:"host_id" binding:"required"`
	Reason string `json:"reason"`
}

// ReleaseHost removes network isolation from a host.
// POST /api/v1/hosts/release
func (h *HostIsolationHandler) ReleaseHost(c *gin.Context) {
	var req releaseHostReq
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "参数错误")
		return
	}

	var record model.HostIsolation
	if err := h.db.Where("host_id = ? AND status = ?", req.HostID, "active").First(&record).Error; err != nil {
		NotFound(c, "主机不在隔离状态")
		return
	}

	username, _ := c.Get("username")
	now := model.Now()

	record.Status = "released"
	record.ReleasedAt = &now
	record.ReleasedBy = fmt.Sprintf("%v", username)
	h.db.Save(&record)

	// Dispatch release command to Agent.
	if err := h.dispatchReleaseCommand(req.HostID, req.Reason); err != nil {
		h.logger.Error("下发解除隔离命令失败", zap.Error(err))
		// Don't revert — the DB record is updated, AC may retry.
	}

	h.logger.Warn("主机隔离解除命令已下发",
		zap.String("host_id", req.HostID),
		zap.String("reason", req.Reason))

	Success(c, record)
}

// GetIsolationStatus returns the isolation status of a host.
// GET /api/v1/hosts/:host_id/isolation-status
func (h *HostIsolationHandler) GetIsolationStatus(c *gin.Context) {
	hostID := c.Param("host_id")

	var record model.HostIsolation
	err := h.db.Where("host_id = ? AND status = ?", hostID, "active").First(&record).Error

	if err != nil {
		// No active isolation.
		Success(c, gin.H{
			"isolated": false,
			"level":    "none",
		})
		return
	}

	Success(c, gin.H{
		"isolated":    true,
		"level":       record.Level,
		"reason":      record.Reason,
		"timeout":     record.Timeout,
		"isolated_at": record.IsolatedAt,
		"source":      record.Source,
		"created_by":  record.CreatedBy,
	})
}

// ListIsolations returns all isolation records with pagination.
// GET /api/v1/hosts/isolations?status=active&page=1&page_size=20
func (h *HostIsolationHandler) ListIsolations(c *gin.Context) {
	status := c.Query("status")
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}

	q := h.db.Model(&model.HostIsolation{})
	if status != "" {
		q = q.Where("status = ?", status)
	}

	var total int64
	q.Count(&total)

	var records []model.HostIsolation
	if err := q.Order("id DESC").Offset((page - 1) * pageSize).Limit(pageSize).Find(&records).Error; err != nil {
		InternalError(c, "查询失败")
		return
	}

	Success(c, PaginatedData{Total: total, Items: records})
}

// --- Command dispatch ---

func (h *HostIsolationHandler) dispatchIsolateCommand(hostID, level, reason string, timeout int) error {
	if h.acDispatcher == nil {
		h.logger.Warn("隔离命令未下发: AC dispatcher 未初始化")
		return nil
	}

	taskData := map[string]any{
		"action":  "isolate",
		"level":   level,
		"reason":  reason,
		"timeout": timeout,
	}
	taskJSON, _ := json.Marshal(taskData)

	cmd := &grpcProto.Command{
		Tasks: []*grpcProto.Task{{
			DataType:   9997,
			ObjectName: "edr",
			Data:       string(taskJSON),
		}},
	}

	return h.acDispatcher.SendCommand(hostID, cmd)
}

func (h *HostIsolationHandler) dispatchReleaseCommand(hostID, reason string) error {
	if h.acDispatcher == nil {
		return nil
	}

	taskData := map[string]any{
		"action": "release",
		"reason": reason,
	}
	taskJSON, _ := json.Marshal(taskData)

	cmd := &grpcProto.Command{
		Tasks: []*grpcProto.Task{{
			DataType:   9997,
			ObjectName: "edr",
			Data:       string(taskJSON),
		}},
	}

	return h.acDispatcher.SendCommand(hostID, cmd)
}
