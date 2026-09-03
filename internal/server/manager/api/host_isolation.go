package api

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/manager/sd"
	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// HostIsolationHandler handles host network isolation API requests.
type HostIsolationHandler struct {
	db           *gorm.DB
	logger       *zap.Logger
	acDispatcher *sd.ACDispatcher
	responses    *ResponseActionHandler
}

// NewHostIsolationHandler creates a new host isolation handler.
func NewHostIsolationHandler(db *gorm.DB, logger *zap.Logger, acDispatcher *sd.ACDispatcher) *HostIsolationHandler {
	return &HostIsolationHandler{
		db: db, logger: logger, acDispatcher: acDispatcher,
		responses: NewResponseActionHandler(db, logger, acDispatcher),
	}
}

type isolateHostReq struct {
	HostID  string `json:"host_id" binding:"required"`
	Level   string `json:"level"`   // standard (default) / complete
	Reason  string `json:"reason"`  // 隔离理由，必填
	Timeout int    `json:"timeout"` // 超时秒数，默认 14400 (4h)
	// IncidentID 关联事件，处置过程回流为该事件的证据。
	IncidentID string `json:"incident_id"`
	// IdempotencyKey 由调用方提供，避免重复点击产生多条待审批申请。
	IdempotencyKey string `json:"idempotency_key"`
}

// IsolateHost 提交主机隔离申请。**不再直接执行。**
//
// 隔离会切断业务流量。原实现是一次调用即刻生效，没有第二个人看过，事后也回答不了
// "这台机器当时为什么被隔离、谁批的"。现在统一走处置闸门：提申请 → 他人审批 → 执行。
//
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
		req.Timeout = 14400 // 默认 4 小时
	}
	if strings.TrimSpace(req.Reason) == "" {
		BadRequest(c, "隔离申请必须写明理由")
		return
	}

	var host model.Host
	if err := h.db.Where("host_id = ?", req.HostID).First(&host).Error; err != nil {
		NotFound(c, "主机不存在")
		return
	}
	var existing model.HostIsolation
	if err := h.db.Where("host_id = ? AND status = ?", req.HostID, "active").
		First(&existing).Error; err == nil {
		BadRequest(c, fmt.Sprintf("主机已处于隔离状态 (level=%s)", existing.Level))
		return
	}

	h.responses.requestHostResponse(c, model.ResponseActionIsolateHost, req.HostID, req.Reason,
		isolationParams{Level: req.Level, Timeout: req.Timeout, Reason: req.Reason},
		req.IncidentID, isolationIdemKey("isolate", req.HostID, req.IdempotencyKey))
}

type releaseHostReq struct {
	HostID         string `json:"host_id" binding:"required"`
	Reason         string `json:"reason"`
	IncidentID     string `json:"incident_id"`
	IdempotencyKey string `json:"idempotency_key"`
}

// ReleaseHost 提交解除隔离申请。
//
// 解除隔离同样走审批：错误地解除会把仍在失陷的主机放回网络，
// 后果不比误隔离轻。
//
// POST /api/v1/hosts/release
func (h *HostIsolationHandler) ReleaseHost(c *gin.Context) {
	var req releaseHostReq
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "参数错误")
		return
	}
	if strings.TrimSpace(req.Reason) == "" {
		BadRequest(c, "解除隔离申请必须写明理由")
		return
	}
	var record model.HostIsolation
	if err := h.db.Where("host_id = ? AND status = ?", req.HostID, "active").
		First(&record).Error; err != nil {
		NotFound(c, "主机不在隔离状态")
		return
	}

	h.responses.requestHostResponse(c, model.ResponseActionReleaseHost, req.HostID, req.Reason,
		isolationParams{Reason: req.Reason}, req.IncidentID,
		isolationIdemKey("release", req.HostID, req.IdempotencyKey))
}

// isolationIdemKey 生成幂等键。调用方未提供时按 动作+主机+当前隔离轮次 派生，
// 避免同一主机的重复点击产生多条待审批申请。
func isolationIdemKey(action, hostID, provided string) string {
	if k := strings.TrimSpace(provided); k != "" {
		return k
	}
	return fmt.Sprintf("%s:%s:%d", action, hostID, time.Now().Unix()/60)
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
