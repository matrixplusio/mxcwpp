// Package api 提供 HTTP API 处理器
package api

import (
	"errors"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/manager/biz/casework"
	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// IncidentHandler 安全事件 API 处理器（P2）
type IncidentHandler struct {
	db     *gorm.DB
	logger *zap.Logger
	cases  *casework.Service
}

// NewIncidentHandler 创建安全事件 API 处理器
func NewIncidentHandler(db *gorm.DB, logger *zap.Logger) *IncidentHandler {
	return &IncidentHandler{db: db, logger: logger, cases: casework.NewService(db, logger)}
}

// ListIncidentsRequest 查询事件列表请求
type ListIncidentsRequest struct {
	Page     int    `form:"page" binding:"omitempty,min=1"`
	PageSize int    `form:"page_size" binding:"omitempty,min=1,max=100"`
	Status   string `form:"status"`
	HostID   string `form:"host_id"`
}

// ListIncidents 获取安全事件列表
// GET /api/v1/incidents
func (h *IncidentHandler) ListIncidents(c *gin.Context) {
	var req ListIncidentsRequest
	if err := c.ShouldBindQuery(&req); err != nil {
		BadRequest(c, "请求参数错误")
		return
	}
	if req.Page <= 0 {
		req.Page = 1
	}
	if req.PageSize <= 0 {
		req.PageSize = 20
	}

	query := h.db.Model(&model.Incident{})
	if req.Status != "" {
		query = query.Where("status = ?", req.Status)
	}
	if req.HostID != "" {
		query = query.Where("host_id = ?", req.HostID)
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		h.logger.Error("查询事件总数失败", zap.Error(err))
		InternalError(c, "查询事件失败")
		return
	}

	var items []model.Incident
	offset := (req.Page - 1) * req.PageSize
	if err := query.Order("risk_score DESC, last_seen_at DESC").
		Offset(offset).Limit(req.PageSize).Find(&items).Error; err != nil {
		h.logger.Error("查询事件列表失败", zap.Error(err))
		InternalError(c, "查询事件失败")
		return
	}

	Success(c, gin.H{
		"items":      items,
		"total":      total,
		"page":       req.Page,
		"page_size":  req.PageSize,
		"total_page": (int(total) + req.PageSize - 1) / req.PageSize,
	})
}

// GetIncident 获取事件详情(含成员告警)
// GET /api/v1/incidents/:id
func (h *IncidentHandler) GetIncident(c *gin.Context) {
	id := c.Param("id")
	var inc model.Incident
	if err := h.db.Where("incident_id = ?", id).First(&inc).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "事件不存在")
			return
		}
		InternalError(c, "查询事件失败")
		return
	}

	// 展开成员告警
	var alerts []model.Alert
	if len(inc.AlertIDs) > 0 {
		h.db.Where("id IN ?", []string(inc.AlertIDs)).Find(&alerts)
	}
	sortAlertsByTime(alerts)

	// 生成攻击阶段叙事 + 处置建议(展示层"看得懂",而非堆元数据)
	stages, narrative, recommendations := buildIncidentNarrative(inc, alerts)

	Success(c, gin.H{
		"incident":        inc,
		"alerts":          alerts,
		"stages":          stages,
		"narrative":       narrative,
		"recommendations": recommendations,
	})
}

// ResolveIncident 人工关闭事件
// POST /api/v1/incidents/:id/resolve
// AssignIncidentRequest POST /api/v1/incidents/:id/assign
type AssignIncidentRequest struct {
	Owner string `json:"owner" binding:"required"`
}

// AssignIncident 指派负责人。
func (h *IncidentHandler) AssignIncident(c *gin.Context) {
	var req AssignIncidentRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "请指定负责人")
		return
	}
	h.caseResult(c, h.cases.Assign(c.Param("id"), req.Owner, actorOf(c)), "已指派")
}

// AckIncident 认领事件。POST /api/v1/incidents/:id/ack
func (h *IncidentHandler) AckIncident(c *gin.Context) {
	h.caseResult(c, h.cases.Ack(c.Param("id"), actorOf(c)), "已认领")
}

// CommentIncidentRequest POST /api/v1/incidents/:id/comments
type CommentIncidentRequest struct {
	Body string `json:"body" binding:"required"`
	Ref  string `json:"ref"`
}

// CommentIncident 追加研判备注或证据。
func (h *IncidentHandler) CommentIncident(c *gin.Context) {
	var req CommentIncidentRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "备注内容不能为空")
		return
	}
	h.caseResult(c, h.cases.Comment(c.Param("id"), actorOf(c), req.Body, req.Ref), "已记录")
}

// EscalateIncidentRequest POST /api/v1/incidents/:id/escalate
type EscalateIncidentRequest struct {
	To     string `json:"to" binding:"required"`
	Reason string `json:"reason" binding:"required"`
}

// EscalateIncident 升级事件。
func (h *IncidentHandler) EscalateIncident(c *gin.Context) {
	var req EscalateIncidentRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "升级需指定对象与原因")
		return
	}
	h.caseResult(c, h.cases.Escalate(c.Param("id"), req.To, req.Reason, actorOf(c)), "已升级")
}

// GetIncidentTimeline 返回事件时间线。GET /api/v1/incidents/:id/timeline
func (h *IncidentHandler) GetIncidentTimeline(c *gin.Context) {
	events, err := h.cases.Timeline(c.Param("id"))
	if err != nil {
		h.logger.Error("查询事件时间线失败", zap.Error(err))
		InternalError(c, "查询事件时间线失败")
		return
	}
	Success(c, gin.H{"items": events, "total": len(events)})
}

// ResolveIncidentRequest POST /api/v1/incidents/:id/resolve
//
// verdict 与 reason 均必填：原实现关闭事件不需要任何理由，于是无法回答
// "这条到底是不是真威胁"和"当时为什么关掉它"——前者是检测质量的唯一可信来源，
// 后者是复盘的前提。
type ResolveIncidentRequest struct {
	Verdict string `json:"verdict" binding:"required"`
	Reason  string `json:"reason" binding:"required"`
}

// ResolveIncident 关闭事件，必须给出研判结论与原因。
func (h *IncidentHandler) ResolveIncident(c *gin.Context) {
	var req ResolveIncidentRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "关闭事件必须给出研判结论(verdict)与原因(reason)")
		return
	}
	h.caseResult(c, h.cases.Resolve(c.Param("id"), req.Verdict, req.Reason, actorOf(c)), "已关闭")
}

// caseResult 统一把运营闭环操作的错误映射为 HTTP 响应。
func (h *IncidentHandler) caseResult(c *gin.Context, err error, okMsg string) {
	switch {
	case err == nil:
		SuccessWithMessage(c, okMsg, nil)
	case errors.Is(err, casework.ErrNotFound):
		NotFound(c, "事件不存在")
	case errors.Is(err, casework.ErrAlreadyResolved):
		BadRequest(c, "事件已关闭")
	case errors.Is(err, casework.ErrVerdictRequired),
		errors.Is(err, casework.ErrCloseReasonRequired):
		BadRequest(c, err.Error())
	default:
		h.logger.Error("事件运营操作失败", zap.Error(err))
		BadRequest(c, err.Error())
	}
}

// actorOf 取当前操作者。运营闭环的每一步都要能追溯到人。
func actorOf(c *gin.Context) string {
	if u := c.GetString("username"); u != "" {
		return u
	}
	return "unknown"
}
