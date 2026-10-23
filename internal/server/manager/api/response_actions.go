package api

import (
	"encoding/json"
	"errors"
	"strconv"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/manager/biz/casework"
	"github.com/matrixplusio/mxcwpp/internal/server/manager/sd"
	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// ResponseActionHandler 处置申请与审批 API。
type ResponseActionHandler struct {
	db     *gorm.DB
	logger *zap.Logger
	cases  *casework.Service
	exec   casework.Executor
}

// NewResponseActionHandler 创建处置处理器。
func NewResponseActionHandler(db *gorm.DB, logger *zap.Logger, d *sd.ACDispatcher) *ResponseActionHandler {
	return &ResponseActionHandler{
		db:     db,
		logger: logger,
		cases:  casework.NewService(db, logger),
		exec:   newHostResponseExecutor(db, logger, d),
	}
}

// ListResponseActions GET /api/v1/response-actions?status=pending
func (h *ResponseActionHandler) ListResponseActions(c *gin.Context) {
	q := h.db.Model(&model.ResponseAction{})
	if st := c.Query("status"); st != "" {
		q = q.Where("status = ?", st)
	}
	var items []model.ResponseAction
	if err := q.Order("requested_at DESC").Limit(200).Find(&items).Error; err != nil {
		h.logger.Error("查询处置申请失败", zap.Error(err))
		InternalError(c, "查询处置申请失败")
		return
	}
	Success(c, gin.H{"items": items, "total": len(items)})
}

// ApproveResponseAction POST /api/v1/response-actions/:id/approve
func (h *ResponseActionHandler) ApproveResponseAction(c *gin.Context) {
	id, ok := h.parseID(c)
	if !ok {
		return
	}
	h.respond(c, h.cases.ApproveResponse(id, actorOf(c)), "已审批")
}

// RejectResponseActionRequest POST /api/v1/response-actions/:id/reject
type RejectResponseActionRequest struct {
	Reason string `json:"reason" binding:"required"`
}

// RejectResponseAction 驳回处置申请。
func (h *ResponseActionHandler) RejectResponseAction(c *gin.Context) {
	id, ok := h.parseID(c)
	if !ok {
		return
	}
	var req RejectResponseActionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "驳回必须写明原因")
		return
	}
	h.respond(c, h.cases.RejectResponse(id, actorOf(c), req.Reason), "已驳回")
}

// ExecuteResponseAction POST /api/v1/response-actions/:id/execute
//
// 执行与审批分开成两步：审批是"同意做"，执行是"现在做"。
// 合成一步意味着审批人必须在可以立即执行的时刻才能点同意。
func (h *ResponseActionHandler) ExecuteResponseAction(c *gin.Context) {
	id, ok := h.parseID(c)
	if !ok {
		return
	}
	h.respond(c, h.cases.ExecuteResponse(id, h.exec), "已执行")
}

// RollbackResponseAction POST /api/v1/response-actions/:id/rollback
func (h *ResponseActionHandler) RollbackResponseAction(c *gin.Context) {
	id, ok := h.parseID(c)
	if !ok {
		return
	}
	h.respond(c, h.cases.RollbackResponse(id, actorOf(c), h.exec), "已回滚")
}

func (h *ResponseActionHandler) parseID(c *gin.Context) (uint, bool) {
	n, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		BadRequest(c, "无效的处置申请 ID")
		return 0, false
	}
	return uint(n), true
}

// respond 把处置流程的错误映射为 HTTP 响应。
func (h *ResponseActionHandler) respond(c *gin.Context, err error, okMsg string) {
	switch {
	case err == nil:
		SuccessWithMessage(c, okMsg, nil)
	case errors.Is(err, casework.ErrNotFound):
		NotFound(c, "处置申请不存在")
	case errors.Is(err, casework.ErrNotApproved),
		errors.Is(err, casework.ErrSelfApproval),
		errors.Is(err, casework.ErrAlreadyDecided),
		errors.Is(err, casework.ErrNotExecuted),
		errors.Is(err, casework.ErrAutoResponseForbidden):
		BadRequest(c, err.Error())
	default:
		h.logger.Error("处置操作失败", zap.Error(err))
		BadRequest(c, err.Error())
	}
}

// requestHostResponse 提交主机类处置申请，供隔离/解除隔离接口复用。
//
// 参数存进 Result 字段随申请一起保留：执行发生在审批之后，
// 那时必须还能拿到申请当时的级别与时长，而不是重新猜一遍。
func (h *ResponseActionHandler) requestHostResponse(
	c *gin.Context, action, hostID, reason string, p isolationParams, incidentID, idemKey string,
) {
	params, _ := json.Marshal(p)
	act, err := h.cases.RequestResponse(&model.ResponseAction{
		IdempotencyKey: idemKey,
		Action:         action,
		Target:         hostID,
		IncidentID:     incidentID,
		Reason:         reason,
		RequestedBy:    actorOf(c),
		Result:         string(params),
	})
	if err != nil {
		if errors.Is(err, casework.ErrAutoResponseForbidden) {
			BadRequest(c, err.Error())
			return
		}
		h.logger.Error("提交处置申请失败", zap.Error(err))
		BadRequest(c, err.Error())
		return
	}
	SuccessWithMessage(c, "处置申请已提交，等待审批", act)
}
