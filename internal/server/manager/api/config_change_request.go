// Package api 提供配置变更审批 HTTP API (P1-1)。
//
// 路由 (RBAC: 仅 ops + admin):
//
//	POST   /api/v2/config/change-requests        — 提交变更
//	GET    /api/v2/config/change-requests        — 列表 (pending / approved / rejected)
//	GET    /api/v2/config/change-requests/:id    — 详情
//	POST   /api/v2/config/change-requests/:id/approve  — 审批 (admin/security_lead)
//	POST   /api/v2/config/change-requests/:id/reject   — 拒绝
//	POST   /api/v2/config/change-requests/:id/cancel   — 申请人取消
//	GET    /api/v2/config/change-requests/sensitivity?key=foo  — 查询某 key 所需审批数
//
// 流程:
//
//  1. ops 提交 → status=pending
//  2. admin/security_lead approve → approved_count++
//  3. approved_count >= approval_required_count → status=approved
//  4. Worker 周期扫 approved → 应用到 FeatureFlag.Value → status=applied
//  5. 任何阶段都写 AuditLog
package api

import (
	"errors"
	"strings"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/imkerbos/mxsec-platform/internal/server/model"
)

// ConfigChangeRequestHandler 配置变更审批 handler.
type ConfigChangeRequestHandler struct {
	db     *gorm.DB
	logger *zap.Logger
}

// NewConfigChangeRequestHandler 构造。
func NewConfigChangeRequestHandler(db *gorm.DB, logger *zap.Logger) *ConfigChangeRequestHandler {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &ConfigChangeRequestHandler{db: db, logger: logger}
}

// CreateChangeRequestRequest 提交变更请求体。
type CreateChangeRequestRequest struct {
	TargetTable   string `json:"target_table" binding:"required"` // feature_flags / kube_clusters / system_config
	TargetKey     string `json:"target_key" binding:"required"`
	ProposedValue string `json:"proposed_value" binding:"required"`
	Reason        string `json:"reason" binding:"required,min=10"` // 至少 10 字符 (审计要求)
}

// Create 提交配置变更请求。
func (h *ConfigChangeRequestHandler) Create(c *gin.Context) {
	var req CreateChangeRequestRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "请求参数错误: "+err.Error())
		return
	}
	user := getCurrentUser(c)
	tenant := getCurrentTenant(c)

	// 查 target_table 当前 value (作为 old_value)
	oldValue, err := h.fetchCurrentValue(req.TargetTable, req.TargetKey, tenant)
	if err != nil {
		BadRequest(c, "无法读取 target 当前值: "+err.Error())
		return
	}

	// 同 (target_table, target_key) 不允重复 pending
	var existing model.ConfigChangeRequest
	err = h.db.Where("tenant_id = ? AND target_table = ? AND target_key = ? AND status = ?",
		tenant, req.TargetTable, req.TargetKey, "pending").First(&existing).Error
	if err == nil {
		BadRequest(c, "已有该 key 的待审批请求, 请先取消旧请求")
		return
	}

	reqModel := model.ConfigChangeRequest{
		TenantID:            tenant,
		TargetTable:         req.TargetTable,
		TargetKey:           req.TargetKey,
		OldValue:            oldValue,
		ProposedValue:       req.ProposedValue,
		Reason:              req.Reason,
		Status:              "pending",
		RequestedBy:         user,
		ApprovalRequiredCnt: model.RequiredApprovalCount(req.TargetKey),
	}
	if err := h.db.Create(&reqModel).Error; err != nil {
		InternalError(c, "保存变更请求失败")
		return
	}
	h.audit(tenant, user, "config_change.create", &reqModel)
	Success(c, reqModel)
}

// List 列出变更请求 (按状态过滤可选)。
func (h *ConfigChangeRequestHandler) List(c *gin.Context) {
	tenant := getCurrentTenant(c)
	q := h.db.Where("tenant_id = ?", tenant)
	if status := c.Query("status"); status != "" {
		q = q.Where("status = ?", status)
	}
	if targetTable := c.Query("target_table"); targetTable != "" {
		q = q.Where("target_table = ?", targetTable)
	}
	var items []model.ConfigChangeRequest
	if err := q.Order("id DESC").Limit(200).Find(&items).Error; err != nil {
		InternalError(c, "查询失败")
		return
	}
	Success(c, gin.H{"items": items, "total": len(items)})
}

// Get 详情。
func (h *ConfigChangeRequestHandler) Get(c *gin.Context) {
	id := c.Param("id")
	tenant := getCurrentTenant(c)
	var item model.ConfigChangeRequest
	if err := h.db.Where("tenant_id = ? AND id = ?", tenant, id).First(&item).Error; err != nil {
		NotFound(c, "请求不存在")
		return
	}
	Success(c, item)
}

// Approve 审批通过。
//
// 如果 approved_count >= approval_required_count → 进 approved 状态。
// 单个审批人不能重复审批 (Approvers 字段 contains 检查)。
func (h *ConfigChangeRequestHandler) Approve(c *gin.Context) {
	id := c.Param("id")
	tenant := getCurrentTenant(c)
	user := getCurrentUser(c)

	var item model.ConfigChangeRequest
	if err := h.db.Where("tenant_id = ? AND id = ?", tenant, id).First(&item).Error; err != nil {
		NotFound(c, "请求不存在")
		return
	}
	if item.Status != "pending" {
		BadRequest(c, "状态非 pending, 不可审批")
		return
	}
	if strings.Contains(item.Approvers, user+",") || item.Approvers == user || strings.HasSuffix(item.Approvers, ","+user) {
		BadRequest(c, "您已审批过此请求")
		return
	}
	if item.RequestedBy == user {
		BadRequest(c, "申请人不可自审批")
		return
	}

	if item.Approvers == "" {
		item.Approvers = user
	} else {
		item.Approvers = item.Approvers + "," + user
	}
	item.ApprovedCount++
	if item.ApprovedCount >= item.ApprovalRequiredCnt {
		item.Status = "approved"
	}
	if err := h.db.Save(&item).Error; err != nil {
		InternalError(c, "更新失败")
		return
	}
	h.audit(tenant, user, "config_change.approve", &item)
	Success(c, item)
}

// RejectRequest 拒绝请求体。
type RejectRequest struct {
	Reason string `json:"reason" binding:"required,min=5"`
}

// Reject 拒绝。
func (h *ConfigChangeRequestHandler) Reject(c *gin.Context) {
	id := c.Param("id")
	tenant := getCurrentTenant(c)
	user := getCurrentUser(c)

	var req RejectRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "请求参数错误: "+err.Error())
		return
	}
	var item model.ConfigChangeRequest
	if err := h.db.Where("tenant_id = ? AND id = ?", tenant, id).First(&item).Error; err != nil {
		NotFound(c, "请求不存在")
		return
	}
	if item.Status != "pending" {
		BadRequest(c, "状态非 pending")
		return
	}
	item.Status = "rejected"
	item.RejectedBy = user
	item.RejectReason = req.Reason
	if err := h.db.Save(&item).Error; err != nil {
		InternalError(c, "更新失败")
		return
	}
	h.audit(tenant, user, "config_change.reject", &item)
	Success(c, item)
}

// Cancel 申请人主动取消 (仅 pending 状态可取消)。
func (h *ConfigChangeRequestHandler) Cancel(c *gin.Context) {
	id := c.Param("id")
	tenant := getCurrentTenant(c)
	user := getCurrentUser(c)

	var item model.ConfigChangeRequest
	if err := h.db.Where("tenant_id = ? AND id = ?", tenant, id).First(&item).Error; err != nil {
		NotFound(c, "请求不存在")
		return
	}
	if item.RequestedBy != user {
		BadRequest(c, "仅申请人可取消")
		return
	}
	if item.Status != "pending" {
		BadRequest(c, "状态非 pending, 不可取消")
		return
	}
	item.Status = "cancelled"
	if err := h.db.Save(&item).Error; err != nil {
		InternalError(c, "更新失败")
		return
	}
	h.audit(tenant, user, "config_change.cancel", &item)
	Success(c, item)
}

// GetSensitivity 查询某 key 所需审批数。
//
//	GET /api/v2/config/change-requests/sensitivity?key=mode.global
//	→ {key: "mode.global", required_approval_count: 2, sensitive: true}
func (h *ConfigChangeRequestHandler) GetSensitivity(c *gin.Context) {
	key := c.Query("key")
	if key == "" {
		BadRequest(c, "缺少 key")
		return
	}
	cnt := model.RequiredApprovalCount(key)
	Success(c, gin.H{
		"key":                     key,
		"required_approval_count": cnt,
		"sensitive":               cnt >= 2,
	})
}

// fetchCurrentValue 读 target_table 当前 value (作为 old_value 留底)。
//
// 当前仅支持 feature_flags 表; 后续扩展 system_config / kube_clusters 等。
func (h *ConfigChangeRequestHandler) fetchCurrentValue(table, key, tenant string) (string, error) {
	switch table {
	case "feature_flags":
		var ff model.FeatureFlag
		err := h.db.Where("tenant_id = ? AND flag_key = ?", tenant, key).First(&ff).Error
		if err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ff.DefaultVal, nil
			}
			return "", err
		}
		return ff.Value, nil
	case "system_config", "kube_clusters":
		// 后续扩展
		return "", nil
	}
	return "", errors.New("unsupported target_table: " + table)
}

func (h *ConfigChangeRequestHandler) audit(tenant, user, action string, item *model.ConfigChangeRequest) {
	h.logger.Info("config change audit",
		zap.String("tenant", tenant),
		zap.String("user", user),
		zap.String("action", action),
		zap.Uint("request_id", item.ID),
		zap.String("target", item.TargetTable+"."+item.TargetKey),
		zap.String("status", item.Status))
	// 后续: 写 model.AuditLog 表
}

// getCurrentUser 从 JWT/context 取当前用户名。
func getCurrentUser(c *gin.Context) string {
	if v, ok := c.Get("user_id"); ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	if v, ok := c.Get("username"); ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return "anonymous"
}

// getCurrentTenant 从 context 取当前租户。
func getCurrentTenant(c *gin.Context) string {
	if v, ok := c.Get("tenant_id"); ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return "t-default"
}
